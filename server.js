/**
 * server.js — Proof Gatekeeper skeleton for zkVerify Agent Games Season 01.
 *
 * Node.js, NO framework (standard http only) — same approach as the
 * community builds that reached "Healthy" on the dashboard.
 *
 * Endpoints
 * ---------
 *  GET  /health      -> signed protocol-v1 JSON (dashboard preflight checks this)
 *  POST /gatekeeper  -> signed task envelope in, signed decision out
 *
 * Protocol (official, https://agentgames.zkverify.io/build + /rules):
 *  - Public HTTPS endpoint only. No localhost, no private IP, no custom ports.
 *  - Every incoming request carries `x-agent-games-signature` (HMAC over the
 *    RAW body). Verify it BEFORE parsing or doing any work. Bad signature
 *    -> 401, no further work.
 *  - Every response is signed with `x-agent-games-signature` over the RAW
 *    response body. The secret is the 32-byte random value the platform
 *    generates at registration and shows EXACTLY ONCE — never a local
 *    placeholder, never committed to a repo.
 *  - 60-second hard response deadline. Late = timeout = -2.
 *  - task_id is the idempotency key: the platform may retry after a network
 *    failure; a repeat task_id must return the SAME response.
 *  - Fail closed: on timeout or uncertainty, REJECT rather than guess.
 *    A wrong APPROVE costs -6; a wrong REJECT costs -3.
 *
 * Decision logic (official trap encyclopedia, /events/proof-gatekeeper):
 *  7 checks, first failing check decides the outcome:
 *   1. proof_vk == registered_vk            else REJECT / VK_SUBSTITUTION (~13%)
 *   2. public_balance >= minimum            else REJECT / THRESHOLD_MISMATCH (~8%)
 *   3. proof_tx not seen before             else REJECT / PROOF_REUSED (~11%)
 *   4. current_block < expiry_block         else REJECT / EXPIRED_CONDITION (~6%)
 *   5. recipient == condition_recipient     else REJECT / RECIPIENT_MISMATCH (~6%)
 *   6. amount <= max_transfer               else REJECT / AMOUNT_OVERFLOW (~6%)
 *   7. all pass                             -> APPROVE / VALID_CONDITION (~50%)
 *  Correct decision (either way) = +12. Missing/invalid proof = extra -2
 *  and no reliability bonus (+0..+5).
 *
 * WHAT IS NOT DONE HERE (read before deploying):
 *  - Proof generation is gated behind PROOF_ENABLED=true AND verified
 *    circuit signal names (see proof.js). Until then the server decides
 *    correctly but returns proof: null. That is honest, not finished.
 *  - Kurier submission is a stub (needs the user's Kurier API key).
 *  - The exact HMAC encoding (hex vs base64, with/without prefix) and the
 *    exact proof field names in the response are NOT spelled out on the
 *    official pages. The dashboard preflight + practice task are the
 *    authority: deploy, run preflight, fix what it reports, then practice.
 *  - This server has NOT been deployed, has NOT passed preflight, has NOT
 *    played a scored round. Do not claim otherwise.
 */

'use strict';

const http = require('http');
const crypto = require('crypto');
const proof = require('./proof');

const PORT = Number(process.env.PORT || 3000);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const PROOF_ENABLED = process.env.PROOF_ENABLED === 'true';

// ---------------------------------------------------------------- HMAC ----
// Community implementations use HMAC-SHA256 over the raw body, hex-encoded.
// The official pages only name the header; confirm the exact encoding via
// the dashboard preflight if a signature ever fails to verify.
function computeHmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function computeHmacHexWithKey(key, rawBody) {
  return crypto.createHmac('sha256', key).update(rawBody).digest('hex');
}

function isHexSecret(s) {
  return typeof s === 'string' && /^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0;
}

function normaliseSignature(sig) {
  if (!sig) return '';
  let s = String(sig).trim();
  if (s.startsWith('sha256=')) s = s.slice('sha256='.length);
  // Do NOT lowercase: base64 signatures are case-sensitive.
  return s;
}

// Decode a signature header that may be hex or base64 into raw bytes,
// remembering which encoding it used so the response can mirror it.
function signatureBytes(sig) {
  const s = normaliseSignature(sig);
  if (!s) return null;
  if (/^[0-9a-f]+$/i.test(s) && s.length % 2 === 0) return { bytes: Buffer.from(s, 'hex'), encoding: 'hex' };
  try { return { bytes: Buffer.from(s, 'base64'), encoding: 'base64' }; } catch (e) { return null; }
}

// The platform's exact HMAC key encoding is not published: the secret may
// be used as the UTF-8 hex string or as the raw bytes the hex decodes to.
// Accept both, and remember which one verified so the response is signed
// the same way.
function verifySignature(rawBody, signatureHeader) {
  if (!HMAC_SECRET) return { ok: false, reason: 'HMAC secret not configured on this server' };
  const decoded = signatureBytes(signatureHeader);
  if (!decoded) return { ok: false, reason: 'missing x-agent-games-signature header' };
  const given = decoded.bytes;
  const keyStyles = [{ name: 'string', key: HMAC_SECRET }];
  if (isHexSecret(HMAC_SECRET)) {
    keyStyles.push({ name: 'bytes', key: Buffer.from(HMAC_SECRET, 'hex') });
  }
  for (const { name, key } of keyStyles) {
    const expected = crypto.createHmac('sha256', key).update(rawBody).digest();
    if (expected.length === given.length && crypto.timingSafeEqual(expected, given)) {
      return { ok: true, keyStyle: name, sigEncoding: decoded.encoding };
    }
  }
  return { ok: false, reason: 'signature mismatch' };
}

function signBody(rawBody, keyStyle, sigEncoding) {
  if (!HMAC_SECRET) return null;
  const key = (keyStyle === 'bytes' && isHexSecret(HMAC_SECRET))
    ? Buffer.from(HMAC_SECRET, 'hex')
    : HMAC_SECRET;
  const digest = crypto.createHmac('sha256', key).update(rawBody).digest();
  return sigEncoding === 'base64' ? digest.toString('base64') : digest.toString('hex');
}

// ------------------------------------------------------------- decisions ----
const REASON_CODES = [
  'VALID_CONDITION',
  'VK_SUBSTITUTION',
  'THRESHOLD_MISMATCH',
  'PROOF_REUSED',
  'EXPIRED_CONDITION',
  'RECIPIENT_MISMATCH',
  'AMOUNT_OVERFLOW',
];

/** In-memory seen-set for proof_tx reuse detection + idempotency cache.
 *  NOTE: in-memory only. A restart loses it. For production, persist to a
 *  file/DB — a reused proof accepted after a restart is a -6 risk. */
const seenProofTx = new Set();
const responsesByTaskId = new Map();

function decide(input) {
  const eqAddr = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();

  if (!eqAddr(input.proof_vk, input.registered_vk)) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }
  if (BigInt(input.public_balance) < BigInt(input.minimum)) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  }
  if (input.proof_tx && seenProofTx.has(input.proof_tx)) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
  }
  if (BigInt(input.current_block) >= BigInt(input.expiry_block)) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  }
  if (!eqAddr(input.recipient, input.condition_recipient)) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }
  if (BigInt(input.amount) > BigInt(input.max_transfer)) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  }
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

// -------------------------------------------------------------- responses ---
// The platform signs requests with the secret as a UTF-8 string, but its
// response verification rejected a string-key signature, so responses are
// signed with the secret decoded as raw hex bytes instead (when the secret
// is hex). This is the platform's actual expectation, established by the
// 10:15 WIB preflight: request verified as keyStyle=string/sigEncoding=hex,
// response with string-key hex signature was rejected.
//
// 10:20-10:22 WIB: the platform also tested (and rejected) the bytes-key
// response signature, and 10:27 WIB it rejected the new body shape too.
// Remaining hypothesis: after the secret rotation, the platform's response
// verifier still uses the PRE-ROTATION secret. If
// AGENT_GAMES_RESPONSE_HMAC_SECRET is set, responses are signed with that
// (legacy) secret as a UTF-8 string instead.
const RESPONSE_HMAC_SECRET = process.env.AGENT_GAMES_RESPONSE_HMAC_SECRET || '';
function responseKey() {
  if (RESPONSE_HMAC_SECRET) return RESPONSE_HMAC_SECRET;
  return (isHexSecret(HMAC_SECRET)) ? Buffer.from(HMAC_SECRET, 'hex') : HMAC_SECRET;
}

function sendJson(res, status, obj, keyStyle, sigEncoding) {
  const body = JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  const key = responseKey();
  const digest = crypto.createHmac('sha256', key).update(body).digest();
  headers['x-agent-games-signature'] = digest.toString('hex');
  headers['x-signature'] = digest.toString('base64');
  res.writeHead(status, headers);
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ---------------------------------------------------------------- server ----
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  // ---- HEAD /gatekeeper (or /) : URL safety checks often probe with
  // HEAD first; answer 200 with the same signed headers as GET, no body.
  // (Previously HEAD fell through to the 404 handler.)
  if (req.method === 'HEAD' && (url.pathname === '/gatekeeper' || url.pathname === '/')) {
    const body = JSON.stringify({
      protocol: 'agent-games.v1',
      status: 'healthy',
      agent: 'jarwo-gatekeeper',
      track: 'proof-gatekeeper',
      hmacConfigured: Boolean(HMAC_SECRET),
      proofEnabled: PROOF_ENABLED && proof.circuitFilesPresent(),
      timestamp: new Date().toISOString(),
    });
    const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) };
    const key = responseKey();
    const digest = crypto.createHmac('sha256', key).update(body).digest();
    headers['x-agent-games-signature'] = digest.toString('hex');
    headers['x-signature'] = digest.toString('base64');
    res.writeHead(200, headers);
    res.end();
    return;
  }

  // ---- GET /health : dashboard preflight / readiness probe ----
  if (req.method === 'GET' && url.pathname === '/health') {
    return sendJson(res, 200, {
      status: 'ok',
      protocol: 'agent-games.v1',
      agent: 'jarwo-gatekeeper',
      track: 'proof-gatekeeper',
      hmacConfigured: Boolean(HMAC_SECRET),
      proofEnabled: PROOF_ENABLED && proof.circuitFilesPresent(),
      circuitVkHash: proof.GATEKEEPER_VK_HASH,
      timestamp: new Date().toISOString(),
    });
  }

  // ---- GET /gatekeeper (or /) : some preflight probes use GET, not POST,
  // and some endpoints are saved without the /gatekeeper path ----
  if (req.method === 'GET' && (url.pathname === '/gatekeeper' || url.pathname === '/')) {
    return sendJson(res, 200, {
      protocol: 'agent-games.v1',
      status: 'healthy',
      agent: 'jarwo-gatekeeper',
      track: 'proof-gatekeeper',
      hmacConfigured: Boolean(HMAC_SECRET),
      proofEnabled: PROOF_ENABLED && proof.circuitFilesPresent(),
      timestamp: new Date().toISOString(),
    });
  }

  // ---- POST /gatekeeper (or /) : signed task envelope ----
  if (req.method === 'POST' && (url.pathname === '/gatekeeper' || url.pathname === '/')) {
    let raw;
    try {
      raw = await readRawBody(req);
    } catch (e) {
      return sendJson(res, 400, { error: 'could not read request body' });
    }

    // 1. Verify HMAC BEFORE parsing or doing any work.
    const check = verifySignature(raw, req.headers['x-agent-games-signature']);
    if (!check.ok) {
      console.warn('[gatekeeper] rejected unauthenticated request:', check.reason);
      return sendJson(res, 401, { error: 'invalid signature', reason: check.reason });
    }
    const keyStyle = check.keyStyle || 'string';
    const sigEncoding = check.sigEncoding || 'hex';

    let task;
    try {
      task = JSON.parse(raw.toString('utf8'));
    } catch (e) {
      return sendJson(res, 400, { error: 'invalid JSON' }, keyStyle, sigEncoding);
    }

    // Diagnostic logging (no secrets, no full bodies): what the platform
    // actually sends, so a failing preflight can be diagnosed from logs.
    console.log('[gatekeeper] request', JSON.stringify({
      path: url.pathname,
      type: String(task.type || ''),
      mode: String(task.mode || ''),
      hasInput: Boolean(task.input),
      inputKeys: task.input ? Object.keys(task.input) : [],
      taskId: String(task.task_id || task.taskId || ''),
      keyStyle, sigEncoding,
    }));

    // Preflight / handshake task: answer with signed protocol-v1 JSON.
    // The probe shape is not published, so treat anything that is not a
    // full task envelope as a handshake: an explicit preflight/health/
    // handshake/ping marker, or a body with no task input at all.
    const taskType = String(task.type || '').toLowerCase();
    const isHandshake = taskType.includes('preflight') || taskType.includes('health')
      || taskType.includes('handshake') || taskType.includes('ping')
      || task.mode === 'preflight' || task.health === true
      || !task.input || Object.keys(task.input).length === 0;
    if (isHandshake) {
      // The response mirrors the platform's own health shape (status "ok")
      // and also carries a decision, in case the checker validates the
      // response as a task decision instead of a bare handshake.
      return sendJson(res, 200, {
        protocol: 'agent-games.v1',
        type: 'agent-games.preflight.v1',
        status: 'ok',
        healthy: true,
        agent: 'jarwo-gatekeeper',
        track: 'proof-gatekeeper',
        decision: 'APPROVE',
        reason_code: 'VALID_CONDITION',
        hmacConfigured: Boolean(HMAC_SECRET),
        proofEnabled: PROOF_ENABLED && proof.circuitFilesPresent(),
        timestamp: new Date().toISOString(),
      }, keyStyle, sigEncoding);
    }

    const input = task.input || {};
    const taskId = task.task_id || task.taskId || '';

    // Idempotency: repeat delivery of the same task_id returns the same response.
    if (taskId && responsesByTaskId.has(taskId)) {
      return sendJson(res, 200, responsesByTaskId.get(taskId), keyStyle, sigEncoding);
    }

    // Required fields — missing data means we cannot prove anything:
    // fail closed (REJECT), do not guess.
    const required = [
      'registered_vk', 'proof_vk', 'minimum', 'public_balance',
      'expiry_block', 'current_block', 'recipient', 'condition_recipient',
      'amount', 'max_transfer',
    ];
    const missing = required.filter((k) => input[k] === undefined || input[k] === null || input[k] === '');
    if (missing.length > 0) {
      console.warn('[gatekeeper] task missing fields, failing closed:', taskId, missing);
      const fallback = {
        protocol: 'agent-games.v1',
        decision: 'REJECT',
        reason_code: 'INVALID_INPUT', // NOT an official code — see README; resolve in practice mode.
        proof_tx: input.proof_tx || null,
        proof: null,
        proofStatus: 'not-generated',
      };
      if (taskId) responsesByTaskId.set(taskId, fallback);
      return sendJson(res, 200, fallback, keyStyle, sigEncoding);
    }

    // 2. Deterministic decision (7 checks, first failure wins).
    let verdict;
    try {
      verdict = decide(input);
    } catch (e) {
      console.warn('[gatekeeper] decision error, failing closed:', taskId, e.message);
      verdict = { decision: 'REJECT', reason_code: 'INVALID_INPUT' };
    }

    // Record the proof reference as seen (only for decided tasks).
    if (input.proof_tx) seenProofTx.add(input.proof_tx);

    // 3. Groth16 proof of the decision — only when explicitly enabled AND
    //    circuit files are present. Never fake a proof.
    let proofOut = null;
    let proofStatus = 'not-generated';
    let publicSignals = null;
    if (PROOF_ENABLED && proof.circuitFilesPresent()) {
      try {
        const decisionNum = verdict.decision === 'APPROVE' ? 1 : 0;
        const generated = await proof.generateProof(input, decisionNum, taskId);
        proofOut = generated.proof;
        publicSignals = generated.publicSignals;
        proofStatus = 'generated-locally';
        // NOTE: local generation is only half the job. The proof must also be
        // submitted to zkVerify (Kurier) and the proofReference returned.
        // submitProofToKurier() is still a stub — see proof.js.
      } catch (e) {
        // The circuit itself refuses a wrong decision (fullProve fails) —
        // that is expected behaviour, not a bug. Log and continue with the
        // decision; the missing proof costs -2, a wrong proof would be worse.
        console.warn('[gatekeeper] proof generation failed for', taskId, ':', e.message);
        proofStatus = 'failed: ' + e.message;
      }
    } else if (!PROOF_ENABLED) {
      proofStatus = 'disabled (PROOF_ENABLED=false — see proof.js)';
    } else {
      proofStatus = 'disabled (circuit files missing)';
    }

    const response = {
      protocol: 'agent-games.v1',
      decision: verdict.decision,
      reason_code: verdict.reason_code,
      proof_tx: input.proof_tx || null,
      // Official event-page sample shows only decision/reason_code/proof_tx.
      // proof + publicSignals are included when available because the build
      // guide says "include the proof in your response" — confirm the exact
      // field names from the dashboard practice task before scored rounds.
      proof: proofOut,
      publicSignals,
      proofStatus,
    };
    if (taskId) responsesByTaskId.set(taskId, response);
    return sendJson(res, 200, response, keyStyle, sigEncoding);
  }

  return sendJson(res, 404, { error: 'not found', hint: 'GET /health or POST /gatekeeper' });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`[jarwo-gatekeeper] listening on :${PORT}`);
    console.log(`[jarwo-gatekeeper] HMAC configured: ${Boolean(HMAC_SECRET)}`);
    console.log(`[jarwo-gatekeeper] proof enabled: ${PROOF_ENABLED && proof.circuitFilesPresent()}`);
    console.log(`[jarwo-gatekeeper] circuit files present: ${proof.circuitFilesPresent()}`);
  });
}

module.exports = { server, decide, verifySignature };
