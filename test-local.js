/**
 * test-local.js — local smoke test, no platform, no network, no secrets.
 *
 * Starts the server on a test port with a throwaway HMAC secret, then:
 *  1. GET /health                    -> must be 200 + signed + protocol agent-games.v1
 *  2. POST /gatekeeper, bad HMAC     -> must be 401, no work done
 *  3. POST /gatekeeper, valid task   -> must be APPROVE / VALID_CONDITION
 *  4. POST /gatekeeper, VK trap      -> must be REJECT / VK_SUBSTITUTION
 *  5. POST /gatekeeper, same task_id -> must return the identical response (idempotency)
 *  6. POST /gatekeeper, reused proof -> must be REJECT / PROOF_REUSED
 *  7. POST /gatekeeper, preflight    -> must be signed protocol-v1 JSON
 *
 * Run:  node test-local.js        (does NOT need PROOF_ENABLED or circuit files)
 * The decision tests are the point here — proof generation is tested
 * separately by prove-test.js.
 */
'use strict';

const http = require('http');
const crypto = require('crypto');

process.env.PORT = '3456';
process.env.AGENT_GAMES_HMAC_SECRET = 'test-secret-do-not-use-in-production-0123456789abcdef';
process.env.PROOF_ENABLED = 'false';

const { server } = require('./server');
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;

const BASE_INPUT = {
  registered_vk: '0x7d3a00000000000000000000000000000000000000000000000000000000f291',
  proof_vk: '0x7d3a00000000000000000000000000000000000000000000000000000000f291',
  minimum: '1000',
  public_balance: '1460',
  expiry_block: 19842201,
  current_block: 19832000,
  recipient: '0xDe4200000000000000000000000000000000009f01',
  condition_recipient: '0xDe4200000000000000000000000000000000009f01',
  amount: '500',
  max_transfer: '1000',
  proof_tx: '0xa4c1000000000000000000000000000000000000000000000000000000008ff1',
};

function hmac(body) {
  return crypto.createHmac('sha256', SECRET).update(body).digest('hex');
}

function request(method, path, bodyObj, sign = true) {
  return new Promise((resolve, reject) => {
    const body = bodyObj === undefined ? '' : JSON.stringify(bodyObj);
    const headers = { 'Content-Type': 'application/json' };
    if (sign && body) headers['x-agent-games-signature'] = hmac(body);
    const req = http.request(
      { host: '127.0.0.1', port: 3456, path, method, headers },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        }));
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function check(name, cond, extra = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? ' — ' + extra : ''}`);
  if (!cond) process.exitCode = 1;
}

(async () => {
  await new Promise((r) => server.listen(3456, r));

  // 1. health
  const health = await request('GET', '/health');
  const healthJson = JSON.parse(health.body);
  check('GET /health is 200', health.status === 200);
  check('GET /health protocol is agent-games.v1', healthJson.protocol === 'agent-games.v1');
  check('GET /health response is signed', Boolean(health.headers['x-agent-games-signature']));

  // 2. bad HMAC -> 401 (uses a throwaway proof_tx so it cannot pollute the seen-set)
  const tampered = await new Promise((resolve, reject) => {
    const body = JSON.stringify({ type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_bad2', input: { ...BASE_INPUT, proof_tx: '0xdead00000000000000000000000000000000000000000000000000000000beef' } });
    const req = http.request({ host: '127.0.0.1', port: 3456, path: '/gatekeeper', method: 'POST', headers: { 'Content-Type': 'application/json', 'x-agent-games-signature': 'deadbeef' } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
  check('POST with bad HMAC is 401', tampered.status === 401, `got ${tampered.status}`);

  // 3. valid task -> APPROVE
  const validTask = { type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_24_9d1', mode: 'competition', input: BASE_INPUT };
  const valid = await request('POST', '/gatekeeper', validTask);
  const validJson = JSON.parse(valid.body);
  check('valid task APPROVE / VALID_CONDITION', valid.status === 200 && validJson.decision === 'APPROVE' && validJson.reason_code === 'VALID_CONDITION', JSON.stringify(validJson));
  check('response is signed', Boolean(valid.headers['x-agent-games-signature']));

  // 4. VK substitution trap -> REJECT
  const vkTrap = { type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_24_9d2', mode: 'competition', input: { ...BASE_INPUT, proof_vk: '0xa4c100000000000000000000000000000000000000000000000000000000b8ff', proof_tx: '0xbbbb000000000000000000000000000000000000000000000000000000000001' } };
  const vk = await request('POST', '/gatekeeper', vkTrap);
  const vkJson = JSON.parse(vk.body);
  check('VK trap REJECT / VK_SUBSTITUTION', vkJson.decision === 'REJECT' && vkJson.reason_code === 'VK_SUBSTITUTION', JSON.stringify(vkJson));

  // 5. idempotency: repeat the valid task_id -> identical response
  const repeat = await request('POST', '/gatekeeper', validTask);
  check('repeat task_id returns identical response', repeat.body === valid.body);

  // 6. reused proof_tx (new task_id, same proof_tx as task 3) -> PROOF_REUSED
  const reuse = await request('POST', '/gatekeeper', { type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_24_9d3', mode: 'competition', input: BASE_INPUT });
  const reuseJson = JSON.parse(reuse.body);
  check('reused proof REJECT / PROOF_REUSED', reuseJson.decision === 'REJECT' && reuseJson.reason_code === 'PROOF_REUSED', JSON.stringify(reuseJson));

  // 7. preflight
  const pre = await request('POST', '/gatekeeper', { type: 'agent-games.proof-gatekeeper.v1.preflight', mode: 'preflight' });
  const preJson = JSON.parse(pre.body);
  check('preflight returns signed protocol-v1 JSON', pre.status === 200 && preJson.protocol === 'agent-games.v1' && Boolean(pre.headers['x-agent-games-signature']), JSON.stringify(preJson));

  server.close();
  console.log(process.exitCode ? '\nSome checks FAILED.' : '\nAll local checks passed. (Decisions only — proof generation is prove-test.js.)');
})().catch((e) => { console.error(e); process.exit(1); });
