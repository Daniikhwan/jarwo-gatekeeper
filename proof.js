/**
 * proof.js — Groth16 proof generation for Proof Gatekeeper.
 *
 * STATUS (15 Nov 2026): UNVERIFIED / NOT TESTED END-TO-END AGAINST THE PLATFORM.
 *
 * What is official (from https://agentgames.zkverify.io/build and
 * https://agentgames.zkverify.io/api/circuit-info):
 *  - Both arena circuits are Groth16/BN128, compiled with Circom 2.x.
 *  - Proving key (.zkey) + WASM are public; generate proofs locally with snarkjs.
 *  - Gatekeeper vkHash: 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
 *  - Artifacts:
 *      https://agentgames.zkverify.io/circuits/gatekeeper.wasm
 *      https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
 *  - A valid proof for a valid scenario must verify against the platform's
 *    own registered verification key.
 *
 * What is NOT official and must be confirmed before scored rounds:
 *  - The circuit source and the 13 input signal names are NOT published on
 *    the /build page. The names used below come from COMMUNITY probing of the
 *    compiled wasm (reported by independent builders on 15 Nov 2026):
 *    registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
 *    currentBlock, recipient, conditionRecipient, amount, maxTransfer,
 *    decision, taskId, salt (private).
 *    Treat them as a hypothesis, not a fact. Verify with:
 *      node prove-test.js   (runs fullProve + verify locally)
 *    and, decisively, with the dashboard practice task + preflight.
 *  - The encoding of `taskId` (a string like "gk_24_9d1") as a circuit
 *    field element is also unverified. Below it is SHA-256(taskId) truncated
 *    to 31 bytes as a BigInt — a guess. The platform re-verifies the proof
 *    and checks public signals against the task, so a wrong encoding can
 *    still produce a locally-valid proof that the PLATFORM rejects.
 *  - The exact response field names for the proof are ambiguous: the
 *    official event page shows only {decision, reason_code, proof_tx},
 *    while the build guide says "include the proof in your response" and
 *    community builds return proof + publicSignals and submit via Kurier,
 *    returning a proofReference. Confirm from the dashboard practice task.
 *  - Kurier submission (recommended path: REST, mainnet API key, register
 *    vk once, submit with vk hash, poll to Finalized) is NOT implemented
 *    here — see submitProofToKurier() stub below.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const WASM_PATH = path.join(__dirname, 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = path.join(__dirname, 'circuits', 'gatekeeper_final.zkey');

const GATEKEEPER_VK_HASH =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

/** Circuit files present on disk? */
function circuitFilesPresent() {
  return fs.existsSync(WASM_PATH) && fs.existsSync(ZKEY_PATH);
}

/** Hex string ("0x...") -> BigInt field element. */
function hexToBigInt(hex) {
  if (typeof hex !== 'string') throw new Error('hexToBigInt: expected string');
  return BigInt(hex.startsWith('0x') ? hex : '0x' + hex);
}

/**
 * UNVERIFIED encoding: taskId string -> field element.
 * TODO: confirm against the real circuit / dashboard practice task.
 */
function taskIdToField(taskId) {
  const digest = crypto.createHash('sha256').update(String(taskId)).digest();
  // 31 bytes so the value is safely inside the BN128 field.
  return BigInt('0x' + digest.subarray(0, 31).toString('hex'));
}

/**
 * Build the circuit input object from a task's input fields + decision.
 * `decision` is 1 (APPROVE) or 0 (REJECT). `salt` is a private random value.
 *
 * The circuit enforces: decision == 1 if and only if EVERY check passes.
 * A wrong decision cannot even produce a witness (fullProve fails) — that
 * is the point of the circuit, and it is also why the decision logic in
 * server.js must be exactly right before proving.
 */
function buildCircuitInput(input, decision, taskId) {
  return {
    registeredVkHash: hexToBigInt(input.registered_vk).toString(),
    proofVkHash: hexToBigInt(input.proof_vk).toString(),
    minimum: BigInt(input.minimum).toString(),
    publicBalance: BigInt(input.public_balance).toString(),
    expiryBlock: BigInt(input.expiry_block).toString(),
    currentBlock: BigInt(input.current_block).toString(),
    recipient: hexToBigInt(input.recipient).toString(),
    conditionRecipient: hexToBigInt(input.condition_recipient).toString(),
    amount: BigInt(input.amount).toString(),
    maxTransfer: BigInt(input.max_transfer).toString(),
    decision: String(decision),
    taskId: taskIdToField(taskId).toString(),
    // Private salt — any field element; random per proof.
    salt: BigInt('0x' + crypto.randomBytes(31).toString('hex')).toString(),
  };
}

/**
 * Generate a Groth16 proof with snarkjs. Returns { proof, publicSignals }
 * or throws. Requires PROOF_ENABLED=true semantics — callers must check
 * circuitFilesPresent() first and treat failure as "proof unavailable"
 * (fail closed on the decision, but never fake a proof).
 */
async function generateProof(input, decision, taskId) {
  if (!circuitFilesPresent()) {
    throw new Error('Circuit files missing: circuits/gatekeeper.wasm or gatekeeper_final.zkey not found');
  }
  let snarkjs;
  try {
    snarkjs = require('snarkjs');
  } catch (e) {
    throw new Error('snarkjs not installed — run `npm install` first');
  }
  const circuitInput = buildCircuitInput(input, decision, taskId);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM_PATH,
    ZKEY_PATH,
  );
  return { proof, publicSignals, circuitInput };
}

/**
 * STUB — Kurier submission (recommended verification path per /build).
 * Real flow: get a mainnet API key, register the verification key once,
 * submit the proof with its vk hash, poll until the job reaches Finalized.
 * Job states: Submitted -> IncludedInBlock -> Finalized.
 * NOT implemented: needs a Kurier API key, which only exists after the
 * user registers. Do NOT invent one.
 */
async function submitProofToKurier(/* proof, publicSignals */) {
  throw new Error(
    'Kurier submission not implemented: needs a real mainnet API key from the user’s Kurier account (after registration).',
  );
}

module.exports = {
  GATEKEEPER_VK_HASH,
  WASM_PATH,
  ZKEY_PATH,
  circuitFilesPresent,
  buildCircuitInput,
  generateProof,
  submitProofToKurier,
  taskIdToField,
};
