/**
 * prove-test.js — local Groth16 proof test, no platform involved.
 *
 * Uses the OFFICIAL circuit files (circuits/gatekeeper.wasm +
 * gatekeeper_final.zkey, downloaded from agentgames.zkverify.io) and the
 * COMMUNITY-REPORTED 13 signal names (see proof.js — NOT in the official
 * docs). Run:
 *   npm install
 *   node prove-test.js
 *
 * It proves the official sample scenario (minimum 1000, balance 1460,
 * amount 500, cap 1000, matching recipient, expiry ahead of current block,
 * matching VKs, decision=1) and then verifies it locally with the
 * verification key exported from the .zkey.
 *
 * A local "OK" here proves ONLY that snarkjs + the circuit files work and
 * that the guessed signal names produce a witness. It does NOT prove the
 * platform will accept the proof — the taskId encoding and the exact
 * response fields can only be confirmed by the dashboard practice task.
 * It also proves the negative case: decision=1 on a trap (recipient
 * mismatch) must FAIL to produce a witness.
 */
'use strict';

const proof = require('./proof');

const SAMPLE_INPUT = {
  registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
  proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
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

(async () => {
  console.log('circuit files present:', proof.circuitFilesPresent());
  if (!proof.circuitFilesPresent()) {
    console.log('Download them first — see circuits/README.md.');
    process.exit(1);
  }
  const snarkjs = require('snarkjs');

  // Positive case: valid scenario, decision = 1 (APPROVE).
  console.log('\n[1] Valid scenario, decision=1 ...');
  const t0 = Date.now();
  const { proof: p, publicSignals } = await proof.generateProof(SAMPLE_INPUT, 1, 'gk_24_9d1');
  console.log(`    fullProve took ${Date.now() - t0} ms; publicSignals:`, publicSignals);

  const vk = await snarkjs.zKey.exportVerificationKey(proof.ZKEY_PATH);
  const ok = await snarkjs.groth16.verify(vk, publicSignals, p);
  console.log('    local groth16 verify:', ok ? 'OK' : 'FAILED');
  if (!ok) process.exit(1);

  // Negative case: same scenario but recipient mismatched, decision = 1.
  // The circuit must REFUSE to produce a witness.
  console.log('\n[2] Trap scenario (recipient mismatch), decision=1 — must FAIL ...');
  const trapInput = { ...SAMPLE_INPUT, recipient: '0x1111000000000000000000000000000000000001' };
  try {
    await proof.generateProof(trapInput, 1, 'gk_24_9d2');
    console.log('    UNEXPECTED: fullProve succeeded on a trap with decision=1. Signal mapping may be wrong — DO NOT TRUST.');
    process.exit(1);
  } catch (e) {
    console.log('    fullProve failed as expected:', String(e.message).slice(0, 160));
  }

  // Same trap, decision = 0 (REJECT) — must succeed.
  console.log('\n[3] Same trap, decision=0 — must SUCCEED ...');
  const r = await proof.generateProof(trapInput, 0, 'gk_24_9d2');
  const ok3 = await snarkjs.groth16.verify(vk, r.publicSignals, r.proof);
  console.log('    local groth16 verify:', ok3 ? 'OK' : 'FAILED');
  if (!ok3) process.exit(1);

  console.log('\nLocal proof loop works with the community-reported signal names.');
  console.log('Still unverified: taskId encoding + platform acceptance (practice task).');
})().catch((e) => { console.error('prove-test FAILED:', e); process.exit(1); });
