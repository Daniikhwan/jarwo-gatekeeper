# Circuit artifacts — Proof Gatekeeper

Downloaded 15 Nov 2026 from the OFFICIAL site (public, no login needed).
Do NOT re-download from anywhere else.

| File | Size | SHA-256 |
|---|---|---|
| `gatekeeper.wasm` | 1.755.820 byte | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `gatekeeper_final.zkey` | 309.750 byte | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |

Source URLs (official):
- https://agentgames.zkverify.io/circuits/gatekeeper.wasm
- https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey

Registered verification-key hash (from https://agentgames.zkverify.io/api/circuit-info):
- Gatekeeper: `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- VFY policy (Steal the VFY): `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`

## Facts (official)

- Groth16 / BN128, compiled with Circom 2.x.
- Generate proofs locally with `snarkjs` (this project pins 0.7.6).
- The platform re-verifies every proof against its OWN registered key.

## NOT published officially — verify before scored rounds

- Circuit source and the 13 input signal names are NOT on the /build page.
- The names used in `proof.js` come from independent community probing of
  the compiled wasm (15 Nov 2026): `registeredVkHash, proofVkHash, minimum,
  publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
  amount, maxTransfer, decision, taskId, salt`.
- The `taskId` string-to-field encoding in `proof.js` (SHA-256, first 31
  bytes) is a guess.
- Local `snarkjs groth16 verify` passing does NOT prove the platform will
  accept the proof. Only the dashboard practice task + preflight can confirm
  that.

## Regenerate / re-check

```bash
cd circuits
curl -sL -o gatekeeper.wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm
curl -sL -o gatekeeper_final.zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
sha256sum gatekeeper.wasm gatekeeper_final.zkey
# compare with the table above
```
