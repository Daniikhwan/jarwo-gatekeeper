# 🛡️ Jarwo Gatekeeper

> **A verifiable Proof Gatekeeper for zkVerify Agent Games — Season 01**
>
> Every `APPROVE` / `REJECT` is decided deterministically, signed with HMAC,
> and backed by a Groth16 proof. No guessing. No manual play. Fail closed.

![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-339933?logo=node.js&logoColor=white)
![Proof](https://img.shields.io/badge/Proof-Groth16%20%2F%20BN128-6C63FF)
![Circuit](https://img.shields.io/badge/Circuit-Circom%202.x-0E7C7B)
![Track](https://img.shields.io/badge/Track-Proof%20Gatekeeper-FF6B35)
![Status](https://img.shields.io/badge/Status-Preflight%20pending-yellow)
![License](https://img.shields.io/badge/License-MIT-blue)

**Agent:** `JarwoId` · **Track:** Proof Gatekeeper · **From:** Indonesia 🇮🇩
**Competition:** [Agent Games — zkVerify Season 01](https://agentgames.zkverify.io) · 21 Oct – 21 Nov 2026 · 400,000 VFY prize pool

---

## What this agent does

The platform sends a proof-backed payment request. Jarwo checks **everything
the proof claims — not just that it verifies** — and answers in under 60 seconds:

```text
Platform  ── POST /gatekeeper (HMAC-signed task) ──▶  Jarwo Gatekeeper
                                                          │  1. Verify HMAC first
                                                          │  2. Check 7 traps
                                                          │  3. Generate Groth16 proof
                                                          │  4. Sign + return decision
Platform  ◀── { decision, reason_code, proof } ──────────┘
```

> _"A proof can verify perfectly and still authorize the wrong action."_
> — zkVerify Agent Games build guide. That's exactly what this agent guards against.

## The 7 traps — one checklist, no shortcuts

| # | Check | If it fails | Approx. share |
|---|-------|-------------|---------------|
| 1 | `proof_vk == registered_vk` | `REJECT / VK_SUBSTITUTION` | ~13% |
| 2 | `public_balance >= minimum` | `REJECT / THRESHOLD_MISMATCH` | ~8% |
| 3 | `proof_tx` never seen before | `REJECT / PROOF_REUSED` | ~11% |
| 4 | `current_block < expiry_block` | `REJECT / EXPIRED_CONDITION` | ~6% |
| 5 | `recipient == condition_recipient` | `REJECT / RECIPIENT_MISMATCH` | ~6% |
| 6 | `amount <= max_transfer` | `REJECT / AMOUNT_OVERFLOW` | ~6% |
| 7 | All pass | `APPROVE / VALID_CONDITION` | ~50% |

**Scoring:** correct decision **+12** · wrong `APPROVE` **−6** · wrong `REJECT` **−3** · timeout **−2** · missing/invalid proof **−2** · reliability bonus **+0 to +5**.

That's why the agent **fails closed**: when data is missing or uncertain, it
rejects instead of guessing. A wrong approve costs twice a wrong reject.

## Highlights

- 🔐 **HMAC first, always** — `x-agent-games-signature` is verified against the
  raw body *before* any parsing or work. Bad signature → `401`, no work done.
- 🧾 **Groth16 proof, locally generated** — official `gatekeeper.wasm` +
  `gatekeeper_final.zkey`, proved with `snarkjs` in ~0.9s. The circuit itself
  refuses a wrong decision: a trap with `decision=1` cannot even produce
  a witness.
- 🔁 **Idempotent** — a repeated `task_id` returns the exact same response.
- 🛡️ **Fail closed** — missing fields, decision errors, or proof failures
  never become a guessed `APPROVE`.
- ⚡ **Zero framework, zero bloat** — plain Node.js `http`, one dependency
  (`snarkjs`). Fast to deploy, easy to audit.

## Quick start

```bash
git clone https://github.com/Daniikhwan/jarwo-gatekeeper.git
cd jarwo-gatekeeper
npm install

# Run the tests (no platform, no network, no secrets needed)
npm test            # decision + HMAC + idempotency — 10 checks
npm run prove:test  # full Groth16 prove + verify — 3 checks

# Run the server
cp .env.example .env   # fill AGENT_GAMES_HMAC_SECRET on the host only
npm start              # GET /health · POST /gatekeeper
```

```bash
curl http://localhost:3000/health
# {"status":"ok","protocol":"agent-games.v1","agent":"jarwo-gatekeeper",...}
```

## Project structure

```text
jarwo-gatekeeper/
├── server.js            # GET /health · POST /gatekeeper · 7 trap checks · HMAC
├── proof.js             # Groth16 proof generation (snarkjs) + Kurier stub
├── test-local.js        # npm test — decisions, HMAC, idempotency, preflight
├── prove-test.js        # npm run prove:test — fullProve + local verify
├── circuits/
│   ├── gatekeeper.wasm          # official, 1,755,820 bytes
│   ├── gatekeeper_final.zkey   # official, 309,750 bytes
│   └── README.md                # SHA-256 + source URLs + verification
├── docs/
│   └── DEPLOY.md        # Railway deploy + preflight + practice task
├── .env.example         # never commit a real secret
└── railway.json         # Railway deploy config
```

## Deploy

One command on Railway — see **[docs/DEPLOY.md](docs/DEPLOY.md)** for the full checklist:

1. Push this repo to GitHub (public).
2. Railway → New Project → Deploy from GitHub → root is this repo.
3. Set `AGENT_GAMES_HMAC_SECRET` (the 32-byte secret shown **once** at agent
   registration) and `PROOF_ENABLED=true` — as env vars, never in git.
4. Register the endpoint `https://<your-app>.up.railway.app/gatekeeper` in the
   Agent Games dashboard, run **preflight** until `HEALTHY`, then do at least
   **1 practice task** before a scored round.

> The agent must stay online during rounds (16:00–02:00 IST / 17:30–03:30 WIB).
> If it's offline when a task arrives, that task is lost.

## Security

- Never commit `.env`, the HMAC secret, a private key, or a seed phrase.
- The HMAC secret lives only in the host's env vars. If it leaks, rotate it
  from the dashboard — the old secret dies immediately.
- All responses are HMAC-signed; all incoming tasks are verified first.

## Status — honest, not hyped

- ✅ Local tests pass: `npm test` 10/10 · `npm run prove:test` 3/3
- ✅ Groth16 proof generates locally in ~0.9s and verifies with `snarkjs`
- ⏳ **Not yet tested against the platform** — preflight + practice task are
  still pending (they need a registered agent + the real HMAC secret).
- ⏳ Kurier submission is a stub — needs a real Kurier mainnet API key.
- ⏳ Seen-set / idempotency cache is in-memory — move to persistent storage
  before scored rounds (see `docs/DEPLOY.md`).

The circuit signal names used in `proof.js` come from community probing of
the compiled wasm — they are **not** published in the official docs. Local
verification passing does not prove the platform will accept the proof.
The dashboard practice task is the authority.

## Links

- Competition: https://agentgames.zkverify.io
- Build guide: https://agentgames.zkverify.io/build
- Proof Gatekeeper event: https://agentgames.zkverify.io/events/proof-gatekeeper
- Circuit info: https://agentgames.zkverify.io/api/circuit-info

---

Built by **JarwoId** 🇮🇩 for zkVerify Agent Games Season 01.
MIT License — see [LICENSE](LICENSE).
