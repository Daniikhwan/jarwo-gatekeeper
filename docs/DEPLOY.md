# Deploy — Jarwo Gatekeeper

Target: a public HTTPS endpoint, standard port (443), always on.
If the agent is offline when a task is sent, that task is lost.

## Railway (recommended)

1. Push this repo to GitHub (public repo — also a prize-eligibility requirement).
2. Railway → **New Project → Deploy from GitHub** → pick
   `Daniikhwan/jarwo-gatekeeper`.
3. Set these env vars (Railway → Variables). Never commit them:
   - `AGENT_GAMES_HMAC_SECRET` — the 32-byte secret shown **once** when the
     agent is registered in the Agent Games dashboard.
   - `PROOF_ENABLED=true` — only after `npm run prove:test` passes and the
     practice task confirms the platform accepts the proof.
   - `PORT` is provided by Railway automatically.
4. Deploy. You get `https://<your-app>.up.railway.app`.
5. Check `GET https://<your-app>.up.railway.app/health` → `200`,
   `protocol: "agent-games.v1"`, `hmacConfigured: true`.

## Register the endpoint

In the Agent Games dashboard, register the agent endpoint:

```text
https://<your-app>.up.railway.app/gatekeeper
```

Then:

1. **Preflight** — run it until the status is `HEALTHY`.
   Common failure: `FAILED (protocol) — The endpoint must return signed
   protocol-v1 JSON` → the preflight response isn't signed or is the wrong
   shape; check the preflight branch in `server.js`.
2. **Practice task** — do at least **1** (required to enter a round).
   Practice is capped at 10 dispatches per agent per hour and does not
   affect the leaderboard. Use it to confirm the proof field names and the
   `taskId` encoding the platform expects.
3. Only then join the scored rounds: 8 tasks/day, 16:00–02:00 IST
   (17:30–03:30 WIB).

## Before scored rounds — do not skip

- **Persistent seen-set.** `seenProofTx` and the idempotency cache in
  `server.js` are in-memory. A restart loses them, and a reused proof
  accepted after a restart is a −6 risk. Move them to a file or database
  before Round 4.
- **Kurier.** `submitProofToKurier()` in `proof.js` is still a stub. It needs
  a real Kurier mainnet API key (register the verification key once, submit
  with the vk hash, poll to `Finalized`).
- **Keep it awake.** Free tiers that sleep on idle will miss tasks.
  Railway does not sleep like old free tiers, but verify uptime after deploy.

## Security

- Never commit `.env`, the HMAC secret, a private key, or a seed phrase.
- The HMAC secret lives only in host env vars. If it leaks, rotate it from
  the dashboard — the old secret dies immediately.
- Never paste a private key / seed / API key into an AI tool.
