# BridgeGuard Pro v32

Arabic-first secure communications platform prototype.

> **اتصالات آمنة قابلة للإثبات، لا مجرد ادعاءات.**

## Current status

This repository now contains the BridgeGuard Pro v32 application shell plus the security/backend foundation migrated from Lovable. The app is **not yet production-ready** and must not be marketed as independently audited or "verified E2EE".

### Security posture

- Supabase authentication and Row Level Security (RLS) foundation.
- Ciphertext-only message storage.
- Device public keys and fingerprints; private keys remain client-side.
- Browser WebCrypto primitives: ECDH P-256, HKDF-SHA-256, AES-256-GCM.
- Server-side authorization and rate limiting for sensitive operations.
- REDTEAM hardening pass: device registration is RPC-only/rate-limited; call creation/status changes are server-controlled; message sender epochs are bound to the registered device public key; profile writes use least-privilege column grants.
- AI access requires explicit consent and server-side authorization.
- WebRTC signaling/TURN configuration is server-side.
- Arabic RTL dashboard with authentication, local guest mode, messages, security center, privacy export/delete, calls status, and explicit AI consent UI.
- Local key history is retained across rotation for the current browser so newer message epochs can remain decryptable.

### Verification status

GitHub Actions CI is configured for typecheck, lint, unit tests, and build. The latest runs are currently queued on GitHub, so a green CI result has **not** yet been independently observed.

Database authorization should also receive pgTAP/RLS regression tests before production. Database authorization still requires pgTAP/RLS regression tests before production. The repository should test every exposed table's grants and RLS allow/deny cases.

### Known limitations

The current cryptographic composition has not undergone an independent cryptographic audit and does not provide forward secrecy/post-compromise security. Older messages created before sender-key epochs were embedded in envelopes may still require the historical sender public key. Full WebRTC media/call UX and independent security testing remain incomplete.

Do **not** claim verified E2EE, military-grade encryption, zero-server calls, or equivalent guarantees until an audited protocol implementation and external security review support those claims.

## Development

```bash
npm install
npm run dev
npm run build
npm test
npm run lint
```

Copy `.env.example` to `.env` and provide environment-specific values. Never commit secrets.

## Architecture

- TanStack Start + React + TypeScript
- Supabase Auth / Postgres / RLS
- WebCrypto for the current prototype encryption layer
- Lovable AI gateway for explicitly authorized AI requests
- WebRTC signaling with optional TURN

## License

Not specified yet.
