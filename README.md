# BridgeGuard Pro v32

Arabic-first secure communications platform prototype.

> **اتصالات آمنة قابلة للإثبات، لا مجرد ادعاءات.**

## Current status

This repository mirrors the latest available BridgeGuard Pro v32 source from Lovable. The security/backend foundation is present, but the project is **not yet production-ready** and must not be marketed as independently audited or "verified E2EE".

### Security posture

- Supabase authentication and Row Level Security (RLS) foundation.
- Ciphertext-only message storage.
- Device public keys and fingerprints; private keys remain client-side.
- Browser WebCrypto primitives: ECDH P-256, HKDF-SHA-256, AES-256-GCM.
- Server-side authorization and rate limiting for sensitive operations.
- AI access requires explicit consent and server-side authorization.
- WebRTC signaling/TURN configuration is server-side.

### Known limitations

The current cryptographic composition has not undergone an independent cryptographic audit and does not provide forward secrecy/post-compromise security. Key rotation compatibility and call authorization still require further hardening. UI flows and automated security testing are incomplete in this snapshot.

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
