# INDEV dual-app architecture

Copyright (c) 2026 Nathanlel / yshiecast31-maker — MIT

## Apps

1. **INDEV (public)** — local-first workspace users run day to day.
2. **INDEV Companion (private)** — separate origin, integrity checks + pairing.

## Connection model

- Shared 256-bit root (generated offline, never committed).
- Token format: `indev-link:v1.<salt>.<hmac>` where HMAC is HKDF(root, salt, "indev-pair-v1") over the fixed context `INDEV-PAIR-OK`.
- Verification compares MAC in a constant-time style loop.
- Same root can mint/verify tokens on either side.
- Uses Web Crypto HKDF + HMAC-SHA-256 — not a new public-key system.

## Limits

- Not a clone of any government product.
- Not remote attestation of a hostile device.
- Not automatic self-healing of a compromised browser.
- Fail-safe guidance is local (clear data, rotate root, lock vault).
