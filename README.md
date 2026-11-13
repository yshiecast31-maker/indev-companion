# INDEV Companion (private)

Copyright (c) 2026 Nathanlel / yshiecast31-maker — MIT

Private integrity and pairing surface for use with the public [INDEV](https://github.com/yshiecast31-maker/indev-app) app.

## Features
- Local integrity suite (40+ concrete environment checks)
- Pairing via shared 256-bit root + `indev-link:v1` HMAC tokens (HKDF-SHA-256)
- Export JSON report
- Fail-safe guidance (local only)
- No security marketing claims in the UI

## Deploy
Separate Cloudflare Pages project (different origin from public INDEV recommended).
Build command: `exit 0`

## Related
- Public app: https://github.com/yshiecast31-maker/indev-app
- Crypto engine: https://github.com/yshiecast31-maker/ahx1
