<h1 align="center">powguard</h1>

<p align="center">A single-binary, SQLite-backed Cap proof-of-work verification server.</p>

<p align="center">
  <a href="https://go.dev/"><img alt="Go" src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat-square&logo=go&logoColor=white"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square"></a>
  <a href="docs/m5-acceptance.md"><img alt="Status" src="https://img.shields.io/badge/status-beta-orange?style=flat-square"></a>
  <a href="docs/compat-matrix.md"><img alt="Protocol" src="https://img.shields.io/badge/protocol-Cap%20format--1%20%7C%20format--2-2ea44f?style=flat-square"></a>
  <a href="deploy/README.md"><img alt="Deploy" src="https://img.shields.io/badge/deploy-single%20binary-6f42c1?style=flat-square"></a>
</p>

<p align="center"><strong>English</strong> | <a href="README.CN.md">简体中文</a></p>

powguard is a Go implementation of a [Cap](https://github.com/tiagozip/cap) proof-of-work (PoW) verification server. It is wire-compatible with the official `@cap.js/widget` and adds multi-site isolation, per-site policy, secret management, event auditing, and a lightweight WebUI. At runtime it needs only a static binary and a SQLite file.

**Primary use case:** external CAPTCHA for Twikoo comments. It also fits login, signup, forms, and other public endpoints that need rate-limit-friendly bot protection.

## Features

- **Drop-in official widget**: an unmodified `@cap.js/widget` 0.1.63 completes challenge → solve → redeem.
- **Two protocols**: format-1 (`@cap.js/server` 4.0.5 compatible) and format-2 SHA-256 (`capjs-core` 0.1.18 envelope/scope).
- **Twikoo 2.0.17 external mode**: `CAPTCHA_PROVIDER=Cap` + `CAP_API_ENDPOINT` + `CAP_SECRET_KEY`.
- **Multi-site isolation**: sites live under `/{site}/` with independent secrets, protocol, difficulty, TTL, CORS, and rate limits.
- **One-time consumption**: challenges and verification tokens are consumed atomically in memory; replay, expiry, and cross-site tokens are rejected by default.
- **Secure defaults**: site secrets encrypted with AES-256-GCM; admin sessions use `HttpOnly`/`Secure`/`SameSite=Lax` cookies; CSRF on writes; re-auth for high-risk actions; constant-time secret comparison.
- **Lightweight WebUI**: overview, site management, integration snippets, secret reveal/rotate, live events over SSE, stats, and instance settings.
- **Zero external runtime services**: pure-Go SQLite driver, builds with `CGO_ENABLED=0`; no Docker, Node, Redis, or Valkey.
- **Pinned same-origin assets**: bundled widget and WASM with CORS headers for cross-site use, avoiding a hard dependency on jsDelivr.
- **Operable**: `keyrotate` / `backup` / `verify-keys` subcommands, hardened systemd unit, Caddy reverse-proxy example, and backup/restore docs.

> **Status:** single-instance beta. Challenges and verification tokens live in process memory, so a restart invalidates unfinished challenges (the visitor solves once more). Multi-replica HA is intentionally out of scope.

## Quick Start

Requirements: Go 1.26+, Make, OpenSSL.

```bash
git clone https://github.com/sseaan/powguard.git
cd powguard
make build

export POWGUARD_MASTER_KEY="$(openssl rand -hex 32)"
export POWGUARD_ADMIN_KEY="$(openssl rand -base64 24)"
export POWGUARD_SITE_SECRET="$(openssl rand -hex 24)"

./powguard
```

Then open:

- Admin panel: <http://127.0.0.1:3000/admin> (log in with `POWGUARD_ADMIN_KEY`)
- Demo page: <http://127.0.0.1:3000/>
- Default site: `twikoo` → `http://127.0.0.1:3000/twikoo/`
- SQLite: `./powguard.sqlite3`

On first start, if the database has no sites, powguard creates one using `POWGUARD_SITE_SLUG` and `POWGUARD_SITE_SECRET`. If no secret is supplied, a temporary one is generated and a warning is logged; use that only for local demos.

Verify the full flow with `capsolve`:

```bash
./capsolve -endpoint http://127.0.0.1:3000/twikoo/ -secret "$POWGUARD_SITE_SECRET"
# Expected: challenge → solve → redeem → siteverify → replay-rejected
```

## Deployment

Build a static Linux binary:

```bash
make linux
# Output: dist/powguard-linux-amd64 (+ .sha256)
```

Recommended topology:

```text
Caddy / Nginx (HTTPS)
        ↓
powguard  127.0.0.1:3000
        ├── SQLite
        └── in-memory challenges / tokens
```

See **[deploy/README.md](deploy/README.md)** for the complete systemd hardening, Caddy configuration, trusted proxy setup, backup/restore, upgrade/rollback, and troubleshooting guide.

Validated on Aliyun Shenzhen, Rocky Linux 10.2, Caddy 2.11.4, at `cap.mvr.cc`. See **[docs/m5-acceptance.md](docs/m5-acceptance.md)** for the acceptance record.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `POWGUARD_ADDR` | `127.0.0.1:3000` | Listen address; keep it on loopback behind a reverse proxy |
| `POWGUARD_DB_PATH` | `./powguard.sqlite3` | SQLite file path |
| `POWGUARD_PUBLIC_URL` | empty | Public URL; an `https://` URL makes the admin cookie `Secure` |
| `POWGUARD_MASTER_KEY` | empty | 32-byte key (hex/base64) used to encrypt site secrets; existing ciphertext requires it |
| `POWGUARD_ADMIN_KEY` | empty | Admin panel login key; empty disables the admin panel |
| `POWGUARD_TRUST_PROXY` | empty | Comma-separated trusted proxy CIDRs; `X-Forwarded-For` is read only when configured |
| `POWGUARD_SITE_SLUG` | `twikoo` | Used only for first-start bootstrap |
| `POWGUARD_SITE_SECRET` | empty | Used only for first-start bootstrap; set explicitly in production |

> Back up `POWGUARD_MASTER_KEY` and the SQLite database **together but separately**. Without the master key, encrypted site secrets cannot be recovered.

### Operations

```bash
powguard version
powguard backup      --db <path> --out <file>                       # online consistent snapshot
powguard verify-keys --db <path> --master-key <hex|b64>            # validate all ciphertext
powguard keyrotate   --db <path> --old-key <k> --new-key <k>       # rotate the master key
```

`keyrotate` re-encrypts all site secrets in a single transaction. Update `POWGUARD_MASTER_KEY` and restart the service afterwards.

## Twikoo Integration

1. Create a site in the powguard admin panel (for example slug `twikoo`, protocol **format-1 / Twikoo compatible**).
2. Reveal `CAP_SECRET_KEY` on the site's **Keys** page.
3. Configure Twikoo:

```text
CAPTCHA_PROVIDER  = Cap
CAP_API_ENDPOINT  = https://cap.example.com/twikoo/
CAP_SECRET_KEY    = <powguard site secret>
```

`CAP_BUILTIN` is derived by Twikoo from whether `CAP_API_ENDPOINT` is empty; do not set it manually.

By default the Twikoo frontend loads the Cap widget from `cdn.jsdmirror.com`. To use powguard's pinned same-origin assets instead, preload them before the Twikoo script:

```html
<script>window.CAP_CUSTOM_WASM_URL = "https://cap.example.com/static/vendor/cap_wasm_bg.wasm";</script>
<script src="https://cap.example.com/static/vendor/cap.min.js"></script>
```

Acceptance checks:

- Complete the challenge → comment is published;
- Submit without solving → rejected;
- Replay the same token → `404 Token not found`;
- Wrong secret → `403 Invalid site key or secret`;
- Token from site A submitted to site B → rejected.

## HTTP API

| Method | Path | Description |
|---|---|---|
| `POST` | `/{site}/challenge` | Issue a challenge (format-1 or format-2 envelope) |
| `POST` | `/{site}/redeem` | Submit solutions and receive a one-time verification token |
| `POST` | `/{site}/siteverify` | Server-side token check: `{secret, response}` |
| `POST` | `/siteverify` | capd-style pathless variant; site is recovered from the token |
| `OPTIONS` | `/{site}/challenge` etc. | CORS preflight |
| `GET` | `/healthz` | Health check: `{"status":"ok"}` |
| `GET` | `/` | Built-in widget demo page |
| `GET` | `/admin` | Admin panel |
| `GET` | `/static/vendor/*` | Pinned widget / WASM / CSS assets |

Response examples:

```jsonc
// POST /twikoo/challenge (format-1)
{ "challenge": { "c": 50, "s": 32, "d": 4 }, "token": "...", "expires": 1795067399614 }

// POST /twikoo/redeem
{ "success": true, "token": "twikoo:...:...", "expires": 1795068000000 }

// POST /twikoo/siteverify
{ "success": true }
// Failure: { "success": false, "error": "Token not found" }
```

Public endpoints support per-site CORS allowlists, per-IP rate limiting, request body limits, and widget query parameters such as `?wasm=0`.

## Security Model

- Site secrets and format-2 signing keys are encrypted with **AES-256-GCM**; AAD binds the site slug, field name, and schema version.
- Site secrets are compared in constant time; logs, events, and error pages never include secrets.
- Admin sessions store only a token hash; cookies are `HttpOnly`, `Secure` on HTTPS, and `SameSite=Lax`.
- Every mutating admin request requires CSRF; reveal/rotate require the admin key again.
- Events store a **keyed IP digest**, never a plaintext IP; events are retained for 30 days by default.
- `X-Forwarded-For` is trusted only from `POWGUARD_TRUST_PROXY` CIDRs; forged headers are ignored.
- Site deletion is a soft delete so audit events keep their context.

## Project Layout

```text
cmd/powguard/          startup, config, signals, HTTP server, ops subcommands
internal/protocol/     format-1 / format-2 / PRNG / SHA-256 PoW
internal/api/          public / admin / middleware (CORS, rate limit, body limit, real IP)
internal/policy/       site resolution, protocol and policy validation
internal/store/        memory (challenge/token/limiter) and sqlite (sites/keys/sessions/events)
internal/security/     secretbox, session, csrf
internal/events/       asynchronous audit event sink
web/                   html/template + vanilla JS/CSS + go:embed assets
deploy/                systemd, Caddy, env example, backup/restore scripts
docs/                  protocol notes, compatibility matrix, M5 acceptance record
tools/oracle/          official Node fixtures and bidirectional interop
tools/capsolve/        end-to-end test and load-test CLI
```

## Testing & Compatibility

```bash
make test     # unit tests
make race     # go test -race
make check    # gofmt + vet + race (interop tests skip if oracle deps are absent)
make oracle   # official package fixtures + bidirectional interop (run `cd tools/oracle && npm ci` first)
```

Pinned compatibility baseline (see [versions.lock](versions.lock)):

| Component | Version | Verified |
|---|---:|---|
| `@cap.js/widget` | 0.1.63 | Unmodified widget completes challenge → solve → redeem |
| `@cap.js/wasm` | 0.0.8 | Loaded same-origin, no jsDelivr dependency |
| `@cap.js/server` | 4.0.5 | format-1 bidirectional interop |
| `capjs-core` | 0.1.18 | format-2 SHA-256 / scope interop |
| Twikoo | 2.0.17 | External mode, real comment submission and negative cases |

See [docs/protocol-notes.md](docs/protocol-notes.md) and [docs/compat-matrix.md](docs/compat-matrix.md) for protocol details, error semantics, and cross-checks.

## Status & Scope

**Implemented**

- format-1 and format-2 SHA-256;
- multi-site with per-site protocol, difficulty, TTL, CORS, and rate limits;
- admin panel, event audit, SSE, and stats;
- SQLite persistence, secret encryption, and master-key rotation;
- single-node systemd + Caddy deployment and backup/restore;
- real-browser and Twikoo acceptance testing.

**Not implemented**

- HashWX, RSW time-lock puzzles, instrumentation / behavioural detection;
- multi-replica HA or a shared challenge/token store;
- capd's GeoIP/ASN, ClickHouse, webhooks, share links, or full rule DSL;
- feature parity with the complete capd dashboard.

These remain future protocol/provider extensions and are not advertised as stable capabilities today.

## Documentation

- [AGENT.md](AGENT.md) — contributor/agent conventions, architecture, and release gates
- [docs/protocol-notes.md](docs/protocol-notes.md) — format-1 / format-2 / Twikoo protocol notes
- [docs/compat-matrix.md](docs/compat-matrix.md) — compatibility matrix
- [docs/m5-acceptance.md](docs/m5-acceptance.md) — Shenzhen production acceptance record
- [deploy/README.md](deploy/README.md) — systemd + Caddy deployment and operations
- [README.CN.md](README.CN.md) — 简体中文
- [versions.lock](versions.lock) — pinned versions and verified capabilities

## License

Apache-2.0. See [LICENSE](LICENSE).

The protocol design and wire format reference upstream [tiagozip/cap](https://github.com/tiagozip/cap) (Copyright 2025 Tiago) and the npm packages `@cap.js/server` and `capjs-core`. Official widget/WASM assets under `web/static/vendor/` are redistributed under their upstream licenses; see [web/static/vendor/NOTICE.md](web/static/vendor/NOTICE.md) for sources and versions.
