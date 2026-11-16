# Secure MCP Gateway

[![tests](https://github.com/Rlealbarili/secure-mcp-gateway/actions/workflows/tests.yml/badge.svg)](https://github.com/Rlealbarili/secure-mcp-gateway/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**English** | [Português (Brasil)](README.pt-BR.md)

A small, fail-closed gateway that exposes a private server to remote AI clients (such as Google Gemini) through the **Model Context Protocol (MCP)** over **Streamable HTTP**, protected by an embedded **OAuth 2.0 authorization server with PKCE (S256)** and **JWT bearer tokens**.

It started as the entry point that lets a web AI assistant reach a self-hosted Linux server behind a Cloudflare Tunnel without opening ports or putting credentials in URLs.

## What is implemented (phase 1)

| Area | Details |
|---|---|
| Discovery | `/.well-known/oauth-authorization-server` (RFC 8414) and `/.well-known/oauth-protected-resource` (RFC 9728) |
| Authorization | Authorization Code flow with **mandatory PKCE S256** (no `plain`, no empty challenge), strict `redirect_uri` allowlist, short-lived single-use codes |
| Consent | Human-in-the-loop consent page protected by an operator PIN, with per-IP failure counting, lockout and `Retry-After` |
| Tokens | HS256 JWT access tokens (1 h) and rotating refresh tokens (30 d); client authentication by `client_secret` |
| Resource protection | Middleware that rejects any `/mcp` call without a valid bearer token and returns a standards-compliant `WWW-Authenticate` header |
| Transport | FastMCP Streamable HTTP (stateless) mounted on FastAPI, with host and origin allowlists and security headers |
| Fail-closed boot | The service refuses to start if any secret is missing or below the minimum entropy (client secret and JWT secret ≥ 256 bits) |
| Secrets | Environment variables, or the Unix `pass` vault (GPG) when `MCP_GATEWAY_USE_PASS=1` |
| MCP tools | `ping_server`: authenticated smoke test returning host status and uptime |

**Not implemented yet (roadmap):** command-execution tools with deterministic guardrails, an append-only audit log, and persistent storage for codes and tokens (they are in-memory today, so a restart invalidates sessions).

## Tests

12 automated tests run in CI with ephemeral secrets generated per run:

- discovery metadata and unauthenticated rejection;
- the complete OAuth 2.0 + PKCE flow followed by `tools/list` and `tools/call` over MCP;
- adversarial regressions: fail-closed boot with weak secrets, forged JWTs, PKCE bypass attempts (`plain` or empty), `redirect_uri` tampering, PIN brute force and lockout, refresh-token reuse, XSS escaping and security headers on the consent page, disabled API docs, CORS preflight and case-insensitive `Bearer` parsing (RFC 6750).

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
python -m pytest -q
```

## Running

```bash
# 1. Secrets (choose one)
export MCP_OAUTH_CLIENT_ID=...  MCP_OAUTH_CLIENT_SECRET=...  MCP_OAUTH_JWT_SECRET=...  MCP_OAUTH_MASTER_PIN=...
#    or store them in pass and enable it:
python3 scripts/setup_oauth_secrets.py && export MCP_GATEWAY_USE_PASS=1

# 2. Public domain served by your tunnel / reverse proxy
export MCP_GATEWAY_DOMAIN=mcp.your-domain.com

# 3. Start (binds to 127.0.0.1 only)
scripts/run_gateway.sh

# 4. Expose it, e.g. with Cloudflare Tunnel
cloudflared tunnel route dns <TUNNEL_ID> mcp.your-domain.com
```

Configuration variables: `MCP_GATEWAY_DOMAIN`, `MCP_GATEWAY_PORT` (default 8950), `MCP_GATEWAY_USE_PASS`, `MCP_GATEWAY_PASS_PREFIX` (default `mcp-gateway`), and the four `MCP_OAUTH_*` secrets.

## Design principles

- **Fail closed:** missing or weak identity material stops the service; invalid tokens never reach MCP.
- **Small surface:** discovery, authorize, token and `/mcp` only; interactive API docs are disabled.
- **No secrets in URLs or code:** credentials live in the environment or in an encrypted vault.
- **Security mapped to NIST CSF 2.0** (Protect: identity and access control; Detect: auth failures and lockouts).

## Stack

Python 3.12, FastAPI, MCP Python SDK (FastMCP, Streamable HTTP), PyJWT, Pydantic Settings, pytest.

## Author and license

Rafael Henrique Leal Barili ([@Rlealbarili](https://github.com/Rlealbarili)). Licensed under the [Apache License 2.0](LICENSE).
