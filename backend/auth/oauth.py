"""
Provedor OAuth 2.0 Embutido (RFC 6749, RFC 7636 PKCE, RFC 8414, RFC 9728).
Endurecido contra XSS, timing attacks, força bruta e bypass de identidade.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import secrets
import time
from typing import Optional

import jwt
from fastapi import APIRouter, Form, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from backend.config import settings

oauth_router = APIRouter(tags=["OAuth 2.0"])

# Armazenamento em memória para códigos de autorização e refresh tokens
AUTH_CODES: dict[str, dict] = {}
REFRESH_TOKENS: dict[str, dict] = {}

# Rastreamento para rate-limiting e lockout no PIN
PIN_FAILURES: dict[str, list[float]] = {}
PIN_LOCKOUTS: dict[str, float] = {}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self';"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
}


def clean_expired_data():
    """Remove códigos e refresh tokens expirados periodicamente."""
    now = time.time()
    expired_codes = [k for k, v in AUTH_CODES.items() if v["expires_at"] < now]
    for k in expired_codes:
        del AUTH_CODES[k]

    expired_refreshes = [k for k, v in REFRESH_TOKENS.items() if v["expires_at"] < now]
    for k in expired_refreshes:
        del REFRESH_TOKENS[k]


def get_client_ip(request: Request) -> str:
    """Extrai o IP real do cliente, priorizando o cabeçalho do Cloudflare Named Tunnel."""
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "127.0.0.1"


def verify_client_credentials(
    auth_header: Optional[str],
    body_client_id: Optional[str],
    body_client_secret: Optional[str],
) -> bool:
    """Valida as credenciais do cliente via HTTP Basic ou form-data em tempo constante."""
    client_id = ""
    client_secret = ""

    if auth_header and auth_header.startswith("Basic "):
        try:
            encoded = auth_header[6:].strip()
            decoded = base64.b64decode(encoded).decode("utf-8")
            if ":" in decoded:
                client_id, client_secret = decoded.split(":", 1)
        except Exception:
            return False
    elif body_client_id and body_client_secret:
        client_id = body_client_id
        client_secret = body_client_secret

    if not client_id or not client_secret:
        return False

    if not settings.client_id or not settings.client_secret:
        return False

    id_match = hmac.compare_digest(client_id, settings.client_id)
    secret_match = hmac.compare_digest(client_secret, settings.client_secret)
    return id_match and secret_match


def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    """Verifica o code_verifier contra o code_challenge registrado. S256 é mandatório."""
    if not code_challenge or not code_verifier:
        return False

    if method != "S256":
        return False  # Proibido método plain ou downgrade

    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return hmac.compare_digest(computed, code_challenge.rstrip("="))


def create_access_token(client_id: str) -> str:
    """Emite um JWT assinado. Falha fechado se jwt_secret for fraco ou ausente."""
    if not settings.jwt_secret or len(settings.jwt_secret.strip()) < 32:
        raise RuntimeError("FALHA CRÍTICA: jwt_secret ausente ou menor que 32 caracteres")

    now = int(time.time())
    payload = {
        "iss": settings.base_url,
        "sub": client_id,
        "client_id": client_id,
        "aud": settings.base_url,
        "iat": now,
        "exp": now + settings.access_token_expire_seconds,
        "scope": "mcp:all",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def verify_jwt_token(token: str) -> dict | None:
    """Valida integridade, expiração e emissor de um token JWT. Rejeita chave vazia."""
    if not settings.jwt_secret or len(settings.jwt_secret.strip()) < 32:
        return None

    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.base_url,
            audience=settings.base_url,
        )
        return payload
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 1. Metadados e Discovery (RFC 8414 & RFC 9728)
# ─────────────────────────────────────────────────────────────────────────────

@oauth_router.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource():
    return JSONResponse(
        content={
            "resource": f"{settings.base_url}/mcp",
            "authorization_servers": [settings.base_url],
            "bearer_methods_supported": ["header"],
        },
        headers=SECURITY_HEADERS,
    )


@oauth_router.get("/.well-known/oauth-authorization-server")
@oauth_router.get("/.well-known/openid-configuration")
async def oauth_authorization_server():
    return JSONResponse(
        content={
            "issuer": settings.base_url,
            "authorization_endpoint": f"{settings.base_url}/oauth/authorize",
            "token_endpoint": f"{settings.base_url}/oauth/token",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],  # plain removido
        },
        headers=SECURITY_HEADERS,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Endpoint de Autorização Humana (/oauth/authorize)
# ─────────────────────────────────────────────────────────────────────────────

@oauth_router.get("/oauth/authorize", response_class=HTMLResponse)
async def authorize_get(
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    scope: str = "mcp:all",
):
    if response_type != "code":
        raise HTTPException(
            status_code=400,
            detail="unsupported_response_type: apenas 'code' é suportado"
        )

    # Validar se o client_id é o nosso
    if not settings.client_id or not hmac.compare_digest(client_id, settings.client_id):
        raise HTTPException(status_code=400, detail="client_id inválido")

    # Validar allowlist de redirect_uri (RFC 6749 §3.1.2.3)
    if redirect_uri not in settings.allowed_redirect_uris:
        raise HTTPException(status_code=400, detail="redirect_uri não autorizada ou não registrada")

    # PKCE S256 Mandatório (RFC 7636)
    if not code_challenge or code_challenge_method != "S256":
        raise HTTPException(
            status_code=400,
            detail="PKCE code_challenge com code_challenge_method='S256' é obrigatório"
        )

    # Sanitização contra XSS refletido (B2)
    safe_client_id = html.escape(client_id, quote=True)
    safe_redirect_uri = html.escape(redirect_uri, quote=True)
    safe_state = html.escape(state, quote=True)
    safe_code_challenge = html.escape(code_challenge, quote=True)
    safe_code_challenge_method = html.escape(code_challenge_method, quote=True)

    html_content = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secure MCP Gateway — Autorização</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a;
      color: #f8fafc;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 16px;
    }}
    .card {{
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 32px;
      width: 100%;
      max-width: 440px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    }}
    h1 {{
      font-size: 1.25rem;
      margin-top: 0;
      display: flex;
      align-items: center;
      gap: 8px;
      color: #38bdf8;
    }}
    p {{
      font-size: 0.9rem;
      color: #94a3b8;
      line-height: 1.5;
    }}
    .badge {{
      display: inline-block;
      background: #0369a1;
      color: #e0f2fe;
      font-size: 0.75rem;
      padding: 2px 8px;
      border-radius: 4px;
      margin-bottom: 16px;
    }}
    label {{
      display: block;
      font-size: 0.85rem;
      margin-bottom: 6px;
      color: #cbd5e1;
    }}
    input[type="password"] {{
      width: 100%;
      padding: 10px 12px;
      background: #0f172a;
      border: 1px solid #475569;
      border-radius: 6px;
      color: #fff;
      font-size: 1rem;
      box-sizing: border-box;
      margin-bottom: 20px;
    }}
    input[type="password"]:focus {{
      border-color: #38bdf8;
      outline: none;
    }}
    button {{
      width: 100%;
      padding: 12px;
      background: #0284c7;
      color: #fff;
      border: none;
      border-radius: 6px;
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
    }}
    button:hover {{
      background: #0369a1;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>🛡️ Secure MCP Gateway</h1>
    <span class="badge">Google Gemini Conexão</span>
    <p>O Google Gemini solicitou autorização para se conectar ao seu <strong>servidor protegido</strong> via MCP.</p>
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="{safe_client_id}">
      <input type="hidden" name="redirect_uri" value="{safe_redirect_uri}">
      <input type="hidden" name="state" value="{safe_state}">
      <input type="hidden" name="code_challenge" value="{safe_code_challenge}">
      <input type="hidden" name="code_challenge_method" value="{safe_code_challenge_method}">
      
      <label for="pin">Digite a Senha Mestre (PIN):</label>
      <input type="password" id="pin" name="pin" autofocus required placeholder="••••••" autocomplete="current-password">
      
      <button type="submit">Autorizar Conexão</button>
    </form>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html_content, headers=SECURITY_HEADERS)


@oauth_router.post("/oauth/authorize")
async def authorize_post(
    request: Request,
    pin: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(""),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form("S256"),
):
    clean_expired_data()
    now = time.time()
    client_ip = get_client_ip(request)

    # 1. Checagem de Lockout por IP (B4)
    if client_ip in PIN_LOCKOUTS:
        lockout_expiry = PIN_LOCKOUTS[client_ip]
        if now < lockout_expiry:
            retry_after = max(1, int(lockout_expiry - now))
            headers = dict(SECURITY_HEADERS)
            headers["Retry-After"] = str(retry_after)
            return HTMLResponse(
                content=f"<h3>❌ IP bloqueado por tentativas excessivas. Tente novamente em {retry_after} segundos.</h3>",
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers=headers,
            )
        else:
            del PIN_LOCKOUTS[client_ip]

    # 2. Validações preliminares
    if not settings.client_id or not hmac.compare_digest(client_id, settings.client_id):
        raise HTTPException(status_code=400, detail="client_id inválido")

    if redirect_uri not in settings.allowed_redirect_uris:
        raise HTTPException(status_code=400, detail="redirect_uri não autorizada ou não registrada")

    if not code_challenge or code_challenge_method != "S256":
        raise HTTPException(status_code=400, detail="PKCE S256 obrigatório")

    # 3. Validação do PIN com tempo constante e proteção fail-closed
    if not settings.master_pin or len(settings.master_pin.strip()) < 6:
        raise HTTPException(status_code=500, detail="Configuração de segurança incompleta no gateway")

    is_pin_valid = hmac.compare_digest(pin.strip(), settings.master_pin.strip())

    if not is_pin_valid:
        # Registrar falha e aplicar Rate-Limit (B4)
        failures = PIN_FAILURES.setdefault(client_ip, [])
        # Filtrar falhas nos últimos 300 segundos
        failures = [t for t in failures if (now - t) < 300]
        failures.append(now)
        PIN_FAILURES[client_ip] = failures

        if len(failures) > settings.pin_max_attempts:
            PIN_LOCKOUTS[client_ip] = now + settings.pin_lockout_seconds
            headers = dict(SECURITY_HEADERS)
            headers["Retry-After"] = str(settings.pin_lockout_seconds)
            return HTMLResponse(
                content="<h3>❌ Muitas tentativas incorretas. IP bloqueado temporariamente por 15 minutos.</h3>",
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers=headers,
            )

        attempts_left = max(0, settings.pin_max_attempts - len(failures))
        return HTMLResponse(
            content=f"<h3>❌ Senha Mestre incorreta!</h3><p>Tentativas restantes antes do bloqueio: {attempts_left}</p><p><a href='javascript:history.back()'>Tentar novamente</a></p>",
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers=SECURITY_HEADERS,
        )

    # Sucesso no PIN -> limpa falhas do IP
    PIN_FAILURES.pop(client_ip, None)

    # Gera código de autorização seguro (TTL de 60 segundos)
    code = secrets.token_urlsafe(32)
    AUTH_CODES[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at": time.time() + 60,
    }

    # Redireciona de volta para o cliente autorizado
    separator = "&" if "?" in redirect_uri else "?"
    target_url = f"{redirect_uri}{separator}code={code}"
    if state:
        target_url += f"&state={html.escape(state, quote=True)}"

    response = RedirectResponse(url=target_url, status_code=status.HTTP_302_FOUND)
    for k, v in SECURITY_HEADERS.items():
        response.headers[k] = v
    return response


# ─────────────────────────────────────────────────────────────────────────────
# 3. Endpoint de Troca e Renovação de Token (/oauth/token)
# ─────────────────────────────────────────────────────────────────────────────

@oauth_router.post("/oauth/token")
async def oauth_token(
    request: Request,
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    authorization: Optional[str] = Header(None),
):
    clean_expired_data()

    # Validação das credenciais do cliente
    if not verify_client_credentials(authorization, client_id, client_secret):
        headers = dict(SECURITY_HEADERS)
        headers["WWW-Authenticate"] = "Basic"
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "invalid_client", "error_description": "Credenciais OAuth inválidas"},
            headers=headers,
        )

    effective_client_id = client_id or settings.client_id

    # Caso A: Troca de Authorization Code
    if grant_type == "authorization_code":
        if not code or code not in AUTH_CODES:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "invalid_grant", "error_description": "Authorization code inválido ou expirado"},
                headers=SECURITY_HEADERS,
            )

        code_data = AUTH_CODES.pop(code)  # Código de uso único!

        # B3: redirect_uri deve ser fornecida e coincidir estritamente com a do code
        if not redirect_uri or redirect_uri != code_data["redirect_uri"]:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "invalid_grant", "error_description": "redirect_uri não corresponde à do código"},
                headers=SECURITY_HEADERS,
            )

        # B3 / A7: PKCE S256 mandatório
        if not code_verifier or not verify_pkce(
            code_verifier, code_data["code_challenge"], code_data["code_challenge_method"]
        ):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "invalid_grant", "error_description": "Falha na validação PKCE (code_verifier)"},
                headers=SECURITY_HEADERS,
            )

        # Emite Access Token e Refresh Token
        access_token = create_access_token(effective_client_id)
        new_refresh = secrets.token_urlsafe(48)
        REFRESH_TOKENS[new_refresh] = {
            "client_id": effective_client_id,
            "expires_at": time.time() + (settings.refresh_token_expire_days * 86400),
        }

        return JSONResponse(
            content={
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": settings.access_token_expire_seconds,
                "refresh_token": new_refresh,
                "scope": "mcp:all",
            },
            headers=SECURITY_HEADERS,
        )

    # Caso B: Renovação via Refresh Token com ROTAÇÃO MANDATÓRIA (A8)
    elif grant_type == "refresh_token":
        if not refresh_token or refresh_token not in REFRESH_TOKENS:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "invalid_grant", "error_description": "Refresh token inválido ou já utilizado"},
                headers=SECURITY_HEADERS,
            )

        token_data = REFRESH_TOKENS.pop(refresh_token)  # Rotacionado: uso único!
        if token_data["expires_at"] < time.time():
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "invalid_grant", "error_description": "Refresh token expirado"},
                headers=SECURITY_HEADERS,
            )

        # Emite novo access_token e rotaciona o refresh_token
        access_token = create_access_token(effective_client_id)
        new_refresh = secrets.token_urlsafe(48)
        REFRESH_TOKENS[new_refresh] = {
            "client_id": effective_client_id,
            "expires_at": time.time() + (settings.refresh_token_expire_days * 86400),
        }

        return JSONResponse(
            content={
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": settings.access_token_expire_seconds,
                "refresh_token": new_refresh,
                "scope": "mcp:all",
            },
            headers=SECURITY_HEADERS,
        )

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "unsupported_grant_type", "error_description": f"grant_type '{grant_type}' não suportado"},
        headers=SECURITY_HEADERS,
    )
