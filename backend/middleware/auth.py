"""
Middleware ASGI de proteção Fail-Closed para rotas MCP.
Endurecido contra bypass de preflight OPTIONS e em conformidade com RFC 6750.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from backend.auth.oauth import SECURITY_HEADERS, verify_jwt_token
from backend.config import settings


class MCPAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # 1. Permite preflight CORS (OPTIONS) transitar livremente para resposta de headers
        if request.method == "OPTIONS":
            return await call_next(request)

        # 2. Rotas públicas do gateway (descoberta OAuth, consentimento, health)
        if (
            path.startswith("/.well-known/")
            or path.startswith("/oauth/")
            or path in ["/", "/health", "/favicon.ico"]
        ):
            response = await call_next(request)
            for k, v in SECURITY_HEADERS.items():
                if k not in response.headers:
                    response.headers[k] = v
            return response

        # 3. Se for rota MCP (/mcp, /sse, /messages), exige autenticação Bearer
        if path.startswith("/mcp") or path.startswith("/sse") or path.startswith("/messages"):
            auth_header = request.headers.get("Authorization", "").strip()
            token = None

            # RFC 6750 §2.1: prefixo Bearer é case-insensitive
            if auth_header and auth_header[:7].lower() == "bearer ":
                token = auth_header[7:].strip()

            if not token:
                headers = dict(SECURITY_HEADERS)
                headers["WWW-Authenticate"] = (
                    f'Bearer realm="secure-mcp", '
                    f'resource_metadata="{settings.base_url}/.well-known/oauth-protected-resource"'
                )
                return JSONResponse(
                    status_code=401,
                    content={"error": "unauthorized", "message": "Token Bearer obrigatório para acessar /mcp"},
                    headers=headers,
                )

            payload = verify_jwt_token(token)
            if not payload:
                headers = dict(SECURITY_HEADERS)
                headers["WWW-Authenticate"] = (
                    f'Bearer realm="secure-mcp", '
                    f'error="invalid_token", '
                    f'resource_metadata="{settings.base_url}/.well-known/oauth-protected-resource"'
                )
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_token", "message": "Token de acesso expirado ou inválido"},
                    headers=headers,
                )

            # Armazena identidade no request.state para auditoria
            request.state.client_id = payload.get("client_id", "unknown")

        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            if k not in response.headers:
                response.headers[k] = v
        return response
