"""
Configuração do gateway.

Segredos vêm de variáveis de ambiente. Opcionalmente, quando
MCP_GATEWAY_USE_PASS=1, são lidos do cofre Unix `pass` (GPG) sob o prefixo
MCP_GATEWAY_PASS_PREFIX (padrão: "mcp-gateway").
"""

from __future__ import annotations

import os
import subprocess
from pydantic_settings import BaseSettings

USE_PASS = os.getenv("MCP_GATEWAY_USE_PASS", "0") == "1"
PASS_PREFIX = os.getenv("MCP_GATEWAY_PASS_PREFIX", "mcp-gateway").rstrip("/")
DOMAIN = os.getenv("MCP_GATEWAY_DOMAIN", "mcp.example.com")


def get_pass_secret(path: str) -> str | None:
    """Recupera um segredo do cofre Unix pass (GPG), se habilitado."""
    if not USE_PASS:
        return None
    try:
        proc = subprocess.run(
            ["pass", "show", path],
            capture_output=True,
            check=True
        )
        return proc.stdout.decode("utf-8").strip()
    except Exception:
        return None


def _secret(name: str) -> str:
    return get_pass_secret(f"{PASS_PREFIX}/{name}") or os.getenv(name, "")


class Settings(BaseSettings):
    app_name: str = "secure-mcp-gateway"
    host: str = "127.0.0.1"
    port: int = 8950
    domain: str = DOMAIN
    base_url: str = f"https://{DOMAIN}"

    # Segredos OAuth (pass opcional, com fallback para variáveis de ambiente)
    client_id: str = _secret("MCP_OAUTH_CLIENT_ID")
    client_secret: str = _secret("MCP_OAUTH_CLIENT_SECRET")
    jwt_secret: str = _secret("MCP_OAUTH_JWT_SECRET")
    master_pin: str = _secret("MCP_OAUTH_MASTER_PIN")

    # JWT Settings
    jwt_algorithm: str = "HS256"
    access_token_expire_seconds: int = 3600  # 1 hora
    refresh_token_expire_days: int = 30     # 30 dias

    # Allowlist estrita de redirect_uris (RFC 6749 §3.1.2.3)
    allowed_redirect_uris: list[str] = [
        "https://gemini.google.com/oauth/callback",
        f"https://{DOMAIN}/docs/oauth2-redirect",
    ]

    # Rate limiting do PIN
    pin_max_attempts: int = 5
    pin_lockout_seconds: int = 900  # 15 minutos

    def validate_fail_closed(self) -> None:
        """Valida que todos os segredos críticos de identidade estão carregados e possuem entropia mínima."""
        errors = []
        if not self.client_id or len(self.client_id.strip()) < 8:
            errors.append("client_id ausente ou menor que 8 caracteres")
        if not self.client_secret or len(self.client_secret.strip()) < 32:
            errors.append("client_secret ausente ou menor que 32 caracteres (256 bits)")
        if not self.jwt_secret or len(self.jwt_secret.strip()) < 32:
            errors.append("jwt_secret ausente ou menor que 32 caracteres (256 bits)")
        if not self.master_pin or len(self.master_pin.strip()) < 6:
            errors.append("master_pin ausente ou menor que 6 caracteres")

        if errors:
            raise RuntimeError(f"FALHA CRÍTICA DE IDENTIDADE (FAIL-CLOSED): {'; '.join(errors)}")


settings = Settings()
