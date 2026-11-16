#!/usr/bin/env python3
"""
Gera e armazena os segredos OAuth 2.0 do gateway no cofre Unix pass.
Caminhos (prefixo configurável por MCP_GATEWAY_PASS_PREFIX, padrão "mcp-gateway"):
- <prefixo>/MCP_OAUTH_CLIENT_ID
- <prefixo>/MCP_OAUTH_CLIENT_SECRET
- <prefixo>/MCP_OAUTH_JWT_SECRET
- <prefixo>/MCP_OAUTH_MASTER_PIN
Depois rode o gateway com MCP_GATEWAY_USE_PASS=1.
"""

import os
import secrets
import subprocess
import sys


PREFIX = os.getenv("MCP_GATEWAY_PASS_PREFIX", "mcp-gateway").rstrip("/")


def set_pass_key(path: str, value: str) -> bool:
    """Insere um valor no cofre pass sem interação manual."""
    try:
        proc = subprocess.run(
            ["pass", "insert", "-f", "-m", path],
            input=value.encode("utf-8"),
            capture_output=True,
            check=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Erro ao salvar {path} no pass: {e.stderr.decode()}", file=sys.stderr)
        return False


def get_pass_key(path: str) -> str | None:
    """Recupera um valor do cofre pass."""
    try:
        proc = subprocess.run(
            ["pass", "show", path],
            capture_output=True,
            check=True
        )
        return proc.stdout.decode("utf-8").strip()
    except subprocess.CalledProcessError:
        return None


def main():
    print("🔐 Configurando Segredos OAuth 2.0 no Cofre pass...")

    # 1. Client ID
    client_id = get_pass_key(f"{PREFIX}/MCP_OAUTH_CLIENT_ID")
    if not client_id:
        client_id = f"mcp-client-{secrets.token_hex(8)}"
        set_pass_key(f"{PREFIX}/MCP_OAUTH_CLIENT_ID", client_id)
        print(f"  ✓ MCP_OAUTH_CLIENT_ID gerado: {client_id}")
    else:
        print(f"  ✓ MCP_OAUTH_CLIENT_ID existente: {client_id}")

    # 2. Client Secret
    client_secret = get_pass_key(f"{PREFIX}/MCP_OAUTH_CLIENT_SECRET")
    if not client_secret:
        client_secret = secrets.token_urlsafe(32)
        set_pass_key(f"{PREFIX}/MCP_OAUTH_CLIENT_SECRET", client_secret)
        print(f"  ✓ MCP_OAUTH_CLIENT_SECRET gerado.")
    else:
        print(f"  ✓ MCP_OAUTH_CLIENT_SECRET existente.")

    # 3. JWT Secret
    jwt_secret = get_pass_key(f"{PREFIX}/MCP_OAUTH_JWT_SECRET")
    if not jwt_secret:
        jwt_secret = secrets.token_hex(32)
        set_pass_key(f"{PREFIX}/MCP_OAUTH_JWT_SECRET", jwt_secret)
        print(f"  ✓ MCP_OAUTH_JWT_SECRET gerado.")
    else:
        print(f"  ✓ MCP_OAUTH_JWT_SECRET existente.")

    # 4. Master PIN
    master_pin = get_pass_key(f"{PREFIX}/MCP_OAUTH_MASTER_PIN")
    if not master_pin:
        # Gera PIN de 6 dígitos para tela de autorização
        master_pin = f"{secrets.randbelow(900000) + 100000}"
        set_pass_key(f"{PREFIX}/MCP_OAUTH_MASTER_PIN", master_pin)
        print(f"  ✓ MCP_OAUTH_MASTER_PIN gerado: {master_pin}")
    else:
        print(f"  ✓ MCP_OAUTH_MASTER_PIN existente: {master_pin}")

    print("\n✅ Todos os segredos OAuth estão seguros no cofre pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
