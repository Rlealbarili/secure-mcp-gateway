"""
Fixtures globais da suíte de testes do Secure MCP Gateway.
Gera segredos efêmeros por execução (nada de credenciais reais) e compartilha
uma única instância de TestClient para respeitar o ciclo de vida do FastMCP.
"""

import os
import secrets

os.environ.setdefault("MCP_GATEWAY_USE_PASS", "0")
os.environ.setdefault("MCP_GATEWAY_DOMAIN", "mcp.example.com")
os.environ.setdefault("MCP_OAUTH_CLIENT_ID", f"test-client-{secrets.token_hex(8)}")
os.environ.setdefault("MCP_OAUTH_CLIENT_SECRET", secrets.token_urlsafe(48))
os.environ.setdefault("MCP_OAUTH_JWT_SECRET", secrets.token_urlsafe(48))
os.environ.setdefault("MCP_OAUTH_MASTER_PIN", str(secrets.randbelow(10**8)).zfill(8))

import pytest  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from backend.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app, base_url="https://mcp.example.com") as c:
        yield c
