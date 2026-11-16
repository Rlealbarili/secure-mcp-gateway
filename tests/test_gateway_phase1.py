"""
Testes automatizados da Fase 1 do Secure MCP Gateway:
- Discovery OAuth 2.0 (RFC 8414 & RFC 9728)
- Proteção Fail-Closed em /mcp
- Fluxo de Autorização e Consentimento
- Troca de Código por Token JWT com PKCE
- Execução da ferramenta ping_server autenticada
"""

import base64
import hashlib
import json
import secrets
import pytest
from starlette.testclient import TestClient

from backend.config import settings
from backend.main import app


def test_discovery_endpoints(client: TestClient):
    # 1. Protected Resource
    res = client.get("/.well-known/oauth-protected-resource")
    assert res.status_code == 200
    data = res.json()
    assert data["resource"] == "https://mcp.example.com/mcp"
    assert "authorization_servers" in data

    # 2. Authorization Server
    res = client.get("/.well-known/oauth-authorization-server")
    assert res.status_code == 200
    data = res.json()
    assert data["token_endpoint"] == "https://mcp.example.com/oauth/token"
    assert data["authorization_endpoint"] == "https://mcp.example.com/oauth/authorize"
    assert "S256" in data["code_challenge_methods_supported"]


def test_mcp_unauthorized_rejection(client: TestClient):
    headers = {
        "Host": "mcp.example.com",
        "Accept": "application/json, text/event-stream",
    }
    # Sem header Authorization -> Deve ser 401
    res = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"}, headers=headers)
    assert res.status_code == 401
    assert "WWW-Authenticate" in res.headers
    assert "Bearer" in res.headers["WWW-Authenticate"]

    # Com token forjado/inválido -> Deve ser 401
    headers["Authorization"] = "Bearer token_falso_invalido"
    res = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"}, headers=headers)
    assert res.status_code == 401


def test_full_oauth_pkce_and_mcp_flow(client: TestClient):
    # 1. Gerar PKCE verifier e challenge (S256)
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    # 2. GET /oauth/authorize (Consent Screen)
    auth_params = {
        "client_id": settings.client_id,
        "redirect_uri": "https://gemini.google.com/oauth/callback",
        "state": "state_12345",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    res = client.get("/oauth/authorize", params=auth_params)
    assert res.status_code == 200
    assert "Secure MCP Gateway" in res.text

    # 3. POST /oauth/authorize com PIN incorreto -> 401
    post_data = dict(auth_params)
    post_data["pin"] = "wrong_pin"
    res = client.post("/oauth/authorize", data=post_data)
    assert res.status_code == 401

    # 4. POST /oauth/authorize com PIN correto -> 302 Redirect
    post_data["pin"] = settings.master_pin
    res = client.post("/oauth/authorize", data=post_data, follow_redirects=False)
    assert res.status_code == 302
    location = res.headers["location"]
    assert "code=" in location
    assert "state=state_12345" in location

    # Extrair código
    code = location.split("code=")[1].split("&")[0]

    # 5. POST /oauth/token (Troca com PKCE)
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://gemini.google.com/oauth/callback",
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
        "code_verifier": verifier,
    }
    res = client.post("/oauth/token", data=token_data)
    assert res.status_code == 200, res.text
    token_response = res.json()
    assert "access_token" in token_response
    assert token_response["token_type"] == "Bearer"
    assert "refresh_token" in token_response

    access_token = token_response["access_token"]

    # 6. POST /mcp Authenticated Initialize
    headers = {
        "Host": "mcp.example.com",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {access_token}",
    }
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "gemini-web", "version": "1.0"},
        },
    }
    res = client.post("/mcp", json=init_payload, headers=headers)
    assert res.status_code == 200, res.text
    assert "secure-mcp-gateway" in res.text

    # 7. POST /mcp tools/list -> verifica ping_server
    tools_list_payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    }
    res = client.post("/mcp", json=tools_list_payload, headers=headers)
    assert res.status_code == 200, res.text
    assert "ping_server" in res.text

    # 8. POST /mcp tools/call (ping_server) -> valida resposta
    call_payload = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "ping_server",
            "arguments": {},
        },
    }
    res = client.post("/mcp", json=call_payload, headers=headers)
    assert res.status_code == 200, res.text
    assert "operational" in res.text
    assert "servidor protegido" in res.text


def main():
    print("🧪 Executando Bateria de Testes da Fase 1...")
    with TestClient(app, base_url="https://mcp.example.com") as client:
        test_discovery_endpoints(client)
        print("  ✅ test_discovery_endpoints PASSOU!")
        test_mcp_unauthorized_rejection(client)
        print("  ✅ test_mcp_unauthorized_rejection PASSOU!")
        test_full_oauth_pkce_and_mcp_flow(client)
        print("  ✅ test_full_oauth_pkce_and_mcp_flow PASSOU!")
    print("\n🎉 TODOS OS TESTES DA FASE 1 PASSARAM COM SUCESSO!")


if __name__ == "__main__":
    main()
