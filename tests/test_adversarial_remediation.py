"""
Bateria de Testes Adversariais de Regressão (Auditoria DSH / CIRES):
Valida a correção rigorosa dos achados A1 a A10 / Bloqueadores B1 a B5.
"""

import base64
import hashlib
import html
import json
import secrets
import time
import jwt
import pytest
from starlette.testclient import TestClient

from backend.config import Settings, settings
from backend.main import app
from backend.auth.oauth import (
    AUTH_CODES,
    REFRESH_TOKENS,
    PIN_FAILURES,
    PIN_LOCKOUTS,
    verify_jwt_token,
    create_access_token,
)


def test_b1_fail_closed_validation():
    """B1 / A1: Testa que o sistema falha fechado se segredos forem vazios ou curtos."""
    # Instância com chaves nulas ou fracas deve lançar RuntimeError
    broken_settings = Settings(
        client_id="",
        client_secret="curto",
        jwt_secret="",
        master_pin="",
    )
    with pytest.raises(RuntimeError) as exc_info:
        broken_settings.validate_fail_closed()
    assert "FAIL-CLOSED" in str(exc_info.value)

    # Token assinado com chave vazia "" NÃO PODE ser aceito por verify_jwt_token
    try:
        token_forjado = jwt.encode(
            {"iss": settings.base_url, "sub": "attacker", "client_id": "attacker", "exp": int(time.time()) + 3600},
            "",
            algorithm="HS256"
        )
        assert verify_jwt_token(token_forjado) is None
    except jwt.exceptions.InvalidKeyError:
        # O próprio PyJWT mais recente rejeita chave vazia de imediato
        pass


def test_b2_xss_prevention_and_security_headers(client: TestClient):
    """B2 / A2: Testa que injeções XSS são escapadas e headers de segurança são enviados."""
    xss_payload = 'https://gemini.google.com/oauth/callback"><script>alert(document.domain)</script>'
    xss_state = '<img src=x onerror=alert(1)>'

    # Gerar PKCE verifier/challenge válidos
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    # Request com payloads XSS
    res = client.get(
        "/oauth/authorize",
        params={
            "client_id": settings.client_id,
            "redirect_uri": "https://gemini.google.com/oauth/callback",
            "state": xss_state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    assert res.status_code == 200
    # O payload bruto NÃO PODE existir no HTML retornado
    assert "<script>" not in res.text
    assert "<img" not in res.text
    assert "&lt;img" in res.text or "&quot;" in res.text

    # Headers de Segurança Obrigatórios
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert "default-src 'self'" in res.headers.get("Content-Security-Policy", "")
    assert "no-store" in res.headers.get("Cache-Control", "")


def test_b3_redirect_uri_allowlist_and_matching(client: TestClient):
    """B3 / A3: Testa rejeição de URIs fora da allowlist e validação cruzada no /oauth/token."""
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    # 1. Tentativa de autorizar para domínio de atacante -> Deve retornar 400
    res = client.get(
        "/oauth/authorize",
        params={
            "client_id": settings.client_id,
            "redirect_uri": "https://attacker.example/steal",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    assert res.status_code == 400
    assert "redirect_uri" in res.text.lower()

    # 2. Autoriza com URI legítima
    legit_uri = "https://gemini.google.com/oauth/callback"
    post_res = client.post(
        "/oauth/authorize",
        data={
            "pin": settings.master_pin,
            "client_id": settings.client_id,
            "redirect_uri": legit_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert post_res.status_code == 302
    location = post_res.headers["location"]
    code = location.split("code=")[1].split("&")[0]

    # 3. Tenta trocar o code usando redirect_uri divergente -> Deve retornar 400
    token_res = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://outro-host.example/diferente",
            "client_id": settings.client_id,
            "client_secret": settings.client_secret,
            "code_verifier": verifier,
        }
    )
    assert token_res.status_code == 400
    assert "redirect_uri" in token_res.text.lower()


def test_b3_pkce_s256_mandatory(client: TestClient):
    """B3 / A7: Testa que PKCE S256 é estritamente obrigatório (sem bypass plain ou vazio)."""
    # 1. Sem challenge -> Deve ser 400
    res = client.get(
        "/oauth/authorize",
        params={
            "client_id": settings.client_id,
            "redirect_uri": "https://gemini.google.com/oauth/callback",
        }
    )
    assert res.status_code == 400
    assert "pkce" in res.text.lower()

    # 2. Com method "plain" -> Deve ser 400
    res = client.get(
        "/oauth/authorize",
        params={
            "client_id": settings.client_id,
            "redirect_uri": "https://gemini.google.com/oauth/callback",
            "code_challenge": "plain_challenge",
            "code_challenge_method": "plain",
        }
    )
    assert res.status_code == 400


def test_b4_pin_rate_limiting_and_lockout(client: TestClient):
    """B4 / A4: Testa que 5 tentativas incorretas bloqueiam o IP com 429 e Retry-After."""
    PIN_FAILURES.clear()
    PIN_LOCKOUTS.clear()

    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    headers = {"CF-Connecting-IP": "203.0.113.199"}
    data = {
        "pin": "wrong_pin",
        "client_id": settings.client_id,
        "redirect_uri": "https://gemini.google.com/oauth/callback",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    # 5 tentativas erradas -> 401
    for i in range(5):
        res = client.post("/oauth/authorize", data=data, headers=headers)
        assert res.status_code == 401

    # 6ª tentativa -> Deve retornar 429 Too Many Requests com Retry-After
    res_locked = client.post("/oauth/authorize", data=data, headers=headers)
    assert res_locked.status_code == 429
    assert "Retry-After" in res_locked.headers


def test_b5_docs_disabled(client: TestClient):
    """B5 / A5: Testa que /docs, /redoc e /openapi.json estão desativados."""
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_a8_refresh_token_rotation(client: TestClient):
    """A8: Testa rotação de refresh token (token usado uma vez é invalidado)."""
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    legit_uri = "https://gemini.google.com/oauth/callback"
    post_res = client.post(
        "/oauth/authorize",
        data={
            "pin": settings.master_pin,
            "client_id": settings.client_id,
            "redirect_uri": legit_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    code = post_res.headers["location"].split("code=")[1].split("&")[0]

    token_res = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": legit_uri,
            "client_id": settings.client_id,
            "client_secret": settings.client_secret,
            "code_verifier": verifier,
        }
    )
    assert token_res.status_code == 200
    data = token_res.json()
    first_refresh = data["refresh_token"]

    # 1º Refresh -> Sucesso, recebe novo refresh_token
    refresh_res = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": first_refresh,
            "client_id": settings.client_id,
            "client_secret": settings.client_secret,
        }
    )
    assert refresh_res.status_code == 200
    new_data = refresh_res.json()
    second_refresh = new_data["refresh_token"]
    assert second_refresh != first_refresh

    # 2º Refresh com o token antigo (já rotacionado) -> Deve falhar com 400
    replay_res = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": first_refresh,
            "client_id": settings.client_id,
            "client_secret": settings.client_secret,
        }
    )
    assert replay_res.status_code == 400


def test_a9_options_preflight(client: TestClient):
    """A9: Testa que OPTIONS /mcp responde com 200 para preflight CORS sem exigir auth."""
    headers = {
        "Origin": "https://gemini.google.com",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Authorization, Content-Type",
    }
    res = client.options("/mcp", headers=headers)
    assert res.status_code == 200


def test_a13_bearer_case_insensitive(client: TestClient):
    """A13: Testa que o prefixo Bearer é case-insensitive conforme RFC 6750 §2.1."""
    access_token = create_access_token(settings.client_id)
    headers = {
        "Authorization": f"bearer {access_token}",
        "Host": "mcp.example.com",
    }
    res = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"}, headers=headers)
    # Token válido com "bearer" minúsculo NÃO PODE ser 401
    assert res.status_code != 401
