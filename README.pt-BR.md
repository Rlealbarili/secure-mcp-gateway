# Secure MCP Gateway

[![tests](https://github.com/Rlealbarili/secure-mcp-gateway/actions/workflows/tests.yml/badge.svg)](https://github.com/Rlealbarili/secure-mcp-gateway/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![Licença](https://img.shields.io/badge/Licen%C3%A7a-Apache%202.0-blue.svg)](LICENSE)

[English](README.md) | **Português (Brasil)**

Gateway pequeno e *fail-closed* que expõe um servidor privado a clientes de IA remotos (como o Google Gemini) pelo **Model Context Protocol (MCP)** sobre **Streamable HTTP**, protegido por um **servidor de autorização OAuth 2.0 com PKCE (S256)** embutido e **tokens JWT Bearer**.

Nasceu como a porta de entrada que permite a um assistente de IA na web alcançar um servidor Linux próprio atrás de um Cloudflare Tunnel, sem abrir portas e sem credenciais em URLs.

## O que está implementado (fase 1)

| Área | Detalhes |
|---|---|
| Descoberta | `/.well-known/oauth-authorization-server` (RFC 8414) e `/.well-known/oauth-protected-resource` (RFC 9728) |
| Autorização | Fluxo Authorization Code com **PKCE S256 obrigatório** (sem `plain` nem desafio vazio), allowlist estrita de `redirect_uri`, códigos de uso único e curta duração |
| Consentimento | Tela de consentimento com PIN do operador, contagem de falhas por IP, bloqueio e `Retry-After` |
| Tokens | Access token JWT HS256 (1 h) e refresh token rotativo (30 dias); autenticação do cliente por `client_secret` |
| Proteção do recurso | Middleware que recusa qualquer chamada a `/mcp` sem bearer válido e devolve `WWW-Authenticate` conforme o padrão |
| Transporte | FastMCP Streamable HTTP (stateless) montado no FastAPI, com allowlists de host e origem e headers de segurança |
| Boot fail-closed | O serviço não sobe se algum segredo faltar ou tiver entropia abaixo do mínimo (client secret e JWT secret ≥ 256 bits) |
| Segredos | Variáveis de ambiente, ou o cofre Unix `pass` (GPG) com `MCP_GATEWAY_USE_PASS=1` |
| Ferramentas MCP | `ping_server`: smoke test autenticado com status e uptime do host |

**Ainda não implementado (roadmap):** ferramentas de execução de comandos com guardrails determinísticos, log de auditoria append-only e armazenamento persistente de códigos e tokens (hoje ficam em memória; reiniciar invalida as sessões).

## Testes

12 testes automatizados rodam no CI com segredos efêmeros gerados a cada execução:

- metadados de descoberta e recusa sem autenticação;
- fluxo OAuth 2.0 + PKCE completo seguido de `tools/list` e `tools/call` via MCP;
- regressões adversariais: boot fail-closed com segredos fracos, JWT forjado, tentativas de burlar o PKCE (`plain` ou vazio), adulteração de `redirect_uri`, força bruta e bloqueio do PIN, reuso de refresh token, escape de XSS e headers de segurança na tela de consentimento, documentação da API desativada, preflight CORS e `Bearer` sem diferenciar maiúsculas (RFC 6750).

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
python -m pytest -q
```

## Como executar

```bash
# 1. Segredos (escolha um caminho)
export MCP_OAUTH_CLIENT_ID=...  MCP_OAUTH_CLIENT_SECRET=...  MCP_OAUTH_JWT_SECRET=...  MCP_OAUTH_MASTER_PIN=...
#    ou guarde no pass e habilite:
python3 scripts/setup_oauth_secrets.py && export MCP_GATEWAY_USE_PASS=1

# 2. Domínio público servido pelo túnel / proxy reverso
export MCP_GATEWAY_DOMAIN=mcp.seu-dominio.com

# 3. Subir (escuta só em 127.0.0.1)
scripts/run_gateway.sh

# 4. Expor, por exemplo com Cloudflare Tunnel
cloudflared tunnel route dns <TUNNEL_ID> mcp.seu-dominio.com
```

Variáveis: `MCP_GATEWAY_DOMAIN`, `MCP_GATEWAY_PORT` (padrão 8950), `MCP_GATEWAY_USE_PASS`, `MCP_GATEWAY_PASS_PREFIX` (padrão `mcp-gateway`) e os quatro segredos `MCP_OAUTH_*`.

## Princípios

- **Falhar fechado:** material de identidade ausente ou fraco impede a subida; token inválido nunca chega ao MCP.
- **Superfície pequena:** só descoberta, authorize, token e `/mcp`; documentação interativa da API desligada.
- **Sem segredos em URL ou código:** credenciais ficam no ambiente ou num cofre cifrado.
- **Segurança mapeada ao NIST CSF 2.0** (Proteger: identidade e controle de acesso; Detectar: falhas de autenticação e bloqueios).

## Stack

Python 3.12, FastAPI, MCP Python SDK (FastMCP, Streamable HTTP), PyJWT, Pydantic Settings, pytest.

## Autor e licença

Rafael Henrique Leal Barili ([@Rlealbarili](https://github.com/Rlealbarili)). Licença [Apache 2.0](LICENSE).
