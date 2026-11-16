"""
Ponto de entrada principal do Secure MCP Gateway (FastAPI + Streamable HTTP).
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.auth.oauth import oauth_router
from backend.config import settings
from backend.mcp_server import mcp
from backend.middleware.auth import MCPAuthMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("secure-mcp-gateway")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gerencia o ciclo de vida do session manager do FastMCP e valida postura fail-closed."""
    logger.info("🚀 Inicializando Secure MCP Gateway na porta %s...", settings.port)
    logger.info("🌐 Domínio público: %s", settings.base_url)

    # B1: Validação mandatória Fail-Closed no boot
    settings.validate_fail_closed()
    logger.info("🔒 Postura de Identidade Fail-Closed validada com sucesso.")

    async with mcp.session_manager.run():
        logger.info("⚡ FastMCP Streamable HTTP session manager ativo.")
        yield
    logger.info("🛑 Encerrando FastMCP Streamable HTTP session manager.")


app = FastAPI(
    title="Secure MCP Gateway",
    description="Gateway seguro MCP Streamable HTTP com autenticação OAuth 2.0 PKCE para o Google Gemini Web",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

# CORS para clientes web autorizados (sem wildcard perigoso)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://gemini.google.com",
        "https://ai.google.dev",
        settings.base_url,
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Middleware de Autenticação Bearer para rotas /mcp
app.add_middleware(MCPAuthMiddleware)

# Rotas de Descoberta e Autorização OAuth 2.0
app.include_router(oauth_router)


@app.get("/", tags=["Status"])
async def root():
    return {
        "gateway": "secure-mcp-gateway",
        "status": "online",
        "domain": settings.domain,
        "mcp_endpoint": f"{settings.base_url}/mcp",
        "oauth_discovery": f"{settings.base_url}/.well-known/oauth-authorization-server",
        "docs": "https://modelcontextprotocol.io",
    }


@app.get("/health", tags=["Status"])
async def health():
    return {"status": "healthy", "service": "secure-mcp-gateway"}


# Montar aplicação Streamable HTTP do FastMCP na raiz (ela atende /mcp)
mcp_subapp = mcp.streamable_http_app()
app.mount("/", mcp_subapp)


def main():
    uvicorn.run(
        "backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
