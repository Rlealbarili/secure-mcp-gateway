"""
FastMCP Streamable HTTP Server com as ferramentas do gateway.
"""

from __future__ import annotations

import os
import platform
import socket
import time
from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP

from backend.config import settings

mcp = FastMCP("secure-mcp-gateway", stateless_http=True)

# Configurar segurança de transporte do FastMCP
mcp.settings.transport_security.allowed_hosts = [
    settings.domain,
    f"{settings.domain}:*",
    "127.0.0.1",
    "127.0.0.1:*",
    "localhost",
    "localhost:*",
    "testserver",
    "testserver:*",
]
mcp.settings.transport_security.allowed_origins = [
    "https://gemini.google.com",
    "https://*.google.com",
]


def _get_system_uptime() -> str:
    """Calcula o uptime do servidor a partir de /proc/uptime."""
    try:
        with open("/proc/uptime", "r") as f:
            uptime_seconds = float(f.readline().split()[0])
            hours = int(uptime_seconds // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
    except Exception:
        return "desconhecido"


@mcp.tool()
def ping_server() -> dict:
    """
    Retorna o status de conexão, latência, hostname, uptime e telemetria básica
    do servidor protegido. Utilizada como Smoke Test para validar a autenticação OAuth 2.0.
    """
    now = datetime.now(timezone.utc).isoformat()
    return {
        "status": "operational",
        "gateway": "secure-mcp-gateway",
        "node": socket.gethostname(),
        "platform": f"{platform.system()} {platform.release()}",
        "uptime": _get_system_uptime(),
        "timestamp_utc": now,
        "auth_method": "OAuth 2.0 (RFC 6749 + PKCE) + JWT Bearer",
        "domain": settings.domain,
        "message": "Gateway MCP conectado e autenticado com sucesso (servidor protegido).",
    }
