#!/usr/bin/env bash
# Executa o gateway a partir da raiz do projeto (venv em .venv).
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"
exec "$PROJECT_DIR/.venv/bin/python" -m uvicorn backend.main:app --host 127.0.0.1 --port "${MCP_GATEWAY_PORT:-8950}" --workers 1
