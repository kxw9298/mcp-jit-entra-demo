"""ASGI entry point: `uvicorn app.main:app`."""

import logging
import os

from .server import build

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = build().app
