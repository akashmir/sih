"""
NISHAN — FastAPI Application Entry Point
Cryptographic Attribution & Immutable Decryption Provenance
Ministry of Defence — Indian Navy (WESEE)
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .api.routes import router, init_services
from .ledger.blockchain import HashChainLedger
from .identity.manager import IdentityManager
from .documents.store import DocumentStore


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup shared resources."""
    data_dir = os.environ.get("NISHAN_DATA_DIR") or os.path.join(
        os.path.dirname(__file__), 'data'
    )
    os.makedirs(data_dir, exist_ok=True)

    ledger = HashChainLedger(os.path.join(data_dir, 'ledger.db'))
    identity = IdentityManager(os.path.join(data_dir, 'identity.db'))
    documents = DocumentStore(os.path.join(data_dir, 'documents.db'))
    init_services(ledger, identity, documents)

    yield

    ledger.close()
    identity.close()
    documents.close()


app = FastAPI(
    title="NISHAN",
    description=(
        "Cryptographic Attribution & Immutable Decryption Provenance "
        "for Multi-Recipient Encrypted Document Distribution"
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — only the frontend dev server by default (the Vite proxy makes
# its requests same-origin anyway). Override with a comma-separated list.
_cors_origins = [
    o.strip()
    for o in os.environ.get(
        "NISHAN_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    ).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[
        "X-Watermark-Id", "X-Block-Index", "X-Block-Hash",
        "X-Signed-With", "X-User-Id", "X-KEM-Algorithm",
        "X-SIG-Algorithm", "Content-Disposition",
    ],
)

# Mount API routes
app.include_router(router)


# Health check
@app.get("/")
async def root():
    return {
        "name": "NISHAN",
        "status": "operational",
        "organization": "Ministry of Defence — Indian Navy (WESEE)",
        "docs": "/docs",
    }
