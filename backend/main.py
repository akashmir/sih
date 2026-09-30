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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup shared resources."""
    data_dir = os.path.join(os.path.dirname(__file__), 'data')
    os.makedirs(data_dir, exist_ok=True)

    ledger = HashChainLedger(os.path.join(data_dir, 'ledger.db'))
    identity = IdentityManager(os.path.join(data_dir, 'identity.db'))
    init_services(ledger, identity)

    yield

    ledger.close()
    identity.close()


app = FastAPI(
    title="NISHAN",
    description=(
        "Cryptographic Attribution & Immutable Decryption Provenance "
        "for Multi-Recipient Encrypted Document Distribution"
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
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
