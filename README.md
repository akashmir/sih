# NISHAN — Cryptographic Attribution & Immutable Decryption Provenance

> Ministry of Defence — Indian Navy (WESEE)

## About

NISHAN is a cryptographic attribution and immutable decryption provenance system designed for secure document distribution. It solves the critical problem of tracing leaked documents back to their source by:

- **Invisible forensic watermarking** at decryption time (unique per recipient + session)
- **Post-quantum digital signatures** binding decryption events to recipient identity
- **Offline hash chain ledger** for tamper-evident audit trails

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              React Frontend (Vite)                  │
│  Dashboard │ Register │ Distribute │ Decrypt        │
│  Investigate │ Ledger Explorer                      │
└──────────────────┬──────────────────────────────────┘
                   │ REST API (localhost)
┌──────────────────▼──────────────────────────────────┐
│               FastAPI Backend                       │
│  ┌────────────┐  ┌───────────┐  ┌────────────────┐ │
│  │ Identity   │  │ Crypto    │  │ Watermark      │ │
│  │ Manager    │  │ Engine    │  │ Engine         │ │
│  │ (pub keys) │  │ ML-KEM    │  │ Encoder        │ │
│  │            │  │ ML-DSA    │  │ Embedder       │ │
│  │            │  │ AES-GCM   │  │ Extractor      │ │
│  └────────────┘  └───────────┘  └────────────────┘ │
│  ┌──────────────────────────────────────────────┐   │
│  │  Hash Chain Ledger (SQLite, offline)          │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+

### Backend
```bash
cd backend
pip install -r requirements.txt
cd ..
python -m uvicorn backend.main:app --reload --port 8000
```

By default this runs with **classical** crypto (X25519 + Ed25519). For post-quantum
ML-KEM-768 / ML-DSA-65, install the native [liboqs](https://github.com/open-quantum-safe/liboqs)
library and `pip install liboqs-python`. The Dashboard shows which backend is active.
Key files are tied to the backend they were generated with, so re-register users after switching.

Configuration (environment variables):

| Variable | Default | Purpose |
|----------|---------|---------|
| `NISHAN_DATA_DIR` | `backend/data` | Where the SQLite databases live |
| `NISHAN_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Allowed browser origins |

### Tests
```bash
python -m pytest backend/tests
```
Tests use throwaway databases and never touch `backend/data`.

### Frontend
```bash
cd frontend_app
npm install
npm run dev
```

Open http://localhost:5173

## Workflow

1. **Register** — Generate PQ keypairs. Private keys downloaded as `.key` files. Server stores only public keys.
2. **Distribute** — Upload document, select recipients. Document encrypted with AES-256-GCM, key wrapped per-recipient via ML-KEM.
3. **Decrypt** — Recipient uploads `.key` file. Document decrypted, unique invisible watermark embedded, decryption signed and logged to ledger.
4. **Investigate** — Upload leaked doc. System extracts watermark, matches to ledger, verifies signature, identifies the responsible party.
5. **Verify** — Browse the hash chain ledger. Validate chain integrity.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.11 + FastAPI |
| PQ Crypto | ML-KEM-768, ML-DSA-65 via liboqs-python (optional; X25519/Ed25519 fallback) |
| Symmetric | AES-256-GCM |
| Watermark | Zero-width chars (text), LSB steganography (images), PDF metadata + annotation + invisible text layer |
| Ledger | SHA-256 hash chain, SQLite |
| Storage | Encrypted documents persisted in SQLite |
| Frontend | React + Vite |

## Supported Formats
- UTF-8 text (`.txt`, `.md`, `.csv`, `.json`, `.xml`, `.html`, `.log`)
- PDF documents (`.pdf`) — watermark on every page
- Images (`.png`, `.jpg`, `.jpeg`, `.bmp`) — watermarked copies are always delivered as PNG

Other formats (e.g. `.docx`, `.xlsx`) are rejected at upload, since they can't be watermarked without corrupting them.

## Security Properties
- ✅ Server never *stores* private keys — they're returned once as a `.key` file
- ✅ Tamper-evident ledger (any edit breaks hash chain); each block binds the recipient, document and watermark
- ✅ Watermarks carry a checksum and are cross-checked against the ledger during investigation
- ✅ Fully offline / air-gapped (no network dependencies)
- ✅ 3x repetition coding for watermark resilience

### Known limitations
- **Private keys pass through the server.** Keys are generated server-side at registration, and the `.key` file is uploaded to decrypt. The server therefore performs the signing, which weakens non-repudiation. Moving key generation and decryption into the client is the proper fix.
- **No authentication.** Anyone who can reach the API can register users and list documents; decryption requires the recipient's `.key` file, which is stored unencrypted.
- **Ledger can be rewritten by a DB admin.** The chain detects edits, but someone with write access can recompute every hash. Anchoring the latest block hash externally (e.g. printed or signed) closes this.
- **Watermarks are fragile.** Stripping zero-width characters removes text watermarks; re-saving an image as JPEG, or cropping it, destroys the LSB watermark.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/users/register` | Register recipient, download `.key` bundle |
| GET | `/api/users` | List registered users |
| POST | `/api/documents/encrypt` | Encrypt for multi-recipient |
| POST | `/api/documents/decrypt` | Decrypt + watermark + sign + ledger |
| POST | `/api/forensics/investigate` | Extract watermark, attribute leak |
| GET | `/api/ledger/blocks` | Browse audit chain |
| GET | `/api/ledger/verify` | Validate chain integrity |
| GET | `/api/system/info` | System & crypto info |

## License
Government of India — Ministry of Defence
