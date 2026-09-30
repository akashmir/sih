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
| PQ Crypto | ML-KEM-768, ML-DSA-65 (via liboqs / classical fallback) |
| Symmetric | AES-256-GCM |
| Watermark | Zero-width chars (text), LSB steganography (images), PDF annotations |
| Ledger | SHA-256 hash chain, SQLite |
| Frontend | React + Vite |

## Supported Formats
- Plain text (`.txt`, `.md`, `.csv`)
- PDF documents (`.pdf`)
- Images (`.png`, `.jpg`)

## Security Properties
- ✅ Client-held private keys (server never stores them)
- ✅ Non-repudiation via digital signatures
- ✅ Tamper-evident ledger (any edit breaks hash chain)
- ✅ Fully offline / air-gapped (no network dependencies)
- ✅ 3x repetition coding for watermark resilience

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
