import { useState, useEffect, useCallback } from 'react'
import './index.css'

const API = ''  // Vite proxy handles /api

// ─── API helpers ────────────────────────────────────────────────────
async function api(path, opts = {}) {
  const res = await fetch(`${API}${path}`, opts)
  if (!res.ok && !opts.raw) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Request failed')
  }
  return opts.raw ? res : res.json()
}

// Filename from a Content-Disposition header, preferring the RFC 5987 form
function dispositionFilename(header, fallback) {
  if (!header) return fallback
  const star = header.match(/filename\*=UTF-8''([^;]+)/i)
  if (star) {
    try { return decodeURIComponent(star[1]) } catch { /* fall through */ }
  }
  const plain = header.match(/filename="?([^";]+)"?/i)
  return plain ? plain[1] : fallback
}

// ─── Dashboard ──────────────────────────────────────────────────────
function Dashboard() {
  const [info, setInfo] = useState(null)
  const [chain, setChain] = useState(null)

  useEffect(() => {
    api('/api/system/info').then(setInfo).catch(() => {})
    api('/api/ledger/verify').then(setChain).catch(() => {})
  }, [])

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Dashboard</h2>
        <p>System overview and health status for NISHAN</p>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">🔐</div>
          <div className="stat-value">{info?.crypto?.kem_algorithm || '...'}</div>
          <div className="stat-label">Key Encapsulation</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">✍️</div>
          <div className="stat-value">{info?.crypto?.sig_algorithm || '...'}</div>
          <div className="stat-label">Digital Signatures</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">👥</div>
          <div className="stat-value">{info?.registered_users ?? '...'}</div>
          <div className="stat-label">Registered Users</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">📄</div>
          <div className="stat-value">{info?.documents_encrypted ?? '...'}</div>
          <div className="stat-label">Documents Encrypted</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">⛓️</div>
          <div className="stat-value">{info?.chain_length ?? '...'}</div>
          <div className="stat-label">Chain Length</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">{chain?.valid ? '✅' : '❌'}</div>
          <div className="stat-value">{chain ? (chain.valid ? 'Valid' : 'Tampered') : '...'}</div>
          <div className="stat-label">Chain Integrity</div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header"><span className="card-title">System Info</span></div>
          {info && Object.entries(info).filter(([k]) => k !== 'crypto').map(([k, v]) => (
            <div className="result-row" key={k}>
              <span className="label">{k}</span>
              <span className="value">{String(v)}</span>
            </div>
          ))}
        </div>
        <div className="card">
          <div className="card-header"><span className="card-title">Cryptographic Backend</span></div>
          <div className="alert alert-info">
            <span>ℹ️</span>
            <span>{info?.crypto?.post_quantum ? 'Post-quantum algorithms active (NIST-standardized)' : 'Classical fallback active — install liboqs for PQ'}</span>
          </div>
          {info?.crypto && Object.entries(info.crypto).map(([k, v]) => (
            <div className="result-row" key={k}>
              <span className="label">{k}</span>
              <span className="value">{String(v)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Register ───────────────────────────────────────────────────────
function Register() {
  const [userId, setUserId] = useState('')
  const [name, setName] = useState('')
  const [status, setStatus] = useState(null)
  const [users, setUsers] = useState([])

  const loadUsers = useCallback(() => {
    api('/api/users').then(setUsers).catch(() => {})
  }, [])

  useEffect(() => { loadUsers() }, [loadUsers])

  const register = async () => {
    try {
      setStatus({ type: 'loading', msg: 'Generating keypairs...' })
      const form = new FormData()
      form.append('user_id', userId)
      form.append('display_name', name)
      const res = await fetch('/api/users/register', { method: 'POST', body: form })
      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.detail)
      }
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${userId}_private_keys.key`
      a.click()
      URL.revokeObjectURL(url)
      setStatus({ type: 'success', msg: `Registered! Private key downloaded as ${userId}_private_keys.key` })
      setUserId('')
      setName('')
      loadUsers()
    } catch (e) {
      setStatus({ type: 'error', msg: e.message })
    }
  }

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Register Recipients</h2>
        <p>Generate post-quantum keypairs. Private keys are downloaded — server retains only public keys.</p>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header"><span className="card-title">New User</span></div>
          <div className="form-group">
            <label>User ID</label>
            <input className="form-input" placeholder="e.g. admiral_kumar" value={userId} onChange={e => setUserId(e.target.value)} />
          </div>
          <div className="form-group">
            <label>Display Name</label>
            <input className="form-input" placeholder="e.g. Admiral R. Kumar" value={name} onChange={e => setName(e.target.value)} />
          </div>
          <button className="btn btn-primary" onClick={register} disabled={!userId || !name}>
            🔑 Generate Keys & Register
          </button>
          {status && (
            <div className={`result-box ${status.type === 'success' ? 'success' : status.type === 'error' ? 'danger' : ''}`} style={{ marginTop: 16 }}>
              <h4>{status.type === 'loading' ? '⏳' : status.type === 'success' ? '✅' : '❌'} {status.msg}</h4>
            </div>
          )}
        </div>
        <div className="card">
          <div className="card-header"><span className="card-title">Registered Users ({users.length})</span></div>
          {users.length === 0 ? (
            <div className="empty-state"><div className="icon">👤</div><p>No users registered yet</p></div>
          ) : users.map(u => (
            <div className="result-row" key={u.user_id}>
              <span className="label">{u.display_name}</span>
              <span className="value">{u.user_id}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Distribute ─────────────────────────────────────────────────────
function Distribute() {
  const [file, setFile] = useState(null)
  const [users, setUsers] = useState([])
  const [selected, setSelected] = useState([])
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => { api('/api/users').then(setUsers).catch(() => {}) }, [])

  const toggle = id => setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id])

  const encrypt = async () => {
    if (!file || selected.length === 0) return
    setLoading(true)
    try {
      const form = new FormData()
      form.append('document', file)
      form.append('recipients', selected.join(','))
      const res = await api('/api/documents/encrypt', { method: 'POST', body: form })
      setResult(res)
    } catch (e) {
      setResult({ error: e.message })
    }
    setLoading(false)
  }

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Distribute Document</h2>
        <p>Encrypt a document and prepare it for multi-recipient distribution</p>
      </div>

      <div className="card">
        <div className="form-group">
          <label>Document</label>
          <div className="file-input-wrapper">
            <input type="file" onChange={e => setFile(e.target.files[0])} />
            <div className="icon">📁</div>
            <div className="label">{file ? file.name : 'Click to select a document'}</div>
            <div className="sublabel">Supported: .txt, .md, .csv, .json, .xml, .html, .log, .pdf, .png, .jpg, .bmp</div>
          </div>
        </div>

        <div className="form-group">
          <label>Select Recipients</label>
          {users.length === 0 ? (
            <div className="alert alert-warning"><span>⚠️</span><span>No registered users. Register recipients first.</span></div>
          ) : (
            <div className="chip-list">
              {users.map(u => (
                <div key={u.user_id} className={`chip ${selected.includes(u.user_id) ? 'selected' : ''}`} onClick={() => toggle(u.user_id)}>
                  {u.display_name}
                </div>
              ))}
            </div>
          )}
        </div>

        <button className="btn btn-primary" onClick={encrypt} disabled={!file || selected.length === 0 || loading}>
          {loading ? '⏳ Encrypting...' : '🔐 Encrypt & Distribute'}
        </button>

        {result && !result.error && (
          <div className="result-box success">
            <h4>✅ Document encrypted successfully</h4>
            <div className="result-row"><span className="label">Document ID</span><span className="value">{result.doc_id}</span></div>
            <div className="result-row"><span className="label">Filename</span><span className="value">{result.filename}</span></div>
            <div className="result-row"><span className="label">Hash (SHA-256)</span><span className="value">{result.doc_hash?.substring(0, 24)}...</span></div>
            <div className="result-row"><span className="label">Recipients</span><span className="value">{result.recipients?.join(', ')}</span></div>
          </div>
        )}
        {result?.error && (
          <div className="result-box danger"><h4>❌ {result.error}</h4></div>
        )}
      </div>
    </div>
  )
}

// ─── Decrypt ────────────────────────────────────────────────────────
function Decrypt() {
  const [docs, setDocs] = useState([])
  const [docId, setDocId] = useState('')
  const [userId, setUserId] = useState('')
  const [keyFile, setKeyFile] = useState(null)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => { api('/api/documents').then(setDocs).catch(() => {}) }, [])

  const decrypt = async () => {
    setLoading(true)
    try {
      const form = new FormData()
      form.append('doc_id', docId)
      form.append('user_id', userId)
      form.append('key_file', keyFile)
      const res = await fetch('/api/documents/decrypt', { method: 'POST', body: form })
      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.detail)
      }
      const blob = await res.blob()
      const wmId = res.headers.get('X-Watermark-Id')
      const blockHash = res.headers.get('X-Block-Hash')
      const blockIndex = res.headers.get('X-Block-Index')
      const signedWith = res.headers.get('X-Signed-With')

      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = dispositionFilename(res.headers.get('Content-Disposition'), 'decrypted_document')
      a.click()
      URL.revokeObjectURL(url)

      setResult({ success: true, wmId, blockHash, blockIndex, signedWith })
    } catch (e) {
      setResult({ error: e.message })
    }
    setLoading(false)
  }

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Decrypt Document</h2>
        <p>Decrypt your copy — a unique forensic watermark will be embedded silently</p>
      </div>

      <div className="alert alert-info">
        <span>🔒</span>
        <span>Upload your private key file (.key) to decrypt. A unique invisible watermark tied to your identity will be embedded in the decrypted copy.</span>
      </div>

      <div className="card">
        <div className="form-group">
          <label>Document ID</label>
          <select className="form-select" value={docId} onChange={e => setDocId(e.target.value)}>
            <option value="">Select a document...</option>
            {docs.map(d => (
              <option key={d.doc_id} value={d.doc_id}>{d.filename} ({d.doc_id})</option>
            ))}
          </select>
        </div>

        <div className="form-group">
          <label>Your User ID</label>
          <input className="form-input" placeholder="e.g. admiral_kumar" value={userId} onChange={e => setUserId(e.target.value)} />
        </div>

        <div className="form-group">
          <label>Private Key File (.key)</label>
          <div className="file-input-wrapper">
            <input type="file" accept=".key" onChange={e => setKeyFile(e.target.files[0])} />
            <div className="icon">🔑</div>
            <div className="label">{keyFile ? keyFile.name : 'Upload your .key file'}</div>
            <div className="sublabel">The private key bundle you downloaded at registration</div>
          </div>
        </div>

        <button className="btn btn-primary" onClick={decrypt} disabled={!docId || !userId || !keyFile || loading}>
          {loading ? '⏳ Decrypting & Watermarking...' : '🔓 Decrypt Document'}
        </button>

        {result?.success && (
          <div className="result-box success">
            <h4>✅ Document decrypted & watermarked</h4>
            <div className="result-row"><span className="label">Watermark ID</span><span className="value">{result.wmId}</span></div>
            <div className="result-row"><span className="label">Block Index</span><span className="value">#{result.blockIndex}</span></div>
            <div className="result-row"><span className="label">Block Hash</span><span className="value">{result.blockHash?.substring(0, 24)}...</span></div>
            <div className="result-row"><span className="label">Signed With</span><span className="value">{result.signedWith}</span></div>
          </div>
        )}
        {result?.error && (
          <div className="result-box danger"><h4>❌ {result.error}</h4></div>
        )}
      </div>
    </div>
  )
}

// ─── Investigate ────────────────────────────────────────────────────
function Investigate() {
  const [file, setFile] = useState(null)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const investigate = async () => {
    if (!file) return
    setLoading(true)
    try {
      const form = new FormData()
      form.append('document', file)
      const res = await api('/api/forensics/investigate', { method: 'POST', body: form })
      setResult(res)
    } catch (e) {
      setResult({ found: false, message: e.message })
    }
    setLoading(false)
  }

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>🔍 Forensic Investigation</h2>
        <p>Upload a leaked document to extract its watermark and identify the responsible recipient</p>
      </div>

      <div className="card">
        <div className="form-group">
          <label>Leaked Document</label>
          <div className="file-input-wrapper">
            <input type="file" onChange={e => setFile(e.target.files[0])} />
            <div className="icon">🕵️</div>
            <div className="label">{file ? file.name : 'Upload the suspected leaked document'}</div>
          </div>
        </div>

        <button className="btn btn-danger" onClick={investigate} disabled={!file || loading}>
          {loading ? '⏳ Analyzing...' : '🔍 Investigate Document'}
        </button>

        {result && !result.found && (
          <div className="result-box warning">
            <h4>⚠️ {result.message}</h4>
          </div>
        )}

        {result?.found && result?.ledger_match && (
          <div className="result-box success">
            <h4>🎯 Attribution Found</h4>
            <div className="alert alert-success" style={{ margin: '12px 0' }}>
              <span>✅</span>
              <span>{result.message}</span>
            </div>

            <h4 style={{ marginTop: 20 }}>Extracted Watermark</h4>
            <div className="result-row"><span className="label">Watermark ID</span><span className="value">{result.watermark_id}</span></div>

            <h4 style={{ marginTop: 20 }}>Attribution Details</h4>
            <div className="result-row"><span className="label">Recipient ID</span><span className="value">{result.attribution.recipient_id}</span></div>
            <div className="result-row"><span className="label">Recipient Name</span><span className="value">{result.attribution.recipient_name}</span></div>
            <div className="result-row"><span className="label">Decryption Time</span><span className="value">{new Date(result.attribution.decryption_timestamp * 1000).toLocaleString()}</span></div>
            <div className="result-row"><span className="label">Document Hash</span><span className="value">{result.attribution.document_hash?.substring(0, 32)}...</span></div>
            <div className="result-row"><span className="label">Signature Algo</span><span className="value">{result.attribution.signature_algorithm}</span></div>
            <div className="result-row">
              <span className="label">Signature Status</span>
              <span>{result.attribution.signature_verified ? <span className="badge-valid">✓ Verified</span> : <span className="badge-invalid">✗ Unverified</span>}</span>
            </div>
            <div className="result-row">
              <span className="label">Watermark ↔ Ledger</span>
              <span>{result.attribution.watermark_consistent ? <span className="badge-valid">✓ Consistent</span> : <span className="badge-invalid">✗ Mismatch</span>}</span>
            </div>

            <h4 style={{ marginTop: 20 }}>Ledger Proof</h4>
            <div className="result-row"><span className="label">Block Index</span><span className="value">#{result.ledger_proof.block_index}</span></div>
            <div className="result-row"><span className="label">Block Hash</span><span className="value">{result.ledger_proof.block_hash?.substring(0, 32)}...</span></div>
            <div className="result-row"><span className="label">Previous Hash</span><span className="value">{result.ledger_proof.prev_hash?.substring(0, 32)}...</span></div>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Ledger Explorer ────────────────────────────────────────────────
function LedgerExplorer() {
  const [blocks, setBlocks] = useState([])
  const [total, setTotal] = useState(0)
  const [validation, setValidation] = useState(null)

  useEffect(() => {
    api('/api/ledger/blocks').then(d => { setBlocks(d.blocks); setTotal(d.total) }).catch(() => {})
    api('/api/ledger/verify').then(setValidation).catch(() => {})
  }, [])

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>⛓️ Audit Ledger Explorer</h2>
        <p>Browse the tamper-evident hash chain — every decryption event is recorded</p>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">📦</div>
          <div className="stat-value">{total}</div>
          <div className="stat-label">Total Blocks</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">{validation?.valid ? '✅' : '❌'}</div>
          <div className="stat-value">{validation ? (validation.valid ? 'Intact' : `${validation.errors?.length} Tampered`) : '...'}</div>
          <div className="stat-label">Chain Integrity</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🔗</div>
          <div className="stat-value">SHA-256</div>
          <div className="stat-label">Hash Algorithm</div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <span className="card-title">Decryption Events</span>
          {validation?.valid && <span className="badge-valid">✓ Chain Valid</span>}
        </div>

        {blocks.length === 0 ? (
          <div className="empty-state"><div className="icon">⛓️</div><p>No blocks in the chain yet. Decrypt a document to create the first block.</p></div>
        ) : (
          <table className="ledger-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Timestamp</th>
                <th>Recipient</th>
                <th>Watermark ID</th>
                <th>Block Hash</th>
                <th>Prev Hash</th>
              </tr>
            </thead>
            <tbody>
              {blocks.map(b => (
                <tr key={b.block_index}>
                  <td>{b.block_index}</td>
                  <td>{new Date(b.timestamp * 1000).toLocaleString()}</td>
                  <td>{b.recipient_id}</td>
                  <td className="mono">{b.watermark_id?.substring(0, 12)}...</td>
                  <td className="mono">{b.block_hash?.substring(0, 16)}...</td>
                  <td className="mono">{b.prev_hash?.substring(0, 16)}...</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

// ─── App ────────────────────────────────────────────────────────────
const PAGES = [
  { id: 'dashboard', label: 'Dashboard', icon: '📊', component: Dashboard },
  { id: 'register', label: 'Register Users', icon: '👤', component: Register },
  { id: 'distribute', label: 'Distribute', icon: '📤', component: Distribute },
  { id: 'decrypt', label: 'Decrypt', icon: '🔓', component: Decrypt },
  { id: 'investigate', label: 'Investigate', icon: '🔍', component: Investigate },
  { id: 'ledger', label: 'Audit Ledger', icon: '⛓️', component: LedgerExplorer },
]

export default function App() {
  const [page, setPage] = useState('dashboard')
  const CurrentPage = PAGES.find(p => p.id === page)?.component || Dashboard

  return (
    <div className="app">
      <div className="gov-header">
        <div className="left">
          <span>🇮🇳</span>
          <span>Government of India | Ministry of Defence</span>
        </div>
        <div className="right">
          <span>English</span>
          <span>|</span>
          <span>हिन्दी</span>
        </div>
      </div>
      <div className="tricolor-bar"></div>
      <div className="system-banner">
        <span className="banner-icon">🔒</span>
        <span>SECURE DOCUMENT DISTRIBUTION SYSTEM</span>
        <span className="banner-classification">RESTRICTED</span>
      </div>
      <div className="emblem-bar">
        <div className="emblem">☸</div>
        <div className="emblem-text">
          <span className="emblem-title">NISHAN</span>
          <span className="emblem-subtitle">Cryptographic Attribution & Immutable Decryption Provenance</span>
        </div>
        <div className="emblem-text right">
          <span className="emblem-title">Ministry of Defence</span>
          <span className="emblem-subtitle">Indian Navy — WESEE</span>
        </div>
      </div>
      <div className="breadcrumb-bar">
        <span>Home</span>
        <span> / </span>
        <span>Secure Document Distribution</span>
        <span> / </span>
        <span className="current">NISHAN Portal</span>
      </div>
      <div className="last-updated">
        <span>Last Updated: </span>
        <span>{new Date().toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' })}</span>
      </div>
      <div className="accessibility-bar">
        <button className="accessibility-btn" title="Decrease font size">A-</button>
        <button className="accessibility-btn" title="Reset font size">A</button>
        <button className="accessibility-btn" title="Increase font size">A+</button>
        <span className="accessibility-separator">|</span>
        <button className="accessibility-btn" title="High contrast">◐</button>
        <button className="accessibility-btn" title="Screen reader">🔊</button>
      </div>
      <div className="tricolor-bar"></div>
      <div className="app-content">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-icon">N</div>
          <div>
            <h1>NISHAN</h1>
            <div className="badge">DOCUMENT SECURITY</div>
          </div>
        </div>

        <div className="nav-section">Operations</div>
        <ul className="nav-items">
          {PAGES.slice(0, 4).map(p => (
            <li key={p.id} className={`nav-item ${page === p.id ? 'active' : ''}`} onClick={() => setPage(p.id)}>
              <span className="icon">{p.icon}</span> {p.label}
            </li>
          ))}
        </ul>

        <div className="nav-section">Forensics</div>
        <ul className="nav-items">
          {PAGES.slice(4).map(p => (
            <li key={p.id} className={`nav-item ${page === p.id ? 'active' : ''}`} onClick={() => setPage(p.id)}>
              <span className="icon">{p.icon}</span> {p.label}
            </li>
          ))}
        </ul>

        <div style={{ marginTop: 'auto', padding: '16px 12px', borderTop: '1px solid rgba(255,255,255,0.1)' }}>
          <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.5)' }}>Ministry of Defence</div>
          <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.5)' }}>Government of India</div>
        </div>
      </aside>

      <main className="main">
        <CurrentPage />
        <footer className="gov-footer">
          <p>NISHAN — Cryptographic Attribution & Immutable Decryption Provenance</p>
          <p>Ministry of Defence — Indian Navy (WESEE) | Government of India</p>
        </footer>
      </main>
      </div>
    </div>
  )
}
