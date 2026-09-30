import { useState, useEffect, useCallback } from 'react'
import './index.css'

const API = ''  // Same origin: Vite proxy in dev, the backend itself in the desktop app

// ─── API helpers ────────────────────────────────────────────────────
async function api(path, opts = {}) {
  const res = await fetch(`${API}${path}`, opts)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Request failed')
  }
  return res.json()
}

// POST a form and return the raw response, throwing the server's error detail
async function postForm(path, form) {
  const res = await fetch(`${API}${path}`, { method: 'POST', body: form })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Request failed')
  }
  return res
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

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

const shortAlg = alg => alg?.replace(/\s*\(classical fallback\)/, '') ?? '…'
const shortHash = (h, n = 16) => (h ? `${h.substring(0, n)}…` : '—')
const formatTime = ts => new Date(ts * 1000).toLocaleString('en-IN')

const SUPPORTED = '.txt .md .csv .json .xml .html .log .pdf .png .jpg .bmp'

// ─── Shared UI ──────────────────────────────────────────────────────
function PageHeader({ title, subtitle, children }) {
  return (
    <div className="page-header">
      <div>
        <h2>{title}</h2>
        <p>{subtitle}</p>
      </div>
      {children && <div className="page-actions">{children}</div>}
    </div>
  )
}

function Row({ label, children, mono = true }) {
  return (
    <div className="result-row">
      <span className="label">{label}</span>
      <span className={mono ? 'value' : 'value plain'}>{children}</span>
    </div>
  )
}

function Status({ status }) {
  if (!status) return null
  const cls = { success: 'success', error: 'danger', loading: '', warning: 'warning' }[status.type]
  const icon = { success: '✅', error: '❌', loading: '⏳', warning: '⚠️' }[status.type]
  return (
    <div className={`result-box ${cls}`} role={status.type === 'error' ? 'alert' : 'status'}>
      <h4>{icon} {status.msg}</h4>
      {status.children}
    </div>
  )
}

function FilePicker({ file, onChange, icon, prompt, hint, accept }) {
  return (
    <label className={`file-input-wrapper ${file ? 'has-file' : ''}`}>
      <input type="file" accept={accept} onChange={e => onChange(e.target.files[0] || null)} />
      <div className="icon">{file ? '📄' : icon}</div>
      <div className="label">{file ? file.name : prompt}</div>
      {hint && <div className="sublabel">{hint}</div>}
    </label>
  )
}

// ─── Dashboard ──────────────────────────────────────────────────────
function Dashboard() {
  const [info, setInfo] = useState(null)
  const [chain, setChain] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    api('/api/system/info').then(setInfo).catch(e => setError(e.message))
    api('/api/ledger/verify').then(setChain).catch(() => {})
  }, [])

  const pq = info?.crypto?.post_quantum

  return (
    <div className="animate-in">
      <PageHeader title="Dashboard" subtitle="System overview and health status" />

      {error && (
        <div className="alert alert-danger" role="alert">
          <span>⚠️</span>
          <span>Cannot reach the NISHAN backend ({error}). Make sure it is running.</span>
        </div>
      )}

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">🔐</div>
          <div className="stat-value small">{shortAlg(info?.crypto?.kem_algorithm)}</div>
          <div className="stat-label">Key Encapsulation</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">✍️</div>
          <div className="stat-value small">{shortAlg(info?.crypto?.sig_algorithm)}</div>
          <div className="stat-label">Digital Signatures</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">{chain ? (chain.valid ? '✅' : '❌') : '⛓️'}</div>
          <div className={`stat-value ${chain && !chain.valid ? 'bad' : ''}`}>
            {chain ? (chain.valid ? 'Valid' : 'Tampered') : '…'}
          </div>
          <div className="stat-label">Chain Integrity</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">👥</div>
          <div className="stat-value">{info?.registered_users ?? '…'}</div>
          <div className="stat-label">Registered Users</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">📄</div>
          <div className="stat-value">{info?.documents_encrypted ?? '…'}</div>
          <div className="stat-label">Documents Encrypted</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">📦</div>
          <div className="stat-value">{info?.chain_length ?? '…'}</div>
          <div className="stat-label">Ledger Blocks</div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header"><span className="card-title">Cryptographic Backend</span></div>
          {info && (
            <div className={`alert ${pq ? 'alert-success' : 'alert-warning'}`}>
              <span>{pq ? '🛡️' : 'ℹ️'}</span>
              <span>
                {pq
                  ? 'Post-quantum algorithms active (NIST FIPS 203 / 204).'
                  : 'Classical fallback active (X25519 / Ed25519) — not quantum-safe. Install liboqs-python to enable ML-KEM / ML-DSA.'}
              </span>
            </div>
          )}
          {info?.crypto && Object.entries(info.crypto).map(([k, v]) => (
            <Row key={k} label={k.replace(/_/g, ' ')}>{String(v)}</Row>
          ))}
        </div>
        <div className="card">
          <div className="card-header"><span className="card-title">System</span></div>
          {info && (
            <>
              <Row label="Project">{info.project}</Row>
              <Row label="Version">{info.version}</Row>
              <Row label="Organization" mono={false}>{info.organization}</Row>
              <Row label="Chain checked">{chain ? `${chain.blocks_checked} blocks` : '…'}</Row>
            </>
          )}
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

  const validId = /^[A-Za-z0-9_.-]{1,64}$/.test(userId)

  const register = async e => {
    e.preventDefault()
    try {
      setStatus({ type: 'loading', msg: 'Generating keypairs…' })
      const form = new FormData()
      form.append('user_id', userId)
      form.append('display_name', name)
      const res = await postForm('/api/users/register', form)
      const filename = dispositionFilename(res.headers.get('Content-Disposition'), `${userId}_private_keys.key`)
      downloadBlob(await res.blob(), filename)
      setStatus({
        type: 'success',
        msg: `Registered ${name}`,
        children: (
          <p className="hint">
            Private key saved as <strong>{filename}</strong>. This is the only copy — store it securely;
            it is needed to decrypt documents.
          </p>
        ),
      })
      setUserId('')
      setName('')
      loadUsers()
    } catch (err) {
      setStatus({ type: 'error', msg: err.message })
    }
  }

  return (
    <div className="animate-in">
      <PageHeader
        title="Register Recipients"
        subtitle="Generate recipient keypairs. The private key is saved to your computer; the server keeps only public keys."
      />

      <div className="grid-2">
        <form className="card" onSubmit={register}>
          <div className="card-header"><span className="card-title">New Recipient</span></div>
          <div className="form-group">
            <label htmlFor="reg-id">User ID</label>
            <input id="reg-id" className="form-input" placeholder="e.g. admiral_kumar" value={userId}
              onChange={e => setUserId(e.target.value)} aria-invalid={userId !== '' && !validId} />
            <div className={`field-hint ${userId && !validId ? 'error' : ''}`}>
              Letters, digits, <code>_</code> <code>.</code> <code>-</code> — up to 64 characters
            </div>
          </div>
          <div className="form-group">
            <label htmlFor="reg-name">Display Name</label>
            <input id="reg-name" className="form-input" placeholder="e.g. Admiral R. Kumar" value={name}
              onChange={e => setName(e.target.value)} />
          </div>
          <button type="submit" className="btn btn-primary"
            disabled={!validId || !name.trim() || status?.type === 'loading'}>
            🔑 Generate Keys & Register
          </button>
          <Status status={status} />
        </form>
        <div className="card">
          <div className="card-header">
            <span className="card-title">Registered Recipients</span>
            <span className="count">{users.length}</span>
          </div>
          {users.length === 0 ? (
            <div className="empty-state"><div className="icon">👤</div><p>No users registered yet</p></div>
          ) : (
            <div className="scroll-list">
              {users.map(u => (
                <Row key={u.user_id} label={u.display_name}>{u.user_id}</Row>
              ))}
            </div>
          )}
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
  const [status, setStatus] = useState(null)

  useEffect(() => { api('/api/users').then(setUsers).catch(() => {}) }, [])

  const toggle = id => setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id])
  const allSelected = users.length > 0 && selected.length === users.length

  const encrypt = async () => {
    setStatus({ type: 'loading', msg: 'Encrypting…' })
    try {
      const form = new FormData()
      form.append('document', file)
      form.append('recipients', selected.join(','))
      const res = await (await postForm('/api/documents/encrypt', form)).json()
      setStatus({
        type: 'success',
        msg: res.message,
        children: (
          <>
            <Row label="Document ID">{res.doc_id}</Row>
            <Row label="Filename">{res.filename}</Row>
            <Row label="SHA-256">{shortHash(res.doc_hash, 24)}</Row>
            <Row label="Recipients">{res.recipients.join(', ')}</Row>
          </>
        ),
      })
      setFile(null)
      setSelected([])
    } catch (e) {
      setStatus({ type: 'error', msg: e.message })
    }
  }

  return (
    <div className="animate-in">
      <PageHeader title="Distribute Document" subtitle="Encrypt a document once for multiple recipients" />

      <div className="card">
        <div className="form-group">
          <label>Document</label>
          <FilePicker file={file} onChange={setFile} icon="📁"
            prompt="Click to select a document" hint={`Supported: ${SUPPORTED}`} />
        </div>

        <div className="form-group">
          <div className="label-row">
            <label>Recipients {selected.length > 0 && <span className="count">{selected.length}</span>}</label>
            {users.length > 0 && (
              <button type="button" className="link-btn"
                onClick={() => setSelected(allSelected ? [] : users.map(u => u.user_id))}>
                {allSelected ? 'Clear all' : 'Select all'}
              </button>
            )}
          </div>
          {users.length === 0 ? (
            <div className="alert alert-warning"><span>⚠️</span><span>No registered users. Register recipients first.</span></div>
          ) : (
            <div className="chip-list">
              {users.map(u => (
                <button type="button" key={u.user_id} title={u.user_id}
                  className={`chip ${selected.includes(u.user_id) ? 'selected' : ''}`}
                  aria-pressed={selected.includes(u.user_id)} onClick={() => toggle(u.user_id)}>
                  {u.display_name}
                </button>
              ))}
            </div>
          )}
        </div>

        <button className="btn btn-primary" onClick={encrypt}
          disabled={!file || selected.length === 0 || status?.type === 'loading'}>
          {status?.type === 'loading' ? '⏳ Encrypting…' : '🔐 Encrypt & Distribute'}
        </button>

        <Status status={status} />
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
  const [status, setStatus] = useState(null)

  useEffect(() => { api('/api/documents').then(setDocs).catch(() => {}) }, [])

  const doc = docs.find(d => d.doc_id === docId)

  const decrypt = async () => {
    setStatus({ type: 'loading', msg: 'Decrypting & watermarking…' })
    try {
      const form = new FormData()
      form.append('doc_id', docId)
      form.append('user_id', userId)
      form.append('key_file', keyFile)
      const res = await postForm('/api/documents/decrypt', form)
      const filename = dispositionFilename(res.headers.get('Content-Disposition'), 'decrypted_document')
      downloadBlob(await res.blob(), filename)
      setStatus({
        type: 'success',
        msg: `Saved ${filename}`,
        children: (
          <>
            <Row label="Watermark ID">{res.headers.get('X-Watermark-Id')}</Row>
            <Row label="Ledger block">#{res.headers.get('X-Block-Index')}</Row>
            <Row label="Block hash">{shortHash(res.headers.get('X-Block-Hash'), 24)}</Row>
            <Row label="Signed with">{res.headers.get('X-Signed-With')}</Row>
          </>
        ),
      })
    } catch (e) {
      setStatus({ type: 'error', msg: e.message })
    }
  }

  return (
    <div className="animate-in">
      <PageHeader title="Decrypt Document"
        subtitle="Decrypt your copy — a unique, invisible forensic watermark is embedded and the event is logged" />

      <div className="alert alert-info">
        <span>🔒</span>
        <span>Every decryption is signed with your key and recorded in the audit ledger. Your copy carries a watermark that identifies you.</span>
      </div>

      <div className="card">
        <div className="grid-2 tight">
          <div className="form-group">
            <label htmlFor="dec-doc">Document</label>
            <select id="dec-doc" className="form-select" value={docId}
              onChange={e => { setDocId(e.target.value); setUserId('') }}>
              <option value="">Select a document…</option>
              {docs.map(d => (
                <option key={d.doc_id} value={d.doc_id}>{d.filename} ({d.doc_id})</option>
              ))}
            </select>
          </div>

          <div className="form-group">
            <label htmlFor="dec-user">Recipient</label>
            <select id="dec-user" className="form-select" value={userId} disabled={!doc}
              onChange={e => setUserId(e.target.value)}>
              <option value="">{doc ? 'Select your user ID…' : 'Select a document first'}</option>
              {doc?.recipients.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>
        </div>

        <div className="form-group">
          <label>Private Key File (.key)</label>
          <FilePicker file={keyFile} onChange={setKeyFile} icon="🔑" accept=".key"
            prompt="Select your .key file" hint="The private key file saved when you registered" />
        </div>

        <button className="btn btn-primary" onClick={decrypt}
          disabled={!docId || !userId || !keyFile || status?.type === 'loading'}>
          {status?.type === 'loading' ? '⏳ Decrypting…' : '🔓 Decrypt Document'}
        </button>

        <Status status={status} />
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
    setLoading(true)
    setResult(null)
    try {
      const form = new FormData()
      form.append('document', file)
      setResult(await (await postForm('/api/forensics/investigate', form)).json())
    } catch (e) {
      setResult({ error: e.message })
    }
    setLoading(false)
  }

  const attr = result?.attribution
  const proof = result?.ledger_proof
  const trusted = attr?.signature_verified && attr?.watermark_consistent

  return (
    <div className="animate-in">
      <PageHeader title="Forensic Investigation"
        subtitle="Upload a leaked copy to extract its watermark and identify the responsible recipient" />

      <div className="card">
        <div className="form-group">
          <label>Suspected Leaked Document</label>
          <FilePicker file={file} onChange={f => { setFile(f); setResult(null) }} icon="🕵️"
            prompt="Select the leaked document" />
        </div>

        <button className="btn btn-danger" onClick={investigate} disabled={!file || loading}>
          {loading ? '⏳ Analyzing…' : '🔍 Investigate Document'}
        </button>

        {result?.error && <Status status={{ type: 'error', msg: result.error }} />}

        {result && !result.error && !result.ledger_match && (
          <Status status={{
            type: 'warning',
            msg: result.message,
            children: result.watermark_id && <Row label="Watermark ID">{result.watermark_id}</Row>,
          }} />
        )}

        {result?.ledger_match && (
          <div className={`result-box ${trusted ? 'success' : 'danger'}`}>
            <h4>🎯 Attribution {trusted ? 'Established' : 'Found — Verification Failed'}</h4>
            <div className={`alert ${trusted ? 'alert-success' : 'alert-danger'}`}>
              <span>{trusted ? '✅' : '⚠️'}</span>
              <span>{result.message}</span>
            </div>

            <div className="grid-2 tight">
              <div>
                <h5>Recipient</h5>
                <Row label="Name" mono={false}>{attr.recipient_name}</Row>
                <Row label="User ID">{attr.recipient_id}</Row>
                <Row label="Decrypted at" mono={false}>{formatTime(attr.decryption_timestamp)}</Row>
                <Row label="Document ID">{attr.doc_id}</Row>
                <Row label="Document hash">{shortHash(attr.document_hash, 24)}</Row>
              </div>
              <div>
                <h5>Evidence</h5>
                <Row label="Watermark ID">{result.watermark_id}</Row>
                <Row label="Signature" mono={false}>
                  {attr.signature_verified
                    ? <span className="badge-valid">✓ Verified</span>
                    : <span className="badge-invalid">✗ Unverified</span>}
                </Row>
                <Row label="Watermark ↔ Ledger" mono={false}>
                  {attr.watermark_consistent
                    ? <span className="badge-valid">✓ Consistent</span>
                    : <span className="badge-invalid">✗ Mismatch</span>}
                </Row>
                <Row label="Algorithm">{attr.signature_algorithm}</Row>
                <Row label="Ledger block">#{proof.block_index}</Row>
                <Row label="Block hash">{shortHash(proof.block_hash, 24)}</Row>
                <Row label="Previous hash">{shortHash(proof.prev_hash, 24)}</Row>
              </div>
            </div>
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
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => (
    Promise.all([api('/api/ledger/blocks'), api('/api/ledger/verify')])
      .then(([d, v]) => {
        setBlocks(d.blocks)
        setTotal(d.total)
        setValidation(v)
      })
      .catch(() => { /* leave previous data */ })
      .finally(() => setLoading(false))
  ), [])

  useEffect(() => { load() }, [load])

  return (
    <div className="animate-in">
      <PageHeader title="Audit Ledger"
        subtitle="Tamper-evident hash chain — every decryption event is recorded">
        <button className="btn btn-secondary" onClick={() => { setLoading(true); load() }} disabled={loading}>
          {loading ? '⏳' : '↻'} Refresh & Verify
        </button>
      </PageHeader>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">📦</div>
          <div className="stat-value">{total}</div>
          <div className="stat-label">Total Blocks</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">{validation ? (validation.valid ? '✅' : '❌') : '⛓️'}</div>
          <div className={`stat-value ${validation && !validation.valid ? 'bad' : ''}`}>
            {validation ? (validation.valid ? 'Intact' : `${validation.errors?.length} errors`) : '…'}
          </div>
          <div className="stat-label">Chain Integrity</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🔗</div>
          <div className="stat-value">SHA-256</div>
          <div className="stat-label">Hash Algorithm</div>
        </div>
      </div>

      {validation && !validation.valid && (
        <div className="alert alert-danger" role="alert">
          <span>❌</span>
          <span>
            Tampering detected in block{validation.errors.length > 1 ? 's' : ''}{' '}
            {[...new Set(validation.errors.map(e => `#${e.block_index}`))].join(', ')}.
          </span>
        </div>
      )}

      <div className="card flush">
        <div className="card-header padded">
          <span className="card-title">Decryption Events</span>
          {total > blocks.length && <span className="hint">Showing latest {blocks.length} of {total}</span>}
        </div>

        {blocks.length === 0 ? (
          <div className="empty-state"><div className="icon">⛓️</div><p>No blocks yet. Decrypt a document to create the first block.</p></div>
        ) : (
          <div className="table-wrap">
            <table className="ledger-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Timestamp</th>
                  <th>Recipient</th>
                  <th>Document</th>
                  <th>Watermark ID</th>
                  <th>Block Hash</th>
                  <th>Prev Hash</th>
                </tr>
              </thead>
              <tbody>
                {blocks.map(b => (
                  <tr key={b.block_index}>
                    <td>{b.block_index}</td>
                    <td className="nowrap">{formatTime(b.timestamp)}</td>
                    <td>{b.recipient_id}</td>
                    <td className="mono">{b.doc_id || '—'}</td>
                    <td className="mono" title={b.watermark_id}>{shortHash(b.watermark_id, 12)}</td>
                    <td className="mono" title={b.block_hash}>{shortHash(b.block_hash)}</td>
                    <td className="mono" title={b.prev_hash}>{shortHash(b.prev_hash)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── App shell ──────────────────────────────────────────────────────
const PAGES = [
  { id: 'dashboard', label: 'Dashboard', icon: '📊', component: Dashboard, section: 'Operations' },
  { id: 'register', label: 'Register Users', icon: '👤', component: Register, section: 'Operations' },
  { id: 'distribute', label: 'Distribute', icon: '📤', component: Distribute, section: 'Operations' },
  { id: 'decrypt', label: 'Decrypt', icon: '🔓', component: Decrypt, section: 'Operations' },
  { id: 'investigate', label: 'Investigate', icon: '🔍', component: Investigate, section: 'Forensics' },
  { id: 'ledger', label: 'Audit Ledger', icon: '⛓️', component: LedgerExplorer, section: 'Forensics' },
]

const ZOOM_STEPS = [0.9, 1, 1.1, 1.25]

function loadPref(key, fallback) {
  try {
    const v = localStorage.getItem(`nishan.${key}`)
    return v === null ? fallback : JSON.parse(v)
  } catch { return fallback }
}

function savePref(key, value) {
  try { localStorage.setItem(`nishan.${key}`, JSON.stringify(value)) } catch { /* ignore */ }
}

export default function App() {
  const [page, setPage] = useState('dashboard')
  const [zoomIdx, setZoomIdx] = useState(() => loadPref('zoom', 1))
  const [highContrast, setHighContrast] = useState(() => loadPref('contrast', false))

  useEffect(() => { savePref('zoom', zoomIdx) }, [zoomIdx])
  useEffect(() => { savePref('contrast', highContrast) }, [highContrast])

  const current = PAGES.find(p => p.id === page) || PAGES[0]
  const CurrentPage = current.component
  const sections = [...new Set(PAGES.map(p => p.section))]

  return (
    <div className="app" data-contrast={highContrast ? 'high' : undefined}>
      <header className="classification-bar">
        <span className="left">🔒 Secure Document Distribution System</span>
        <span className="banner-classification">RESTRICTED</span>
        <span className="right">Ministry of Defence · Indian Navy (WESEE)</span>
      </header>
      <div className="tricolor-bar" />

      <div className="app-content">
        <aside className="sidebar">
          <div className="sidebar-logo">
            <div className="logo-icon">N</div>
            <div>
              <h1>NISHAN</h1>
              <div className="badge">DOCUMENT SECURITY</div>
            </div>
          </div>

          <nav aria-label="Main">
            {sections.map(section => (
              <div key={section}>
                <div className="nav-section">{section}</div>
                <ul className="nav-items">
                  {PAGES.filter(p => p.section === section).map(p => (
                    <li key={p.id}>
                      <button type="button" className={`nav-item ${page === p.id ? 'active' : ''}`}
                        aria-current={page === p.id ? 'page' : undefined} onClick={() => setPage(p.id)}>
                        <span className="icon">{p.icon}</span> {p.label}
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </nav>

          <div className="sidebar-footer">
            <div className="a11y-controls" role="group" aria-label="Display settings">
              <button type="button" title="Smaller text" aria-label="Smaller text"
                disabled={zoomIdx === 0} onClick={() => setZoomIdx(i => i - 1)}>A−</button>
              <button type="button" title="Reset text size" aria-label="Reset text size"
                onClick={() => setZoomIdx(1)}>A</button>
              <button type="button" title="Larger text" aria-label="Larger text"
                disabled={zoomIdx === ZOOM_STEPS.length - 1} onClick={() => setZoomIdx(i => i + 1)}>A+</button>
              <button type="button" title="High contrast" aria-label="High contrast"
                aria-pressed={highContrast} className={highContrast ? 'on' : ''}
                onClick={() => setHighContrast(c => !c)}>◐</button>
            </div>
            <div className="org">
              <div>Cryptographic Attribution &amp;</div>
              <div>Immutable Decryption Provenance</div>
            </div>
          </div>
        </aside>

        <main className="main">
          <div className="main-inner" style={{ zoom: ZOOM_STEPS[zoomIdx] ?? 1 }}>
            <CurrentPage key={current.id} />
          </div>
        </main>
      </div>
    </div>
  )
}
