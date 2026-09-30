import { useState, useEffect, useCallback } from 'react'
import './index.css'

const API = ''  // Same origin: Vite proxy in dev, the backend itself in the desktop app

// ─── API helpers ────────────────────────────────────────────────────
async function readError(res) {
  const err = await res.json().catch(() => ({ detail: res.statusText }))
  return new Error(friendlyError(err.detail || 'Request failed'))
}

async function api(path) {
  const res = await fetch(`${API}${path}`)
  if (!res.ok) throw await readError(res)
  return res.json()
}

async function postForm(path, form) {
  const res = await fetch(`${API}${path}`, { method: 'POST', body: form })
  if (!res.ok) throw await readError(res)
  return res
}

// Translate server messages into plain language
function friendlyError(msg) {
  const rules = [
    [/Failed to fetch|NetworkError/i, 'Can’t connect to the NISHAN service. Make sure it is running.'],
    [/Invalid key file/i, 'That file isn’t a valid access key.'],
    [/Key file does not match/i, 'This access key belongs to a different person.'],
    [/Key file was generated for/i, 'This access key was created with an older version of NISHAN. Please add the recipient again.'],
    [/decapsulation failed|Decryption failed/i, 'This access key can’t open this document.'],
    [/not an authorized recipient/i, 'You are not one of the recipients of this document.'],
    [/Document not found/i, 'This document is no longer available.'],
    [/already exists/i, 'Someone with this username already exists.'],
    [/User ID must be/i, 'Usernames can only use letters, numbers, dots, dashes and underscores.'],
    [/Unsupported file type/i, 'This file type isn’t supported. Use a text, PDF or image file.'],
    [/must be UTF-8/i, 'This text file uses an unsupported character encoding. Save it as UTF-8 and try again.'],
    [/Image too small/i, 'This image is too small to be protected. Use a larger image.'],
    [/not a readable (image|PDF)|PDF has no pages/i, 'This file appears to be damaged or empty.'],
    [/Recipient '.*' not found/i, 'One of the selected recipients no longer exists.'],
  ]
  const hit = rules.find(([re]) => re.test(msg))
  return hit ? hit[1] : msg
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

const formatTime = ts => new Date(ts * 1000).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' })

// Lookup tables so screens can show names instead of IDs
function useDirectory() {
  const [users, setUsers] = useState([])
  const [docs, setDocs] = useState([])
  const [loaded, setLoaded] = useState(false)
  const reload = useCallback(() => Promise.all([
    api('/api/users').then(setUsers).catch(() => {}),
    api('/api/documents').then(setDocs).catch(() => {}),
  ]).finally(() => setLoaded(true)), [])
  useEffect(() => { reload() }, [reload])

  const userName = id => users.find(u => u.user_id === id)?.display_name || id
  const docName = id => docs.find(d => d.doc_id === id)?.filename
  return { users, docs, loaded, userName, docName, reload }
}

// ─── Shared UI ──────────────────────────────────────────────────────
function PageHeader({ title, subtitle, children }) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {children && <div className="page-actions">{children}</div>}
    </header>
  )
}

function Notice({ tone = 'info', title, children }) {
  return (
    <div className={`notice notice-${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
      {title && <strong>{title}</strong>}
      {children && <div>{children}</div>}
    </div>
  )
}

function FilePicker({ id, file, onChange, prompt, hint, accept }) {
  return (
    <label htmlFor={id} className={`file-drop ${file ? 'has-file' : ''}`}>
      <input id={id} type="file" accept={accept} onChange={e => onChange(e.target.files[0] || null)} />
      <span className="file-drop-button">{file ? 'Change file' : 'Choose file'}</span>
      <span className="file-drop-name">{file ? file.name : prompt}</span>
      {hint && !file && <span className="file-drop-hint">{hint}</span>}
    </label>
  )
}

function Field({ label, htmlFor, hint, error, children }) {
  return (
    <div className="field">
      <label className="field-label" htmlFor={htmlFor}>{label}</label>
      {children}
      {(error || hint) && <div className={`field-hint ${error ? 'error' : ''}`}>{error || hint}</div>}
    </div>
  )
}

function Empty({ children }) {
  return <div className="empty">{children}</div>
}

// ─── Overview ───────────────────────────────────────────────────────
function Overview({ onNavigate }) {
  const [info, setInfo] = useState(null)
  const [chain, setChain] = useState(null)
  const [recent, setRecent] = useState(null)
  const [error, setError] = useState(null)
  const { userName, docName } = useDirectory()

  useEffect(() => {
    api('/api/system/info').then(setInfo).catch(e => setError(e.message))
    api('/api/ledger/verify').then(setChain).catch(() => {})
    api('/api/ledger/blocks?limit=6').then(d => setRecent(d.blocks)).catch(() => setRecent([]))
  }, [])

  return (
    <>
      <PageHeader title="Overview" subtitle="A summary of your documents and recent activity." />

      {error && <Notice tone="error" title="Can’t connect to the NISHAN service">Make sure it is running, then reopen this page.</Notice>}

      <div className="stats">
        <div className="stat">
          <div className="stat-label">Recipients</div>
          <div className="stat-value">{info?.registered_users ?? '–'}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Documents shared</div>
          <div className="stat-value">{info?.documents_encrypted ?? '–'}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Times opened</div>
          <div className="stat-value">{info?.chain_length ?? '–'}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Activity log</div>
          <div className={`stat-value status ${chain ? (chain.valid ? 'ok' : 'bad') : ''}`}>
            {chain ? (chain.valid ? 'Verified' : 'Needs attention') : '–'}
          </div>
        </div>
      </div>

      <div className="columns">
        <section className="panel">
          <div className="panel-header">
            <h2>Recent activity</h2>
            <button type="button" className="link" onClick={() => onNavigate('ledger')}>View all</button>
          </div>
          {recent === null ? (
            <Empty>Loading…</Empty>
          ) : recent.length === 0 ? (
            <Empty>No documents have been opened yet.</Empty>
          ) : (
            <ul className="activity">
              {recent.map(b => (
                <li key={b.block_index}>
                  <div>
                    <strong>{userName(b.recipient_id)}</strong> opened{' '}
                    <strong>{docName(b.doc_id) || 'a document'}</strong>
                  </div>
                  <time>{formatTime(b.timestamp)}</time>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="panel">
          <div className="panel-header"><h2>Get started</h2></div>
          <div className="actions">
            <button type="button" className="action" onClick={() => onNavigate('recipients')}>
              <strong>Add a recipient</strong>
              <span>Create an access key for a new person.</span>
            </button>
            <button type="button" className="action" onClick={() => onNavigate('share')}>
              <strong>Share a document</strong>
              <span>Protect a file so only chosen recipients can open it.</span>
            </button>
            <button type="button" className="action" onClick={() => onNavigate('trace')}>
              <strong>Trace a leaked copy</strong>
              <span>Find out whose copy of a document was leaked.</span>
            </button>
          </div>
        </section>
      </div>
    </>
  )
}

// ─── Recipients ─────────────────────────────────────────────────────
function Recipients() {
  const [userId, setUserId] = useState('')
  const [name, setName] = useState('')
  const [status, setStatus] = useState(null)
  const [busy, setBusy] = useState(false)
  const { users, loaded, reload } = useDirectory()

  const validId = /^[A-Za-z0-9_.-]{1,64}$/.test(userId)

  const register = async e => {
    e.preventDefault()
    setBusy(true)
    setStatus(null)
    try {
      const form = new FormData()
      form.append('user_id', userId)
      form.append('display_name', name.trim())
      const res = await postForm('/api/users/register', form)
      const filename = dispositionFilename(res.headers.get('Content-Disposition'), `${userId}_private_keys.key`)
      downloadBlob(await res.blob(), filename)
      setStatus({
        tone: 'success',
        title: `${name.trim()} has been added`,
        body: <>Their access key was saved as <strong>{filename}</strong>. Give it to them securely — it is the only copy and cannot be recovered.</>,
      })
      setUserId('')
      setName('')
      reload()
    } catch (err) {
      setStatus({ tone: 'error', title: 'Could not add recipient', body: err.message })
    }
    setBusy(false)
  }

  return (
    <>
      <PageHeader title="Recipients" subtitle="People who can receive protected documents." />

      <div className="columns">
        <form className="panel" onSubmit={register}>
          <div className="panel-header"><h2>Add a recipient</h2></div>
          <Field label="Full name" htmlFor="reg-name">
            <input id="reg-name" className="input" placeholder="e.g. Cdr. A. Mehta" value={name}
              onChange={e => setName(e.target.value)} />
          </Field>
          <Field label="Username" htmlFor="reg-id"
            hint="Letters, numbers, dots, dashes and underscores."
            error={userId && !validId ? 'Usernames can only use letters, numbers, dots, dashes and underscores.' : null}>
            <input id="reg-id" className="input" placeholder="e.g. a.mehta" value={userId}
              onChange={e => setUserId(e.target.value)} aria-invalid={userId !== '' && !validId} />
          </Field>
          <p className="muted small form-note">
            An access key file will be saved to this computer. The recipient needs it to open documents.
          </p>
          <button type="submit" className="btn btn-primary" disabled={!validId || !name.trim() || busy}>
            {busy ? 'Adding…' : 'Add recipient'}
          </button>
          {status && <Notice tone={status.tone} title={status.title}>{status.body}</Notice>}
        </form>

        <section className="panel">
          <div className="panel-header">
            <h2>All recipients</h2>
            <span className="muted small">{users.length}</span>
          </div>
          {!loaded ? (
            <Empty>Loading…</Empty>
          ) : users.length === 0 ? (
            <Empty>No recipients yet.</Empty>
          ) : (
            <ul className="people">
              {users.map(u => (
                <li key={u.user_id}>
                  <span className="avatar" aria-hidden="true">{u.display_name.trim().charAt(0).toUpperCase()}</span>
                  <span className="person">
                    <strong>{u.display_name}</strong>
                    <span className="muted small">{u.user_id}</span>
                  </span>
                  <span className="muted small">Added {new Date(u.registered_at * 1000).toLocaleDateString('en-IN', { dateStyle: 'medium' })}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </>
  )
}

// ─── Share Document ─────────────────────────────────────────────────
function ShareDocument() {
  const [file, setFile] = useState(null)
  const [selected, setSelected] = useState([])
  const [status, setStatus] = useState(null)
  const [busy, setBusy] = useState(false)
  const { users, loaded, userName } = useDirectory()

  const toggle = id => setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id])
  const allSelected = users.length > 0 && selected.length === users.length

  const share = async () => {
    setBusy(true)
    setStatus(null)
    try {
      const form = new FormData()
      form.append('document', file)
      form.append('recipients', selected.join(','))
      const res = await (await postForm('/api/documents/encrypt', form)).json()
      setStatus({
        tone: 'success',
        title: `${res.filename} is ready`,
        body: `It can now be opened by ${res.recipients.map(userName).join(', ')}.`,
      })
      setFile(null)
      setSelected([])
    } catch (e) {
      setStatus({ tone: 'error', title: 'Could not share document', body: e.message })
    }
    setBusy(false)
  }

  return (
    <>
      <PageHeader title="Share Document"
        subtitle="Protect a file so only the people you choose can open it. Each person receives a personally marked copy." />

      <section className="panel narrow">
        <Field label="Document">
          <FilePicker id="share-file" file={file} onChange={setFile} prompt="No file selected"
            hint="Text, PDF and image files (PNG, JPG, BMP)" />
        </Field>

        <div className="field">
          <div className="field-label-row">
            <span className="field-label">Recipients{selected.length > 0 && ` (${selected.length} selected)`}</span>
            {users.length > 0 && (
              <button type="button" className="link"
                onClick={() => setSelected(allSelected ? [] : users.map(u => u.user_id))}>
                {allSelected ? 'Clear selection' : 'Select all'}
              </button>
            )}
          </div>
          {!loaded ? (
            <div className="muted">Loading…</div>
          ) : users.length === 0 ? (
            <Notice tone="warning">Add recipients before sharing a document.</Notice>
          ) : (
            <div className="checklist">
              {users.map(u => (
                <label key={u.user_id} className={`check ${selected.includes(u.user_id) ? 'on' : ''}`}>
                  <input type="checkbox" checked={selected.includes(u.user_id)} onChange={() => toggle(u.user_id)} />
                  <span>{u.display_name}</span>
                  <span className="muted small">{u.user_id}</span>
                </label>
              ))}
            </div>
          )}
        </div>

        <button className="btn btn-primary" onClick={share} disabled={!file || selected.length === 0 || busy}>
          {busy ? 'Sharing…' : 'Share document'}
        </button>

        {status && <Notice tone={status.tone} title={status.title}>{status.body}</Notice>}
      </section>
    </>
  )
}

// ─── Open Document ──────────────────────────────────────────────────
function OpenDocument() {
  const [docId, setDocId] = useState('')
  const [userId, setUserId] = useState('')
  const [keyFile, setKeyFile] = useState(null)
  const [status, setStatus] = useState(null)
  const [busy, setBusy] = useState(false)
  const { docs, userName } = useDirectory()

  const doc = docs.find(d => d.doc_id === docId)

  const open = async () => {
    setBusy(true)
    setStatus(null)
    try {
      const form = new FormData()
      form.append('doc_id', docId)
      form.append('user_id', userId)
      form.append('key_file', keyFile)
      const res = await postForm('/api/documents/decrypt', form)
      const filename = dispositionFilename(res.headers.get('Content-Disposition'), 'document')
      downloadBlob(await res.blob(), filename)
      setStatus({
        tone: 'success',
        title: 'Your copy has been saved',
        body: <>Saved as <strong>{filename}</strong>. This copy is personally marked to you, and the access has been recorded.</>,
      })
    } catch (e) {
      setStatus({ tone: 'error', title: 'Could not open document', body: e.message })
    }
    setBusy(false)
  }

  return (
    <>
      <PageHeader title="Open Document"
        subtitle="Open a document that was shared with you, using your access key." />

      <section className="panel narrow">
        <Field label="Document" htmlFor="open-doc">
          <select id="open-doc" className="input" value={docId}
            onChange={e => { setDocId(e.target.value); setUserId('') }}>
            <option value="">Select a document</option>
            {docs.map(d => <option key={d.doc_id} value={d.doc_id}>{d.filename}</option>)}
          </select>
        </Field>

        <Field label="Your name" htmlFor="open-user">
          <select id="open-user" className="input" value={userId} disabled={!doc}
            onChange={e => setUserId(e.target.value)}>
            <option value="">{doc ? 'Select your name' : 'Select a document first'}</option>
            {doc?.recipients.map(r => <option key={r} value={r}>{userName(r)}</option>)}
          </select>
        </Field>

        <Field label="Access key">
          <FilePicker id="open-key" file={keyFile} onChange={setKeyFile} accept=".key"
            prompt="No file selected" hint="The .key file you received when you were added" />
        </Field>

        <button className="btn btn-primary" onClick={open} disabled={!docId || !userId || !keyFile || busy}>
          {busy ? 'Opening…' : 'Open document'}
        </button>

        {status && <Notice tone={status.tone} title={status.title}>{status.body}</Notice>}
      </section>
    </>
  )
}

// ─── Trace Leak ─────────────────────────────────────────────────────
function Check({ ok, good, bad, detail }) {
  return (
    <li className={`check-item ${ok ? 'ok' : 'bad'}`}>
      <span className="dot" aria-hidden="true" />
      <div>
        <strong>{ok ? good : bad}</strong>
        <span className="muted small">{detail}</span>
      </div>
    </li>
  )
}

function TraceLeak() {
  const [file, setFile] = useState(null)
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const { docName } = useDirectory()

  const trace = async () => {
    setBusy(true)
    setResult(null)
    try {
      const form = new FormData()
      form.append('document', file)
      setResult(await (await postForm('/api/forensics/investigate', form)).json())
    } catch (e) {
      setResult({ error: e.message })
    }
    setBusy(false)
  }

  const attr = result?.attribution
  const proof = result?.ledger_proof
  const confirmed = attr?.signature_verified && attr?.watermark_consistent

  return (
    <>
      <PageHeader title="Trace Leak"
        subtitle="Upload a leaked copy of a document to find out whose copy it was." />

      <section className="panel narrow">
        <Field label="Leaked file">
          <FilePicker id="trace-file" file={file} onChange={f => { setFile(f); setResult(null) }}
            prompt="No file selected" />
        </Field>

        <button className="btn btn-primary" onClick={trace} disabled={!file || busy}>
          {busy ? 'Checking…' : 'Trace this file'}
        </button>

        {result?.error && <Notice tone="error" title="Could not check this file">{result.error}</Notice>}

        {result && !result.error && !result.found && (
          <Notice tone="warning" title="No tracking mark found">
            This file may not have been shared through NISHAN, or its tracking mark was removed.
          </Notice>
        )}

        {result?.found && !result.ledger_match && (
          <Notice tone="warning" title="No matching record">
            This file carries a NISHAN tracking mark, but no matching access record was found on this system.
          </Notice>
        )}
      </section>

      {result?.ledger_match && (
        <section className={`panel narrow verdict ${confirmed ? 'ok' : 'bad'}`}>
          <div className="verdict-label">{confirmed ? 'Traced to' : 'Possible match'}</div>
          <div className="verdict-name">{attr.recipient_name}</div>
          <p>
            This copy of <strong>{docName(attr.doc_id) || 'the document'}</strong> was opened
            by {attr.recipient_name} ({attr.recipient_id}) on {formatTime(attr.decryption_timestamp)}.
          </p>

          <ul className="checks">
            <Check ok={attr.signature_verified}
              good="Identity confirmed" bad="Identity could not be confirmed"
              detail="The access record is signed with this recipient’s own access key." />
            <Check ok={attr.watermark_consistent}
              good="Record matches the file" bad="Record does not match the file"
              detail="The tracking mark in the file agrees with the stored access record." />
          </ul>

          <details className="technical">
            <summary>Technical details (for investigators)</summary>
            <dl>
              <dt>Tracking ID</dt><dd>{result.watermark_id}</dd>
              <dt>Document ID</dt><dd>{attr.doc_id}</dd>
              <dt>Document fingerprint</dt><dd>{attr.document_hash}</dd>
              <dt>Access record</dt><dd>#{proof.block_index}</dd>
              <dt>Record fingerprint</dt><dd>{proof.block_hash}</dd>
              <dt>Previous record</dt><dd>{proof.prev_hash}</dd>
              <dt>Signature method</dt><dd>{attr.signature_algorithm}</dd>
            </dl>
          </details>
        </section>
      )}
    </>
  )
}

// ─── Activity Log ───────────────────────────────────────────────────
function ActivityLog() {
  const [blocks, setBlocks] = useState(null)
  const [total, setTotal] = useState(0)
  const [validation, setValidation] = useState(null)
  const [busy, setBusy] = useState(true)
  const { userName, docName } = useDirectory()

  const load = useCallback(() => (
    Promise.all([api('/api/ledger/blocks'), api('/api/ledger/verify')])
      .then(([d, v]) => {
        setBlocks(d.blocks)
        setTotal(d.total)
        setValidation(v)
      })
      .catch(() => setBlocks(b => b ?? []))
      .finally(() => setBusy(false))
  ), [])

  useEffect(() => { load() }, [load])

  const altered = validation && !validation.valid
    ? [...new Set(validation.errors.map(e => `#${e.block_index}`))].join(', ')
    : ''

  return (
    <>
      <PageHeader title="Activity Log"
        subtitle="Every time a document is opened, it is permanently recorded here.">
        <button className="btn btn-secondary" onClick={() => { setBusy(true); load() }} disabled={busy}>
          {busy ? 'Checking…' : 'Check log'}
        </button>
      </PageHeader>

      {validation && (validation.valid ? (
        <Notice tone="success" title="Log verified">
          All {validation.blocks_checked} records are intact. Nothing has been changed or removed.
        </Notice>
      ) : (
        <Notice tone="error" title="The log has been tampered with">
          Record{validation.errors.length > 1 ? 's' : ''} {altered} no longer match{validation.errors.length > 1 ? '' : 'es'} the original. Treat this system as compromised.
        </Notice>
      ))}

      <section className="panel flush">
        {blocks === null ? (
          <Empty>Loading…</Empty>
        ) : blocks.length === 0 ? (
          <Empty>No documents have been opened yet.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Record</th>
                  <th>Date &amp; time</th>
                  <th>Opened by</th>
                  <th>Document</th>
                </tr>
              </thead>
              <tbody>
                {blocks.map(b => (
                  <tr key={b.block_index}>
                    <td className="muted">#{b.block_index}</td>
                    <td className="nowrap">{formatTime(b.timestamp)}</td>
                    <td>{userName(b.recipient_id)}</td>
                    <td>{docName(b.doc_id) || <span className="muted">Unavailable</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {blocks && total > blocks.length && (
          <div className="table-foot muted small">Showing the latest {blocks.length} of {total} records</div>
        )}
      </section>
    </>
  )
}

// ─── App shell ──────────────────────────────────────────────────────
const PAGES = [
  { id: 'overview', label: 'Overview', component: Overview },
  { id: 'recipients', label: 'Recipients', component: Recipients },
  { id: 'share', label: 'Share Document', component: ShareDocument, section: 'Documents' },
  { id: 'open', label: 'Open Document', component: OpenDocument, section: 'Documents' },
  { id: 'trace', label: 'Trace Leak', component: TraceLeak, section: 'Investigation' },
  { id: 'ledger', label: 'Activity Log', component: ActivityLog, section: 'Investigation' },
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
  const [page, setPage] = useState('overview')
  const [zoomIdx, setZoomIdx] = useState(() => loadPref('zoom', 1))
  const [highContrast, setHighContrast] = useState(() => loadPref('contrast', false))

  useEffect(() => { savePref('zoom', zoomIdx) }, [zoomIdx])
  useEffect(() => { savePref('contrast', highContrast) }, [highContrast])

  const current = PAGES.find(p => p.id === page) || PAGES[0]
  const CurrentPage = current.component
  const groups = [...new Set(PAGES.map(p => p.section ?? ''))]

  return (
    <div className="app" data-contrast={highContrast ? 'high' : undefined}>
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">N</div>
          <span className="brand-name">NISHAN</span>
        </div>

        <nav aria-label="Main">
          {groups.map(section => (
            <div key={section || 'main'} className="nav-group">
              {section && <div className="nav-section">{section}</div>}
              {PAGES.filter(p => (p.section ?? '') === section).map(p => (
                <button type="button" key={p.id} className={`nav-item ${page === p.id ? 'active' : ''}`}
                  aria-current={page === p.id ? 'page' : undefined} onClick={() => setPage(p.id)}>
                  {p.label}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="nav-section">Display</div>
          <div className="display-controls" role="group" aria-label="Display settings">
            <button type="button" aria-label="Smaller text" title="Smaller text"
              disabled={zoomIdx === 0} onClick={() => setZoomIdx(i => i - 1)}>A−</button>
            <button type="button" aria-label="Default text size" title="Default text size"
              onClick={() => setZoomIdx(1)}>A</button>
            <button type="button" aria-label="Larger text" title="Larger text"
              disabled={zoomIdx === ZOOM_STEPS.length - 1} onClick={() => setZoomIdx(i => i + 1)}>A+</button>
          </div>
          <label className="toggle">
            <input type="checkbox" checked={highContrast} onChange={e => setHighContrast(e.target.checked)} />
            <span>High contrast</span>
          </label>
        </div>
      </aside>

      <main className="main">
        <div className="main-inner" style={{ zoom: ZOOM_STEPS[zoomIdx] ?? 1 }}>
          <CurrentPage key={current.id} onNavigate={setPage} />
        </div>
      </main>
    </div>
  )
}
