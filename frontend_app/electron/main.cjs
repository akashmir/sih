/**
 * NISHAN desktop shell.
 *
 * Starts the Python backend on a free localhost port, serving the built
 * React UI from frontend_app/dist, and shows it in a native window.
 * The backend is stopped when the app quits.
 *
 *   npm run desktop                      build the UI, then launch
 *   npm run desktop:dev                  load the Vite dev server instead
 *                                        (backend must already run on :8000)
 *
 * Environment:
 *   NISHAN_PYTHON    Python executable (default: python / python3)
 *   NISHAN_DATA_DIR  passed through to the backend
 */

const { app, BrowserWindow, dialog, shell } = require('electron')
const { spawn } = require('node:child_process')
const fs = require('node:fs')
const http = require('node:http')
const net = require('node:net')
const path = require('node:path')

const REPO_ROOT = path.resolve(__dirname, '..', '..')
const DIST_DIR = path.resolve(__dirname, '..', 'dist')
const ICON = path.join(__dirname, 'icon.png')
const DEV_URL = process.argv.find(a => a.startsWith('--dev-url='))?.split('=')[1]
const STARTUP_TIMEOUT_MS = 30_000

let backend = null
let backendLog = ''
let quitting = false
let mainWindow = null

// ─── Backend process ────────────────────────────────────────────────
function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.unref()
    srv.on('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => resolve(port))
    })
  })
}

function startBackend(port) {
  const python = process.env.NISHAN_PYTHON || (process.platform === 'win32' ? 'python' : 'python3')
  backend = spawn(
    python,
    ['-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', String(port)],
    {
      cwd: REPO_ROOT,
      env: { ...process.env, NISHAN_FRONTEND_DIST: DIST_DIR, PYTHONUNBUFFERED: '1' },
      windowsHide: true,
    },
  )

  const capture = chunk => { backendLog = (backendLog + chunk).slice(-4000) }
  backend.stdout.on('data', capture)
  backend.stderr.on('data', capture)

  backend.on('error', err => {
    capture(`\nFailed to run "${python}": ${err.message}\n`)
    backend = null
  })
  backend.on('exit', code => {
    backend = null
    if (!quitting && mainWindow) {
      fail('The NISHAN backend stopped unexpectedly', `Exit code ${code}`)
    }
  })
}

function stopBackend() {
  if (backend) {
    backend.kill()
    backend = null
  }
}

function waitForBackend(port) {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS
  return new Promise((resolve, reject) => {
    const attempt = () => {
      if (!backend) return reject(new Error('Backend process exited during startup'))
      if (Date.now() > deadline) return reject(new Error('Timed out waiting for the backend'))
      const req = http.get({ host: '127.0.0.1', port, path: '/api/system/info', timeout: 1000 }, res => {
        res.resume()
        if (res.statusCode === 200) resolve()
        else setTimeout(attempt, 300)
      })
      req.on('error', () => setTimeout(attempt, 300))
      req.on('timeout', () => req.destroy())
    }
    attempt()
  })
}

function fail(title, detail) {
  dialog.showErrorBox(
    title,
    `${detail}\n\n` +
    'Check that Python 3.10+ is installed and the backend dependencies are present:\n' +
    '  pip install -r backend/requirements.txt\n' +
    'Set NISHAN_PYTHON to choose a specific Python executable.\n\n' +
    (backendLog ? `Backend output:\n${backendLog.slice(-1500)}` : ''),
  )
  app.quit()
}

// ─── Window ─────────────────────────────────────────────────────────
const SPLASH = `data:text/html;charset=utf-8,${encodeURIComponent(`<!doctype html>
<html><head><meta charset="utf-8"><style>
  html,body{height:100%;margin:0;font-family:'Segoe UI',system-ui,sans-serif;background:#f5f6f8;color:#1b2330}
  body{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px}
  .brand{display:flex;align-items:center;gap:12px;font-size:22px;font-weight:700;letter-spacing:.08em}
  .mark{width:40px;height:40px;border-radius:9px;background:#1e4e8c;color:#fff;display:grid;place-items:center;
        font-size:20px;letter-spacing:0}
  .bar{width:160px;height:3px;border-radius:2px;background:#e3e6eb;overflow:hidden}
  .bar::after{content:"";display:block;width:40%;height:100%;background:#1e4e8c;animation:slide 1.1s ease-in-out infinite}
  @keyframes slide{from{transform:translateX(-100%)}to{transform:translateX(250%)}}
  p{margin:0;color:#6b7686;font-size:13px}
</style></head><body>
  <div class="brand"><div class="mark">N</div>NISHAN</div><div class="bar"></div><p>Starting…</p>
</body></html>`)}`

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 960,
    minHeight: 640,
    title: 'NISHAN',
    icon: fs.existsSync(ICON) ? ICON : undefined,
    backgroundColor: '#f5f6f8',
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  })
  mainWindow.on('closed', () => { mainWindow = null })
  mainWindow.loadURL(SPLASH)
  return mainWindow
}

// Keep the window on the app; open external http(s) links in the system browser.
function lockNavigation(win, appUrl) {
  const appOrigin = new URL(appUrl).origin
  const isExternal = url => /^https?:/i.test(url) && new URL(url).origin !== appOrigin

  win.webContents.setWindowOpenHandler(({ url }) => {
    if (isExternal(url)) shell.openExternal(url)
    return { action: 'deny' }
  })
  win.webContents.on('will-navigate', (event, url) => {
    if (url.startsWith(appOrigin)) return
    event.preventDefault()
    if (isExternal(url)) shell.openExternal(url)
  })
}

// ─── Lifecycle ──────────────────────────────────────────────────────
if (!app.requestSingleInstanceLock()) {
  app.quit()
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore()
      mainWindow.focus()
    }
  })

  app.whenReady().then(async () => {
    const win = createWindow()
    let url

    if (DEV_URL) {
      url = DEV_URL
    } else {
      if (!fs.existsSync(path.join(DIST_DIR, 'index.html'))) {
        return fail('NISHAN UI not built', `No build found in ${DIST_DIR}. Run "npm run build" first.`)
      }
      try {
        const port = await freePort()
        startBackend(port)
        await waitForBackend(port)
        url = `http://127.0.0.1:${port}/`
      } catch (err) {
        stopBackend()
        return fail('The NISHAN backend failed to start', err.message)
      }
    }

    if (!mainWindow) return  // closed while starting
    lockNavigation(win, url)
    win.loadURL(url)
  })

  app.on('window-all-closed', () => app.quit())
  app.on('before-quit', () => { quitting = true })
  app.on('will-quit', stopBackend)
  process.on('exit', stopBackend)
}
