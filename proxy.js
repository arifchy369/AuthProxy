/**
 * AuthProxy: auth-protected reverse proxy (HTTP + WebSocket)
 * with a custom login page (login.html) and cookie sessions.
 * Optionally starts your web app with a shell command when the backend is down.
 *
 * Usage:
 *   1) Edit config.json (ports, backend command, session and security settings)
 *   2) Copy .env.example to .env and set PROXY_USER / PROXY_PASS
 *   3) chmod 600 .env
 *   4) npm install && npm start
 *
 * Secrets (.env or real environment variables):
 *   PROXY_USER, PROXY_PASS   (required)
 *
 * Optional overrides (environment wins over config.json):
 *   HOST, PORT, BACKEND_PORT, CONFIG_FILE, ENV_FILE
 *
 * Everything else lives in config.json.
 *
 * Behind nginx/Caddy/etc., set "security": { "trustProxy": true } (loopback proxy)
 * or an array of proxy IPs, so lockouts are per real client instead of per proxy.
 *
 * Routes added by the proxy:
 *   /__login   login page
 *   /__logout  ends the session
 */
'use strict';

const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const httpProxy = require('http-proxy');

// ==================== .env LOADER ====================
// Reads KEY=VALUE lines from .env (next to this script, or ENV_FILE path).
// Real environment variables always win over the file.
// '#' is NOT treated as an inline comment, so passwords may contain it.
// Wrap values in quotes if they have leading/trailing spaces.
(function loadEnv() {
  const file = process.env.ENV_FILE || path.join(__dirname, '.env');
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    if (e.code !== 'ENOENT') console.error(`[Proxy] Cannot read ${file}: ${e.message}`);
    return;
  }
  try {
    const mode = fs.statSync(file).mode & 0o077;
    if (mode) console.warn(`[Proxy] WARNING: ${file} is readable by others. Run: chmod 600 ${file}`);
  } catch (_) { /* ignore */ }

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m) continue;
    let val = m[2];
    if (val.length >= 2 && (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    )) {
      val = val.slice(1, -1);
    }
    if (process.env[m[1]] === undefined) process.env[m[1]] = val;
  }
})();

// ==================== config.json LOADER ====================
const CONFIG_FILE = process.env.CONFIG_FILE || path.join(__dirname, 'config.json');
let cfg = {};
try {
  cfg = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
} catch (e) {
  if (e.code === 'ENOENT') {
    console.warn(`[Proxy] ${CONFIG_FILE} not found, using defaults.`);
  } else {
    console.error(`[Proxy] Cannot read ${CONFIG_FILE}: ${e.message}`);
    process.exit(1);
  }
}

// Returns the first positive finite number, else the fallback
const num = (fallback, ...vals) => {
  for (const v of vals) {
    const n = Number(v);
    if (Number.isFinite(n) && n > 0) return n;
  }
  return fallback;
};

const backendCfg = cfg.backend || {};
const sessionCfg = cfg.session || {};
const securityCfg = cfg.security || {};

// ==================== CONFIG ====================
const HOST = process.env.HOST || cfg.host || '127.0.0.1';
const PORT = num(8080, process.env.PORT, cfg.port);

const BACKEND_HOST = backendCfg.host || '127.0.0.1';
const BACKEND_PORT = num(8090, process.env.BACKEND_PORT, backendCfg.port);
const BACKEND_COMMAND = typeof backendCfg.command === 'string' ? backendCfg.command.trim() : '';
const BACKEND_CWD = backendCfg.cwd ? path.resolve(__dirname, backendCfg.cwd) : __dirname;
const BACKEND_ENV = (backendCfg.env && typeof backendCfg.env === 'object') ? backendCfg.env : {};

const AUTH_USER = process.env.PROXY_USER;
const AUTH_PASS = process.env.PROXY_PASS;

const START_TIMEOUT = num(20000, backendCfg.startTimeoutMs);  // max wait for backend to come up (ms)
const CHECK_INTERVAL = 500;                                   // backend readiness poll (ms)
const MAX_FAILS = num(5, securityCfg.maxFails);               // wrong attempts before block
const BLOCK_MS = num(15, securityCfg.blockMinutes) * 60 * 1000;

// Reverse-proxy awareness: security.trustProxy = true (loopback only) or an
// array of proxy IPs. X-Forwarded-For is honoured only from those peers.
const normIp = (ip) => String(ip || '').replace(/^::ffff:/i, '');
const TRUST_PROXY = (() => {
  const t = securityCfg.trustProxy;
  if (t === true) return ['127.0.0.1', '::1'];
  if (Array.isArray(t)) return t.map(normIp);
  return [];
})();
const isTrustedProxy = (ip) => TRUST_PROXY.includes(normIp(ip));

const SESSION_HOURS = num(12, sessionCfg.hours);
const SESSION_MS = SESSION_HOURS * 60 * 60 * 1000;
const COOKIE_NAME = 'authproxy_session';
const LOGIN_PATH = '/__login';
const LOGOUT_PATH = '/__logout';

if (!AUTH_USER || !AUTH_PASS) {
  console.error('Set PROXY_USER and PROXY_PASS (in .env or as environment variables).');
  process.exit(1);
}

let LOGIN_HTML;
try {
  LOGIN_HTML = fs.readFileSync(path.join(__dirname, 'login.html'), 'utf8');
} catch (e) {
  console.error(`Cannot read login.html next to proxy.js: ${e.message}`);
  process.exit(1);
}

const TARGET = `http://${BACKEND_HOST}:${BACKEND_PORT}`;

// ==================== AUTH ====================
const sha = (s) => crypto.createHash('sha256').update(s).digest();
const USER_HASH = sha(AUTH_USER);
const PASS_HASH = sha(AUTH_PASS);

// Constant-time comparison (hashing equalises lengths)
function checkCreds(user, pass) {
  const uOk = crypto.timingSafeEqual(sha(user), USER_HASH);
  const pOk = crypto.timingSafeEqual(sha(pass), PASS_HASH);
  return uOk && pOk;
}

// Basic header is still accepted (scripts, curl, API clients)
function basicOk(header) {
  if (!header || !header.startsWith('Basic ')) return false;
  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const i = decoded.indexOf(':');
  if (i < 0) return false;
  return checkCreds(decoded.slice(0, i), decoded.slice(i + 1));
}

// ---- Sessions (in memory; users sign in again after a restart) ----
const sessions = new Map(); // token -> expiry timestamp

function createSession() {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + SESSION_MS);
  return token;
}

function sessionValid(token) {
  if (!token) return false;
  const exp = sessions.get(token);
  if (!exp) return false;
  if (exp <= Date.now()) { sessions.delete(token); return false; }
  return true;
}

function getCookie(req, name) {
  const h = req.headers.cookie;
  if (!h) return null;
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

// Remove our cookie before forwarding so the app never sees the session token
function stripSessionCookie(req) {
  const h = req.headers.cookie;
  if (!h) return;
  const kept = h.split(';').map((s) => s.trim())
    .filter((s) => s && !s.startsWith(COOKIE_NAME + '='));
  if (kept.length) req.headers.cookie = kept.join('; ');
  else delete req.headers.cookie;
}

function cookieHeader(req, value, maxAgeSec) {
  const secure = req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https';
  return `${COOKIE_NAME}=${value}; Path=/; Max-Age=${maxAgeSec}; HttpOnly; SameSite=Strict${secure ? '; Secure' : ''}`;
}

// ---- Simple per-IP brute-force protection ----
const fails = new Map(); // ip -> { count, until, last }

// Real client IP. Behind a trusted reverse proxy, take the right-most
// X-Forwarded-For entry that is not itself a trusted proxy.
function clientIp(req) {
  const peer = normIp(req.socket.remoteAddress);
  if (!TRUST_PROXY.length || !isTrustedProxy(peer)) return peer;
  const hops = String(req.headers['x-forwarded-for'] || '')
    .split(',').map((x) => normIp(x.trim())).filter(Boolean);
  for (let i = hops.length - 1; i >= 0; i--) {
    if (!isTrustedProxy(hops[i])) return hops[i];
  }
  return peer;
}

function isBlocked(ip) {
  const f = fails.get(ip);
  return !!(f && f.until > Date.now());
}

function recordFail(ip) {
  const now = Date.now();
  let f = fails.get(ip);
  // Start fresh if the block has ended, or the last failure is older than the window
  if (!f || (f.until && f.until <= now) || (!f.until && now - f.last > BLOCK_MS)) {
    f = { count: 0, until: 0, last: now };
  }
  f.last = now;
  f.count++;
  if (f.count >= MAX_FAILS) {
    f.until = now + BLOCK_MS;
    f.count = 0;
    console.warn(`[Proxy] Blocked ${ip} for ${BLOCK_MS / 60000} min`);
  }
  fails.set(ip, f);
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, f] of fails) {
    const blockOver = f.until && f.until <= now;
    const stale = !f.until && now - f.last > BLOCK_MS;
    if (blockOver || stale) fails.delete(ip);
  }
  for (const [t, exp] of sessions) if (exp <= now) sessions.delete(t);
}, 60 * 1000).unref();

// Returns 200 (ok), 401 (need/invalid creds) or 429 (blocked)
function authorize(req) {
  if (sessionValid(getCookie(req, COOKIE_NAME))) return 200;

  const ip = clientIp(req);
  if (isBlocked(ip)) return 429;
  if (basicOk(req.headers.authorization)) {
    fails.delete(ip);
    return 200;
  }
  if (req.headers.authorization) recordFail(ip);
  return 401;
}

function deny(res, code) {
  const headers = { 'Content-Type': 'text/plain; charset=utf-8' };
  if (code === 429) headers['Retry-After'] = String(BLOCK_MS / 1000);
  res.writeHead(code, headers);
  res.end(code === 401 ? 'Authentication required' : 'Too many attempts');
}

// ==================== LOGIN PAGE ====================
const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

// Only allow same-site relative paths (prevents open redirects)
function safeNext(n) {
  if (typeof n !== 'string') return '/';
  if (!/^\/(?![\/\\])[\x21-\x7e]*$/.test(n)) return '/';  // printable ASCII only: safe in a Location header
  if (n.startsWith(LOGIN_PATH) || n.startsWith(LOGOUT_PATH)) return '/';
  return n;
}

function redirect(res, location, status = 302, extra = {}) {
  res.writeHead(status, { Location: location, 'Cache-Control': 'no-store', ...extra });
  res.end();
}

function renderLogin(res, status, next, error) {
  const html = LOGIN_HTML
    .replace('{{ERROR}}', () => (error ? `<div class="error" role="alert">${esc(error)}</div>` : ''))
    .replace('{{NEXT}}', () => esc(next))
    .replace('{{SESSION_HOURS}}', () => esc(SESSION_HOURS));
  const headers = {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy':
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; " +
      "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  };
  if (status === 429) headers['Retry-After'] = String(BLOCK_MS / 1000);
  res.writeHead(status, headers);
  res.end(html);
}

const BLOCKED_MSG = `Too many attempts. Try again in ${BLOCK_MS / 60000} minutes.`;

function readBody(req, limit, cb) {
  let size = 0;
  const chunks = [];
  let done = false;
  req.on('data', (c) => {
    if (done) return;
    size += c.length;
    if (size > limit) { done = true; req.destroy(); return cb(null); }
    chunks.push(c);
  });
  req.on('end', () => { if (!done) { done = true; cb(Buffer.concat(chunks).toString('utf8')); } });
  req.on('error', () => { if (!done) { done = true; cb(null); } });
}

function handleLogin(req, res, url) {
  const ip = clientIp(req);

  if (req.method === 'GET' || req.method === 'HEAD') {
    const next = safeNext(url.searchParams.get('next'));
    if (sessionValid(getCookie(req, COOKIE_NAME))) return redirect(res, next);
    if (isBlocked(ip)) return renderLogin(res, 429, next, BLOCKED_MSG);
    return renderLogin(res, 200, next, '');
  }

  if (req.method !== 'POST') {
    res.writeHead(405, { Allow: 'GET, HEAD, POST' });
    return res.end();
  }

  readBody(req, 4096, (body) => {
    if (body === null) {
      res.writeHead(413, { 'Content-Type': 'text/plain' });
      return res.end('Request too large');
    }
    const form = new URLSearchParams(body);
    const next = safeNext(form.get('next'));

    if (isBlocked(ip)) return renderLogin(res, 429, next, BLOCKED_MSG);

    const user = form.get('username') || '';
    const pass = form.get('password') || '';
    if (checkCreds(user, pass)) {
      fails.delete(ip);
      const token = createSession();
      return redirect(res, next, 303, {
        'Set-Cookie': cookieHeader(req, token, SESSION_MS / 1000),
      });
    }

    recordFail(ip);
    if (isBlocked(ip)) return renderLogin(res, 429, next, BLOCKED_MSG);
    return renderLogin(res, 401, next, 'Wrong username or password.');
  });
}

function handleLogout(req, res) {
  const token = getCookie(req, COOKIE_NAME);
  if (token) sessions.delete(token);
  redirect(res, LOGIN_PATH, 302, { 'Set-Cookie': cookieHeader(req, '', 0) });
}

// ==================== BACKEND CONTROL ====================
let backendChild = null; // the spawned command, while it is still running

function checkBackend(cb) {
  const sock = net.connect(BACKEND_PORT, BACKEND_HOST);
  sock.once('connect', () => { sock.destroy(); cb(true); });
  sock.once('error', () => { sock.destroy(); cb(false); });
}

// Runs backend.command from config.json through the shell.
// {host} and {port} in the command are replaced with the backend host/port.
function startBackend() {
  if (backendChild) return; // already launched and still running: just keep waiting

  const command = BACKEND_COMMAND
    .replace(/\{host\}/g, BACKEND_HOST)
    .replace(/\{port\}/g, String(BACKEND_PORT));

  // Never hand the proxy credentials to the app
  const env = { ...process.env, ...BACKEND_ENV };
  delete env.PROXY_USER;
  delete env.PROXY_PASS;

  console.log(`[Proxy] Backend offline -> running: ${command}`);
  const child = spawn(command, {
    shell: true,
    cwd: BACKEND_CWD,
    env,
    detached: true,
    stdio: 'ignore',
  });
  backendChild = child;
  child.on('error', (e) => {
    if (backendChild === child) backendChild = null;
    console.error('[Proxy] Failed to start backend:', e.message);
  });
  child.on('exit', (code, signal) => {
    if (backendChild === child) backendChild = null;
    console.warn(`[Proxy] Backend command exited (code=${code}, signal=${signal})`);
  });
  child.unref();
}

// Calls cb(true) once backend is reachable, cb(false) on timeout/disabled
function ensureBackend(cb) {
  checkBackend((up) => {
    if (up) return cb(true);
    if (!BACKEND_COMMAND) return cb(false);
    startBackend();
    const deadline = Date.now() + START_TIMEOUT;
    const poll = () => checkBackend((ok) => {
      if (ok) return cb(true);
      if (Date.now() > deadline) return cb(false);
      setTimeout(poll, CHECK_INTERVAL);
    });
    setTimeout(poll, CHECK_INTERVAL);
  });
}

// ==================== PROXY SERVER ====================
const proxy = httpProxy.createProxyServer({ target: TARGET, xfwd: true });

proxy.on('error', (err, req, res) => {
  console.error('[Proxy] error:', err.message);
  if (res && typeof res.writeHead === 'function' && !res.headersSent) {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('Bad gateway');
  } else if (res && typeof res.destroy === 'function') {
    res.destroy();
  }
});

const wantsHtml = (req) =>
  req.method === 'GET' && (req.headers.accept || '').includes('text/html');

const server = http.createServer((req, res) => {
  let url;
  try { url = new URL(req.url, 'http://proxy.local'); }
  catch (_) { res.writeHead(400); return res.end(); }

  if (url.pathname === LOGIN_PATH) return handleLogin(req, res, url);
  if (url.pathname === LOGOUT_PATH) return handleLogout(req, res);

  const code = authorize(req);
  if (code !== 200) {
    // Browsers get the login page; scripts and XHR get a plain status code
    if (wantsHtml(req)) {
      return redirect(res, `${LOGIN_PATH}?next=${encodeURIComponent(req.url)}`);
    }
    return deny(res, code);
  }

  delete req.headers.authorization; // don't leak proxy credentials to the app
  stripSessionCookie(req);

  ensureBackend((up) => {
    if (!up) {
      res.writeHead(503, { 'Content-Type': 'text/plain' });
      return res.end('Backend unavailable');
    }
    proxy.web(req, res);
  });
});

server.on('upgrade', (req, socket, head) => {
  // Without a listener, a client reset while we wait for the backend would crash the process
  socket.on('error', () => socket.destroy());

  const code = authorize(req);
  if (code !== 200) {
    const msg = code === 401 ? 'Unauthorized' : 'Too Many Requests';
    socket.write(`HTTP/1.1 ${code} ${msg}\r\nConnection: close\r\n\r\n`);
    return socket.destroy();
  }

  delete req.headers.authorization;
  stripSessionCookie(req);

  ensureBackend((up) => {
    if (!up) return socket.destroy();
    proxy.ws(req, socket, head);
  });
});

server.listen(PORT, HOST, () => {
  console.log(`[Proxy] Listening on http://${HOST}:${PORT} -> ${TARGET}`);
  if (BACKEND_COMMAND) console.log(`[Proxy] Backend auto-start enabled (cwd: ${BACKEND_CWD})`);
  if (HOST !== '127.0.0.1' && HOST !== 'localhost') {
    console.warn('[Proxy] WARNING: Credentials and session cookie travel in plain text over HTTP. Use HTTPS or a VPN when exposed.');
  }
});