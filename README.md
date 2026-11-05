# AuthProxy

A small, dependency-light **auth-protected reverse proxy** for HTTP and WebSocket traffic, with a custom login page and cookie-based sessions. It can also start your web app for you with a command you set in `config.json`.

Put it in front of any web app that has no login of its own (or a weak one), and users must sign in before a single request reaches the app.

## Features

- **Custom login page** (`login.html`) with light/dark mode, show/hide password, and mobile support
- **Cookie sessions**: `HttpOnly`, `SameSite=Strict`, and `Secure` automatically over HTTPS
- **HTTP Basic auth still accepted**, so `curl`, scripts, and API clients keep working
- **WebSocket proxying** with the same authentication
- **Brute-force protection**: too many wrong attempts blocks that IP for a while
- **Constant-time credential comparison** (SHA-256 hashing + `timingSafeEqual`)
- **Open-redirect protection** on the post-login `next` parameter
- **Credentials never reach your app**: the `Authorization` header and the session cookie are stripped before forwarding, and `PROXY_USER`/`PROXY_PASS` are removed from the environment of the started app
- **Optional backend auto-start**: runs the command from `config.json` when the backend port is not reachable
- **Hardened login response**: strict CSP, `X-Frame-Options: DENY`, `no-store`, `no-referrer`
- Settings in `config.json`, secrets in `.env`

## Requirements

- Node.js **16 or newer**
- Whatever your web app itself needs, if you use auto-start

## Quick start

```bash
git clone https://github.com/arifchy369/authproxy.git
cd authproxy
npm install
cp .env.example .env
chmod 600 .env
```

Edit `.env` and set your login:

```env
PROXY_USER=admin
PROXY_PASS=change-me-to-a-long-random-password
```

Edit `config.json` (see below), then start:

```bash
npm start
```

Open `http://127.0.0.1:8080`. You will be redirected to the login page.

## Configuration

### `config.json`

```json
{
  "host": "127.0.0.1",
  "port": 8080,
  "backend": {
    "host": "127.0.0.1",
    "port": 8090,
    "command": "npm start",
    "cwd": "/path/to/your/web-app",
    "env": { "NODE_ENV": "production" },
    "startTimeoutMs": 20000
  },
  "session": {
    "hours": 12
  },
  "security": {
    "maxFails": 5,
    "blockMinutes": 15
  }
}
```

| Key                      | Default       | Description |
|--------------------------|---------------|-------------|
| `host`                   | `127.0.0.1`   | Address the proxy binds to |
| `port`                   | `8080`        | Port the proxy listens on |
| `backend.host`           | `127.0.0.1`   | Host of your web app |
| `backend.port`           | `8090`        | Port of your web app |
| `backend.command`        | empty         | Shell command that starts your web app. Leave empty to disable auto-start |
| `backend.cwd`            | proxy folder  | Working directory for the command (relative paths resolve from the proxy folder) |
| `backend.env`            | `{}`          | Extra environment variables for the command |
| `backend.startTimeoutMs` | `20000`       | How long to wait for the app to come up |
| `session.hours`          | `12`          | Session lifetime (also shown on the login page) |
| `security.maxFails`      | `5`           | Wrong attempts before an IP is blocked |
| `security.blockMinutes`  | `15`          | Block duration |

### Starting your web app automatically

If `backend.command` is set, the proxy runs it when a request arrives and the backend port is not reachable, then waits up to `startTimeoutMs` for the port to open. The command runs through the shell, so pipes and arguments work. The placeholders `{host}` and `{port}` are replaced with `backend.host` and `backend.port`:

```json
"command": "node server.js --host {host} --port {port}"
```

Make sure the command makes your app listen on the same `backend.host` and `backend.port`.

### `.env`

| Variable     | Required | Description |
|--------------|----------|-------------|
| `PROXY_USER` | yes      | Login username |
| `PROXY_PASS` | yes      | Login password |

Optional overrides (these take priority over `config.json`): `HOST`, `PORT`, `BACKEND_PORT`. Use `CONFIG_FILE=/path/to/config.json` or `ENV_FILE=/path/to/.env` to load files from another location. Real environment variables always win over values in `.env`.

Format notes: one `KEY=VALUE` per line, `#` starts a comment only at the beginning of a line (so passwords may contain it), and values with leading or trailing spaces should be quoted.

## Routes added by the proxy

| Route       | Purpose |
|-------------|---------|
| `/__login`  | Login page (GET) and credential submission (POST) |
| `/__logout` | Ends the session and redirects to the login page |

Everything else is forwarded to your app once the request is authenticated.

## How it behaves

- **Browsers** (requests that accept `text/html`) without a valid session are redirected to `/__login?next=<original path>`.
- **Scripts and XHR** without valid credentials get a plain `401` (or `429` if blocked).
- **WebSocket upgrades** are authenticated the same way and rejected with `401` or `429` before the upgrade.
- If the app is unreachable and cannot be started, the proxy returns `503 Backend unavailable`.

### Using Basic auth from scripts

```bash
curl -u admin:your-password http://127.0.0.1:8080/
```

## Running as a service (systemd example)

```ini
[Unit]
Description=AuthProxy
After=network.target

[Service]
WorkingDirectory=/opt/authproxy
ExecStart=/usr/bin/node proxy.js
Restart=on-failure
User=www-data

[Install]
WantedBy=multi-user.target
```

## Security notes

- **Use HTTPS.** The proxy itself speaks plain HTTP. If you bind to anything other than `127.0.0.1`/`localhost`, credentials and the session cookie travel unencrypted, and the proxy prints a warning. Put it behind a TLS-terminating reverse proxy (Nginx, Caddy, etc.) or a VPN. When TLS is terminated upstream, forward `X-Forwarded-Proto: https` so the cookie gets the `Secure` flag.
- **`backend.command` is executed in a shell.** Only you should be able to edit `config.json`; restrict its permissions (for example `chmod 600 config.json`).
- **Sessions are stored in memory.** Everyone must sign in again after a restart.
- **Rate limiting is per remote IP.** Behind another reverse proxy, every client appears to come from that proxy's address, so one attacker could trigger a block for all users. In that setup, add rate limiting at the outer proxy as well.
- **Keep `.env` private.** The proxy warns on startup if the file is readable by other users. Never commit it.
- Your app should listen only on `127.0.0.1` so it cannot be reached around the proxy.

## Project structure

```
authproxy/
├── proxy.js        # Proxy server, auth, sessions, backend control
├── login.html      # Login page template
├── config.json     # Ports, backend command, session and security settings
├── .env.example    # Template for your credentials
├── package.json
├── LICENSE
└── README.md
```

`login.html` uses three placeholders that the proxy fills in: `{{ERROR}}`, `{{NEXT}}` and `{{SESSION_HOURS}}`. Keep them if you restyle the page.

## License

MIT, see [LICENSE](LICENSE).
