# Web Port Scanner

A browser-based TCP port scanner, behind a login wall. Flask backend does the
actual scanning (browsers can't open raw sockets), streams results live to
the page over Server-Sent Events, and a terminal-styled UI lights up a port
grid as it goes.

## ⚠️ Before you deploy this publicly

- **Only scan systems you own or have explicit written permission to test.**
  Unauthorized port scanning is illegal in many places (e.g. under the US
  Computer Fraud and Abuse Act) and violates the acceptable-use policy of
  essentially every cloud/hosting provider.
- **Most PaaS providers (Render, Railway, Heroku, PythonAnywhere, AWS, etc.)
  explicitly prohibit port scanning from their infrastructure**, even against
  targets you own, because outbound scanning traffic looks identical to abuse
  from their network's perspective. Read your host's acceptable-use policy
  first — several will suspend your account for this without warning.
- The app is now **login-protected** (see setup below) so a random visitor
  can't use your server to scan someone else. Still set `ALLOWED_TARGETS` if
  you want to hard-lock it to specific hosts even for yourself.
- `MAX_PORTS_PER_SCAN`, `MAX_THREADS`, and the timeout bounds in `app.py` are
  deliberately conservative — raise them only if you understand the tradeoffs.

## Setup: environment variables (required)

The app refuses to start without these set. Copy `.env.example` to `.env` and
fill it in — **never commit the real `.env` file** (it's already git-ignored).

```bash
cp .env.example .env
```

Generate a session secret:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Generate a password hash (pick your own password):
```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your-password-here'))"
```

Paste both into `.env` along with a username. On Windows PowerShell, if you'd
rather set env vars directly instead of using `.env`:
```powershell
$env:SECRET_KEY="paste-generated-secret"
$env:AUTH_USERNAME="admin"
$env:AUTH_PASSWORD_HASH="paste-generated-hash"
```

## Run locally

```bash
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000 and log in with the credentials you set
```

If running plain HTTP locally (no TLS), set `COOKIE_SECURE=false` in `.env`
or the login cookie won't be sent by the browser. Keep it `true` for any real
deployment behind HTTPS.

## Security hardening included

- **Auth**: hashed password (scrypt/pbkdf2 via werkzeug), session cookies with
  `HttpOnly`/`SameSite`/`Secure` flags, rate-limited login attempts.
- **CSRF protection** on the login and logout forms (session-bound token).
- **SSRF guard**: link-local addresses (including the cloud metadata IP
  `169.254.169.254`) are always blocked. Set `STRICT_SSRF_GUARD=true` in
  `.env` to also block private/loopback ranges — recommended if you ever
  deploy this outside your own machine/LAN.
- **Target allow-list** (`ALLOWED_TARGETS`) to hard-lock scans to specific
  hosts you own.
- Bounded in-memory rate-limit tracking so it can't leak memory under a
  flood of login attempts from many IPs.

Periodically re-check `requirements.txt` against the latest releases —
dependencies are pinned for reproducibility, which means they won't
auto-update, so check `pip list --outdated` occasionally.

## Pushing to GitHub

GitHub only hosts your *code* — it doesn't run the Flask app for you (that's
a separate hosting step below). To get this into a repo:

```bash
git init
git add .
git commit -m "Web port scanner with auth"
```

Then create an empty repo on github.com (no README/license, so it doesn't
conflict), and:

```bash
git remote add origin https://github.com/<your-username>/webscanner.git
git branch -M main
git push -u origin main
```

Because `.env` is git-ignored, your secret key and password hash **won't** be
pushed — good. Anyone cloning the repo will need to create their own `.env`
using `.env.example` as the template.

## Run in production (self-hosted VPS)

```bash
pip install -r requirements.txt
export SECRET_KEY=...
export AUTH_USERNAME=...
export AUTH_PASSWORD_HASH=...
gunicorn -w 1 --threads 8 -b 0.0.0.0:8000 app:app
```

Use 1 worker with multiple threads (not multiple workers) since scan state is
kept in-memory per request — this app doesn't need a shared job store since
each scan is a single streamed request/response.

Put this behind nginx/Caddy for TLS. Example nginx snippet:

```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Connection '';
    proxy_http_version 1.1;
    proxy_buffering off;      # required for SSE streaming
    chunked_transfer_encoding off;
    proxy_read_timeout 300s;
}
```

## Hosting options if you still want a managed platform

Check the provider's acceptable-use policy for "port scanning" / "network
abuse" before signing up. As of this writing, platforms like Render, Railway,
Fly.io, and PythonAnywhere are all commonly used for demo/portfolio Flask
apps, but scanning behavior specifically may be restricted or trigger abuse
review — verify current terms directly on the provider's site since these
policies change.

## Project structure

```
webscanner/
├── app.py                 # Flask backend + SSE scan endpoint
├── requirements.txt
├── templates/
│   └── index.html         # UI (terminal-styled console + live port grid)
└── static/                # (empty, styles are inlined in index.html)
```

## Customizing

- Colors/fonts: edit the `:root` CSS variables at the top of `index.html`.
- Common port → service name labels: edit `COMMON_PORTS` in `app.py`.
- Safety limits: `MAX_PORTS_PER_SCAN`, `MAX_THREADS`, `MIN_TIMEOUT`,
  `MAX_TIMEOUT` in `app.py`.
