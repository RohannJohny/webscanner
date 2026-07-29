"""
Web Port Scanner - Flask backend
---------------------------------
Serves the scanner UI and exposes a Server-Sent-Events (SSE) endpoint that
performs a threaded TCP connect scan and streams results live to the browser.

IMPORTANT: Only scan hosts/networks you own or have explicit written
permission to test. Scanning systems you don't control without authorization
is illegal in most jurisdictions (e.g. the US Computer Fraud and Abuse Act)
and violates the acceptable-use policy of virtually every cloud host.

Run locally:
    pip install -r requirements.txt
    python app.py
    -> open http://127.0.0.1:5000
"""

import functools
import ipaddress
import json
import os
import queue
import secrets
import socket
import threading
import time

from flask import (
    Flask, Response, abort, redirect, render_template, request,
    session, stream_with_context, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from dotenv import load_dotenv
    load_dotenv()  # loads .env into os.environ for local dev; no-op if file absent
except ImportError:
    pass  # python-dotenv not installed — fine in production where env vars are set directly

app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,  # 8 hours
)

# ---- Auth config (all pulled from environment variables — see .env.example) ----
# SECRET_KEY signs the session cookie. Generate one with:
#   python -c "import secrets; print(secrets.token_hex(32))"
app.secret_key = os.environ.get("SECRET_KEY", "")
if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\" "
        "and set it before starting the app."
    )

AUTH_USERNAME = os.environ.get("AUTH_USERNAME", "")
AUTH_PASSWORD_HASH = os.environ.get("AUTH_PASSWORD_HASH", "")
if not AUTH_USERNAME or not AUTH_PASSWORD_HASH:
    raise RuntimeError(
        "AUTH_USERNAME and AUTH_PASSWORD_HASH must be set. "
        "Generate a hash with: python -c \"from werkzeug.security import generate_password_hash; "
        "print(generate_password_hash('your-password-here'))\""
    )

# Optional: restrict scans to a fixed allow-list of hosts you actually own,
# e.g. ALLOWED_TARGETS="127.0.0.1,10.0.0.5,mydomain.com". Leave unset to allow
# any target (only recommended for strictly private/local use).
_allowed = os.environ.get("ALLOWED_TARGETS", "").strip()
ALLOWED_TARGETS = {t.strip() for t in _allowed.split(",") if t.strip()} if _allowed else None

# ---- Basic login-attempt rate limiting (in-memory, single-process) ----
_login_attempts = {}          # ip -> [timestamps]
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 8
MAX_TRACKED_IPS = 5000        # cap dict size so a flood of distinct IPs can't leak memory

# ---- Safety limits (tune these before deploying publicly) ----
MAX_PORTS_PER_SCAN = 3000       # cap the range size to keep any one scan fast/bounded
MAX_THREADS = 200
MIN_TIMEOUT = 3.0
MAX_TIMEOUT = 5.0

COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP-Submission", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def scan_one(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def run_scan(ip, start_port, end_port, timeout, thread_count, stop_flag, out_q):
    ports = list(range(start_port, end_port + 1))
    port_q = queue.Queue()
    for p in ports:
        port_q.put(p)

    scanned = 0
    open_count = 0
    lock = threading.Lock()
    start_time = time.time()

    def worker():
        nonlocal scanned, open_count
        while not stop_flag.is_set():
            try:
                port = port_q.get_nowait()
            except queue.Empty:
                return
            is_open = scan_one(ip, port, timeout)
            with lock:
                scanned += 1
                if is_open:
                    open_count += 1
                out_q.put({
                    "type": "result",
                    "port": port,
                    "open": is_open,
                    "service": COMMON_PORTS.get(port, "unknown") if is_open else None,
                    "scanned": scanned,
                    "total": len(ports),
                })
            port_q.task_done()

    workers = [threading.Thread(target=worker, daemon=True) for _ in range(thread_count)]
    for t in workers:
        t.start()
    for t in workers:
        t.join()

    elapsed = time.time() - start_time
    out_q.put({
        "type": "done",
        "stopped": stop_flag.is_set(),
        "open_count": open_count,
        "total": len(ports),
        "elapsed": round(elapsed, 2),
    })


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def _get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def _check_csrf():
    token = session.get("csrf_token")
    submitted = request.form.get("csrf_token", "")
    if not token or not secrets.compare_digest(token, submitted):
        abort(400, description="Invalid or missing CSRF token.")


app.jinja_env.globals["csrf_token"] = _get_csrf_token


# ---- SSRF guard against the most dangerous auto-targets ----
# Link-local addresses (169.254.0.0/16, incl. 169.254.169.254 — the cloud
# metadata endpoint on AWS/GCP/Azure) have no legitimate use for a personal
# port scanner and are always blocked, since this is exactly the target an
# SSRF-style attack would aim for if this app were ever hosted in the cloud.
#
# Private/loopback ranges (127.0.0.1, 192.168.x.x, 10.x.x.x, etc.) are NOT
# blocked by default, because scanning your own machine or LAN is this tool's
# normal, intended use. If you deploy this on cloud infrastructure, set
# STRICT_SSRF_GUARD=true in .env to additionally block private/loopback
# targets (recommended for any non-local deployment) — ALLOWED_TARGETS
# entries are always exempted from both checks.
STRICT_SSRF_GUARD = os.environ.get("STRICT_SSRF_GUARD", "false").lower() == "true"


def _is_blocked_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparsable — fail closed
    if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    if STRICT_SSRF_GUARD and (ip.is_private or ip.is_loopback):
        return True
    return False


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def _login_rate_limited(ip):
    now = time.time()
    # Prune this IP's own expired timestamps
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < LOGIN_WINDOW_SECONDS]
    _login_attempts[ip] = attempts

    # Occasionally sweep the whole dict so it can't grow unbounded if many
    # distinct IPs hit /login (e.g. a scripted flood of failed attempts).
    if len(_login_attempts) > MAX_TRACKED_IPS:
        for tracked_ip in list(_login_attempts.keys()):
            remaining = [t for t in _login_attempts[tracked_ip] if now - t < LOGIN_WINDOW_SECONDS]
            if remaining:
                _login_attempts[tracked_ip] = remaining
            else:
                del _login_attempts[tracked_ip]

    return len(attempts) >= LOGIN_MAX_ATTEMPTS


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    _get_csrf_token()  # ensure a token exists to render into the form
    if request.method == "POST":
        _check_csrf()
        ip = _client_ip()
        if _login_rate_limited(ip):
            error = "Too many attempts. Try again in a few minutes."
        else:
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            _login_attempts.setdefault(ip, []).append(time.time())
            if username == AUTH_USERNAME and check_password_hash(AUTH_PASSWORD_HASH, password):
                _login_attempts[ip] = []  # clear on success
                session.clear()
                session["logged_in"] = True
                session.permanent = True
                _get_csrf_token()  # fresh token bound to the new session
                next_url = request.args.get("next") or url_for("index")
                return redirect(next_url)
            error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    _check_csrf()
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/api/scan/stream")
@login_required
def scan_stream():
    target = request.args.get("target", "").strip()
    try:
        start_port = int(request.args.get("start", ""))
        end_port = int(request.args.get("end", ""))
        timeout = float(request.args.get("timeout", 0.5))
        thread_count = int(request.args.get("threads", 100))
    except ValueError:
        return _sse_error("Invalid numeric input.")

    if not target:
        return _sse_error("Target is required.")
    if ALLOWED_TARGETS is not None and target not in ALLOWED_TARGETS:
        return _sse_error(f"'{target}' is not on the allowed target list.")
    if not (0 <= start_port <= 65535) or not (0 <= end_port <= 65535):
        return _sse_error("Ports must be between 0 and 65535.")
    if start_port > end_port:
        return _sse_error("Start port must be <= end port.")
    if (end_port - start_port + 1) > MAX_PORTS_PER_SCAN:
        return _sse_error(f"Range too large. Max {MAX_PORTS_PER_SCAN} ports per scan.")

    timeout = max(MIN_TIMEOUT, min(MAX_TIMEOUT, timeout))
    thread_count = max(1, min(MAX_THREADS, thread_count))

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return _sse_error("Invalid hostname or IP address.")

    is_explicitly_allowed = ALLOWED_TARGETS is not None and target in ALLOWED_TARGETS
    if not is_explicitly_allowed and _is_blocked_ip(target_ip):
        return _sse_error(f"'{target}' resolves to a blocked address range ({target_ip}).")

    out_q = queue.Queue()
    stop_flag = threading.Event()

    scan_thread = threading.Thread(
        target=run_scan,
        args=(target_ip, start_port, end_port, timeout, thread_count, stop_flag, out_q),
        daemon=True,
    )
    scan_thread.start()

    @stream_with_context
    def generate():
        yield _sse({"type": "start", "target": target, "ip": target_ip,
                     "start": start_port, "end": end_port})
        while True:
            try:
                item = out_q.get(timeout=10)
            except queue.Empty:
                if not scan_thread.is_alive():
                    break
                yield ": keep-alive\n\n"
                continue
            yield _sse(item)
            if item.get("type") == "done":
                break

    return Response(generate(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    })


def _sse(payload):
    return f"data: {json.dumps(payload)}\n\n"


def _sse_error(message):
    def gen():
        yield _sse({"type": "error", "message": message})
    return Response(gen(), mimetype="text/event-stream")


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug, threaded=True)
