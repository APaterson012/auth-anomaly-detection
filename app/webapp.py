import os
import time
import json
from datetime import datetime, timezone
from flask import Flask, request, render_template, redirect, make_response, send_file, abort

app = Flask(__name__)

AUTH_LOG_PATH = os.getenv("AUTH_LOG_PATH", "/data/auth.log")
ALERTS_PATH = os.getenv("ALERTS_PATH", "/output/sample_output.json")

# Shareable “secret link” token:
# Users must visit: http(s)://host:port/?token=YOUR_TOKEN
ACCESS_TOKEN = os.getenv("AUTHLAB_ACCESS_TOKEN", "")

# Demo credentials (you can move these to env later)
DEMO_USERS = {
    "alice": "Password123!",
    "admin": "Admin123!",
}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def append_log(ip: str, user: str, status: str):
    os.makedirs(os.path.dirname(AUTH_LOG_PATH), exist_ok=True)
    line = f"{now_iso()}, IP={ip}, user={user}, status={status}\n"
    with open(AUTH_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line)


def require_token():
    """
    Gate all pages behind a shareable token.
    - If AUTHLAB_ACCESS_TOKEN is empty, gate is disabled (NOT recommended for public exposure).
    - If user visits with ?token=..., we set a cookie so they don’t need it again.
    """
    if not ACCESS_TOKEN:
        return None  # gate disabled

    # already authenticated?
    if request.cookies.get("authlab_access") == ACCESS_TOKEN:
        return None

    # token via query param
    token = request.args.get("token", "")
    if token and token == ACCESS_TOKEN:
        resp = make_response(redirect(request.path or "/"))
        resp.set_cookie("authlab_access", ACCESS_TOKEN, max_age=60 * 60 * 12, httponly=True, samesite="Lax")
        return resp

    # not authorised
    return abort(403)


@app.before_request
def _gate():
    # allow health checks without token if you want
    if request.path == "/health":
        return None
    return require_token()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def index():
    # Show login form + demo controls
    return render_template("login.html", msg=None)


@app.post("/login")
def login():
    user = (request.form.get("user") or "").strip()
    pw = request.form.get("password") or ""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")

    ok = (user in DEMO_USERS and DEMO_USERS[user] == pw)
    append_log(ip=ip, user=user if user else "unknown", status="SUCCESS" if ok else "FAIL")

    return render_template("login.html", msg="Login successful ✅" if ok else "Invalid credentials ❌")


@app.post("/replay")
def replay():
    """
    Replay attack simulation by generating log events.
    Types:
      - bruteforce: same user fails N times
      - stuffing: multiple users fail from same IP
    """
    attack_type = (request.form.get("type") or "bruteforce").strip()
    count = int(request.form.get("count") or "10")
    count = max(1, min(count, 200))  # safety bound

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")

    if attack_type == "bruteforce":
        target_user = (request.form.get("user") or "admin").strip() or "admin"
        for _ in range(count):
            append_log(ip=ip, user=target_user, status="FAIL")
            time.sleep(0.02)

    elif attack_type == "stuffing":
        users = ["admin", "alice", "bob", "charlie", "dave", "eve", "frank", "grace", "heidi"]
        for i in range(count):
            append_log(ip=ip, user=users[i % len(users)], status="FAIL")
            time.sleep(0.02)

    else:
        return render_template("login.html", msg="Unknown replay type ❌")

    return render_template("login.html", msg=f"Replay complete ✅ Generated {count} events ({attack_type}).")


@app.get("/api/alerts/count")
def alerts_count():
    """
    Reads the engine’s alerts JSON and returns a live counter for the UI.
    """
    if not os.path.exists(ALERTS_PATH):
        return {"total": 0, "by_type": {}, "source": ALERTS_PATH}

    try:
        with open(ALERTS_PATH, "r", encoding="utf-8") as f:
            alerts = json.load(f)
    except Exception:
        return {"total": 0, "by_type": {}, "source": ALERTS_PATH, "error": "Could not parse alerts"}

    by_type = {}
    for a in alerts:
        t = a.get("type", "Unknown")
        by_type[t] = by_type.get(t, 0) + 1

    return {"total": len(alerts), "by_type": by_type, "source": ALERTS_PATH}


@app.get("/download/auth.log")
def download_auth_log():
    if not os.path.exists(AUTH_LOG_PATH):
        abort(404)
    return send_file(AUTH_LOG_PATH, as_attachment=True, download_name="auth.log")


@app.get("/download/sample.log")
def download_sample_log():
    sample_path = os.path.join(os.path.dirname(__file__), "..", "example_logs", "auth_example.log")
    sample_path = os.path.abspath(sample_path)
    if not os.path.exists(sample_path):
        abort(404)
    return send_file(sample_path, as_attachment=True, download_name="auth_example.log")