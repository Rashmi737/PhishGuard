"""
PhishGuard - Flask backend (Day 2).

Day 2 adds on top of Day 1:
  * User authentication (register / login / logout) with Flask-Login
  * SQLite persistence via Flask-SQLAlchemy (users + scan history)
  * /history    - paginated, user-scoped scan history (max 50 / page)
  * /analytics  - Chart.js dashboard fed by /api/analytics (real SQLite data)
  * /api/recent - user-scoped recent scans (replaces in-memory deque)
  * CSRF protection on every state-changing route

The application NEVER visits, fetches or renders the submitted URL.
"""

import hmac
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from flask import (
    Flask, flash, jsonify, redirect, render_template, request, session, url_for,
)
from flask_login import (
    LoginManager, current_user, login_required, login_user, logout_user,
)
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import func

from detector import analyze_url
from models import Scan, User, db, risk_level_for, utcnow

import os

app = Flask(__name__)

# --------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------
instance_dir = os.path.join(app.root_path, "instance")
os.makedirs(instance_dir, exist_ok=True)

# Secret key: read from PHISHGUARD_SECRET_KEY environment variable.
# In production, a secure secret key is strictly required.
# In local development, an ephemeral random key is generated if none is configured.
is_production = (
    os.environ.get("FLASK_ENV", "").lower() == "production"
    or os.environ.get("ENV", "").lower() == "production"
)
secret_key = os.environ.get("PHISHGUARD_SECRET_KEY")
if not secret_key:
    if is_production:
        raise RuntimeError(
            "PHISHGUARD_SECRET_KEY environment variable is required in production."
        )
    secret_key = secrets.token_hex(32)

app.config["SECRET_KEY"] = secret_key
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(instance_dir, "phishguard.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Session / cookie hardening (HTTP locally; set SESSION_COOKIE_SECURE=True behind HTTPS)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=1)

# Reject request bodies larger than 16 KB - a URL is at most 2048 chars.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "info"
login_manager.init_app(app)

with app.app_context():
    db.create_all()

# --------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
NAME_RE = re.compile(r"^[A-Za-z\u00C0-\u024F][A-Za-z\u00C0-\u024F .'-]{1,119}$")
# Password: 8-128 chars, at least one letter and one digit.
PASSWORD_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{8,128}$")


def _validate_name(name):
    name = (name or "").strip()
    if not name or len(name) < 2:
        return None, "Please enter your full name (at least 2 characters)."
    if not NAME_RE.match(name):
        return None, "Name may only contain letters, spaces, hyphens and apostrophes."
    return name, None


def _validate_email(email):
    email = (email or "").strip().lower()
    if not email or len(email) > 254 or not EMAIL_RE.match(email):
        return None, "Please enter a valid email address."
    return email, None


def _validate_password(password):
    password = password or ""
    if not PASSWORD_RE.match(password):
        return "Password must be 8-128 characters and include at least one letter and one number."
    return None


# --------------------------------------------------------------------
# CSRF protection (synchronizer token pattern, no extra dependencies)
# --------------------------------------------------------------------
def _csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


def _csrf_ok():
    token = session.get("_csrf_token")
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    return bool(token and sent) and hmac.compare_digest(token, sent)


def _csrf_fail():
    if request.is_json or request.path.startswith(("/scan", "/api/")):
        return jsonify({"success": False,
                        "error": "Invalid or missing CSRF token. Please refresh and try again."}), 400
    flash("Security check failed. Please try again.", "error")
    return redirect(request.referrer or url_for("index"))


# --------------------------------------------------------------------
# Security headers - applied to every response.
# --------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self';"
    )
    return response


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


@app.context_processor
def inject_globals():
    ctx = {"csrf_token": _csrf_token, "total_scans": 0}
    if current_user.is_authenticated:
        try:
            ctx["total_scans"] = Scan.query.filter_by(user_id=current_user.id).count()
        except Exception:
            ctx["total_scans"] = 0
    return ctx


# --------------------------------------------------------------------
# Scan <-> JSON helpers
# --------------------------------------------------------------------
def _scan_public_dict(scan, url_max=64):
    """Small, safe summary for recent-scans lists and the UI."""
    url = scan.scanned_url or ""
    if len(url) > url_max:
        url = url[: url_max - 3] + "..."
    try:
        host = urlparse(scan.scanned_url).hostname or ""
    except Exception:
        host = ""
    return {
        "id": scan.id,
        "url": url,
        "domain": host,
        "score": scan.risk_score,
        "category": scan.risk_category,
        "risk_level": risk_level_for(scan.risk_score),
        "scanned_at": int(scan.scanned_at.replace(tzinfo=timezone.utc).timestamp())
                       if scan.scanned_at else 0,
    }


def _parse_indicators(raw):
    try:
        data = json.loads(raw or "[]")
        return data if isinstance(data, list) else []
    except (ValueError, TypeError):
        return []


def _user_scans():
    """All scans for the current user, newest first (SQLAlchemy query)."""
    return Scan.query.filter_by(user_id=current_user.id).order_by(Scan.scanned_at.desc())


def _safe_next():
    """Only allow relative redirect targets (blocks open redirects)."""
    nxt = request.args.get("next", "") or ""
    if nxt.startswith("/") and not nxt.startswith("//"):
        return nxt
    return url_for("index")


def _save_scan(result):
    """
    Persist one analysis for the logged-in user.
    Returns the Scan row, or None on failure (details are logged server-side).
    """
    try:
        scan = Scan(
            user_id=current_user.id,
            scanned_url=(result.get("normalized_url") or result.get("url") or "")[:2048],
            risk_score=int(result.get("score", 0)),
            risk_category=str(result.get("category", "Unknown"))[:20],
            detected_indicators=json.dumps(result.get("indicators", [])),
            scanned_at=utcnow(),
        )
        db.session.add(scan)
        db.session.commit()
        return scan
    except Exception as exc:  # noqa: BLE001 - never leak DB details to the client
        db.session.rollback()
        app.logger.error("Failed to save scan: %s", exc)
        return None


# --------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = {"name": "", "email": ""}
    error = None

    if request.method == "POST":
        if not _csrf_ok():
            return _csrf_fail()

        name_in = request.form.get("name", "")
        email_in = request.form.get("email", "")
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        form["name"] = (name_in or "").strip()[:120]
        form["email"] = (email_in or "").strip()[:254]

        name, err = _validate_name(name_in)
        if err:
            error = err
        else:
            email, err = _validate_email(email_in)
            if err:
                error = err
            else:
                pwd_err = _validate_password(password)
                if pwd_err:
                    error = pwd_err
                elif password != confirm:
                    error = "Passwords do not match."
                else:
                    existing = User.query.filter_by(email=email).first()
                    if existing:
                        error = "An account with this email already exists."
                    else:
                        user = User(
                            name=name,
                            email=email,
                            password_hash=generate_password_hash(password),
                        )
                        try:
                            db.session.add(user)
                            db.session.commit()
                        except Exception:
                            db.session.rollback()
                            error = "Could not create the account. Please try again."
                        else:
                            login_user(user)
                            flash(f"Welcome to PhishGuard, {user.name.split()[0]}!", "success")
                            return redirect(url_for("index"))

    return render_template("register.html", form=form, error=error, active_page="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    email_in = request.form.get("email", "") if request.method == "POST" else ""
    error = None

    if request.method == "POST":
        if not _csrf_ok():
            return _csrf_fail()

        email, err = _validate_email(email_in)
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first() if not err else None

        # Constant-shape failure path - no account enumeration, no oracle.
        if user is None or not check_password_hash(user.password_hash, password or ""):
            error = "Invalid email or password."
        else:
            login_user(user)
            session.permanent = True
            flash(f"Welcome back, {user.name.split()[0]}!", "success")
            return redirect(_safe_next())

    return render_template("login.html",
                           email=(email_in or "").strip()[:254],
                           error=error,
                           active_page="login")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    if not _csrf_ok():
        return _csrf_fail()
    logout_user()
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


# --------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    return render_template("index.html", active_page="home")


@app.route("/history")
@login_required
def history():
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1

    pagination = _user_scans().paginate(page=page, per_page=50, error_out=False)
    items = [
        {
            "id": s.id,
            "url": s.scanned_url,
            "score": s.risk_score,
            "category": s.risk_category,
            "risk_level": risk_level_for(s.risk_score),
            "indicators": _parse_indicators(s.detected_indicators),
            "scanned_at": s.scanned_at,
        }
        for s in pagination.items
    ]
    return render_template(
        "history.html",
        active_page="history",
        scans=items,
        pagination=pagination,
        total_scans=pagination.total,
    )


@app.route("/analytics")
@login_required
def analytics():
    return render_template("analytics.html", active_page="analytics")


# --------------------------------------------------------------------
# JSON API
# --------------------------------------------------------------------
@app.route("/api/recent", methods=["GET"])
@login_required
def api_recent():
    scans = [_scan_public_dict(s, url_max=72) for s in _user_scans().limit(6).all()]
    return jsonify({"success": True, "scans": scans})


@app.route("/api/analytics", methods=["GET"])
@login_required
def api_analytics():
    base = Scan.query.filter_by(user_id=current_user.id)

    total = base.count()
    low = base.filter(Scan.risk_score < 30).count()
    medium = base.filter(Scan.risk_score >= 30, Scan.risk_score < 70).count()
    high = base.filter(Scan.risk_score >= 70).count()
    avg_score = db.session.query(func.avg(Scan.risk_score)).filter(
        Scan.user_id == current_user.id).scalar()
    avg_score = round(float(avg_score), 1) if avg_score is not None else 0.0

    # Scans over the last 7 days (inclusive of today)
    today = datetime.now(timezone.utc).date()
    start = datetime(today.year, today.month, today.day) - timedelta(days=6)
    rows = (
        Scan.query.filter(Scan.user_id == current_user.id, Scan.scanned_at >= start)
        .with_entities(Scan.scanned_at, Scan.risk_score)
        .all()
    )
    per_day = {}
    for when, _score in rows:
        per_day[when.date()] = per_day.get(when.date(), 0) + 1

    daily = []
    for offset in range(6, -1, -1):
        day = today - timedelta(days=offset)
        daily.append({
            "label": day.strftime("%a %d"),
            "count": per_day.get(day, 0),
        })

    return jsonify({
        "success": True,
        "total": total,
        "low": low,
        "medium": medium,
        "high": high,
        "avg_score": avg_score,
        "daily": daily,
    })


@app.route("/scan", methods=["POST"])
@login_required
def scan():
    if not _csrf_ok():
        return _csrf_fail()

    # Only JSON requests are accepted - this blocks form/simple-request CSRF.
    if not request.is_json:
        return jsonify({"success": False, "error": "Expected a JSON request body."}), 400

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "Malformed JSON body."}), 400

    url = data.get("url", "")
    result = analyze_url(url)

    if not result["success"]:
        # 422 = syntactically valid request carrying an invalid/unsafe URL.
        return jsonify({"success": False, "error": result["error"]}), 422

    saved = _save_scan(result)
    if saved is None:
        return jsonify({"success": False,
                        "error": "Scan completed but could not be saved. Please try again."}), 500

    result["scan_id"] = saved.id
    result["recent_scans"] = [
        _scan_public_dict(s, url_max=72) for s in _user_scans().limit(6).all()
    ]
    result["total_scans"] = _user_scans().count()
    return jsonify(result), 200


# --------------------------------------------------------------------
# Error handlers - never leak filesystem paths, stack traces or config.
# --------------------------------------------------------------------
@app.errorhandler(404)
def not_found(_):
    if request.path.startswith(("/api/", "/scan")):
        return jsonify({"success": False, "error": "The requested resource was not found."}), 404
    return render_template("404.html", active_page=""), 404


@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({"success": False, "error": "Method not allowed."}), 405


@app.errorhandler(413)
def payload_too_large(_):
    return jsonify({"success": False, "error": "Request body too large."}), 413


@app.errorhandler(500)
def internal_error(_):
    db.session.rollback()
    return jsonify({"success": False, "error": "An unexpected server error occurred."}), 500


if __name__ == "__main__":
    # Debug mode is disabled by default and read from FLASK_DEBUG.
    # It is never enabled in production environments.
    debug_mode = (
        not is_production
        and os.environ.get("FLASK_DEBUG", "0").strip().lower() in ("1", "true", "yes")
    )
    app.run(debug=debug_mode, host="127.0.0.1", port=5000)



