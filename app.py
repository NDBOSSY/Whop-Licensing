"""
EA Licensing Server
Handles Whop webhooks + license checks for MetaTrader EAs
Hosted on Railway with PostgreSQL

DATABASE SAFETY GUARANTEES:
  - Flask-Migrate (Alembic) manages all schema changes — tables are NEVER dropped
  - db.create_all() only runs CREATE TABLE IF NOT EXISTS on first boot
  - Railway PostgreSQL is a separate persistent service — it survives every
    code redeployment, crash, container restart, and Railway maintenance window
  - NEVER call db.drop_all() anywhere in this codebase
"""

import os
import hmac
import hashlib
import logging
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate           # Alembic-backed migrations
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()

# ─── App Setup ───────────────────────────────────────────────────────────────

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ── Database ──────────────────────────────────────────────────────────────────
# Railway injects DATABASE_URL automatically (PostgreSQL).
# Locally it falls back to SQLite — no setup needed.

_raw_db_url = os.environ.get("DATABASE_URL", "")

if _raw_db_url:
    # Railway PostgreSQL (fix legacy postgres:// scheme)
    _db_uri     = _raw_db_url.replace("postgres://", "postgresql://")
    _engine_opts = {
        "pool_pre_ping": True,
        "pool_recycle":  300,
        "pool_size":     5,
        "max_overflow":  10,
    }
    logger.info("Using PostgreSQL (Railway)")
else:
    # Local development — SQLite file in the project folder
    _db_uri      = "sqlite:///licenses.db"
    _engine_opts = {}
    logger.info("DATABASE_URL not set — using local SQLite (licenses.db)")

app.config["SQLALCHEMY_DATABASE_URI"]        = _db_uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"]      = _engine_opts

db      = SQLAlchemy(app)
migrate = Migrate(app, db)   # registers `flask db init/migrate/upgrade` commands

# ── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "60 per hour"],
    storage_uri=os.environ.get("REDIS_URL", "memory://"),
)

# ── Secrets ───────────────────────────────────────────────────────────────────
WHOP_WEBHOOK_SECRET = os.environ.get("WHOP_WEBHOOK_SECRET")
API_SECRET_KEY      = os.environ.get("API_SECRET_KEY")


# ─── Model ───────────────────────────────────────────────────────────────────
# Need to add a column later? Run:
#   flask db migrate -m "describe change"
#   flask db upgrade
# This updates the live DB without touching existing rows.

class License(db.Model):
    __tablename__ = "licenses"

    id           = db.Column(db.Integer,     primary_key=True)
    whop_user_id = db.Column(db.String(128), unique=True, nullable=True,  index=True)
    email        = db.Column(db.String(255), unique=True, nullable=True,  index=True)
    license_key  = db.Column(db.String(128), unique=True, nullable=True,  index=True)
    status       = db.Column(db.String(32),  nullable=False, default="active")  # active | cancelled | expired
    plan_id      = db.Column(db.String(128), nullable=True)
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    updated_at   = db.Column(db.DateTime,
                             default=lambda:  datetime.now(timezone.utc),
                             onupdate=lambda: datetime.now(timezone.utc))

    def is_active(self):
        return self.status == "active"

    def to_dict(self):
        return {
            "whop_user_id": self.whop_user_id,
            "email":        self.email,
            "license_key":  self.license_key,
            "status":       self.status,
            "plan_id":      self.plan_id,
            "created_at":   self.created_at.isoformat() if self.created_at else None,
            "updated_at":   self.updated_at.isoformat() if self.updated_at else None,
        }


# ─── Safe DB Init on Every Boot ──────────────────────────────────────────────
# create_all() = CREATE TABLE IF NOT EXISTS — completely safe to run on every
# deployment. It will NEVER drop, truncate, or alter any existing table or row.
# Existing data is always preserved.

def safe_init_db():
    with app.app_context():
        db.create_all()
        count = License.query.count()
        logger.info(f"✓ Database ready — licenses table has {count} existing row(s)")

safe_init_db()


# ─── Helpers ─────────────────────────────────────────────────────────────────

def verify_whop_signature(payload_bytes: bytes, sig_header: str) -> bool:
    """Verify HMAC-SHA256 signature Whop attaches to every webhook."""
    if not WHOP_WEBHOOK_SECRET:
        logger.warning("WHOP_WEBHOOK_SECRET not set — skipping signature check (set it!)")
        return True
    if not sig_header:
        return False
    expected = hmac.new(
        WHOP_WEBHOOK_SECRET.encode(),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    received = sig_header.replace("sha256=", "")
    return hmac.compare_digest(expected, received)


def upsert_license(whop_user_id: str, email: str, plan_id: str, status: str):
    """Insert or update — never deletes any row."""
    record = None
    if whop_user_id:
        record = License.query.filter_by(whop_user_id=whop_user_id).first()
    if not record and email:
        record = License.query.filter_by(email=email).first()

    if record:
        record.status     = status
        record.plan_id    = plan_id
        record.updated_at = datetime.now(timezone.utc)
        if email and not record.email:
            record.email = email
        if whop_user_id and not record.whop_user_id:
            record.whop_user_id = whop_user_id
    else:
        record = License(
            whop_user_id = whop_user_id or None,
            email        = email        or None,
            plan_id      = plan_id,
            status       = status,
        )
        db.session.add(record)

    db.session.commit()
    logger.info(f"Upserted → user_id={whop_user_id} email={email} status={status}")
    return record


def require_admin(req) -> bool:
    token = req.headers.get("X-Admin-Key", "")
    return bool(token) and token == os.environ.get("ADMIN_KEY", "")


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Railway health probe — confirms app AND database are alive."""
    try:
        count = License.query.count()
        return jsonify({
            "status":    "ok",
            "db":        "connected",
            "licenses":  count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Health check DB error: {e}")
        return jsonify({"status": "error", "detail": str(e)}), 500


# ── 1. Whop Webhook ──────────────────────────────────────────────────────────

@app.route("/webhook/whop", methods=["POST"])
def whop_webhook():
    """
    Receives events from Whop on every purchase / cancellation.

    Active events  → status = active
      membership.went_valid
      payment.succeeded
      membership.created

    Inactive events → status = cancelled / expired
      membership.went_invalid
      membership.cancelled
      membership.expired
    """
    payload_bytes = request.get_data()
    sig_header    = request.headers.get("X-Whop-Signature", "")

    if not verify_whop_signature(payload_bytes, sig_header):
        logger.warning("Webhook rejected — bad signature")
        return jsonify({"error": "invalid signature"}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid JSON"}), 400

    event_type   = data.get("event", "")
    membership   = data.get("data", {})
    user_obj     = membership.get("user", {})
    whop_user_id = str(user_obj.get("id") or membership.get("user_id") or "")
    email        = (user_obj.get("email") or membership.get("email") or "").strip().lower()
    plan_id      = membership.get("plan_id") or membership.get("product_id") or ""

    logger.info(f"Whop event: {event_type} | user={whop_user_id} email={email}")

    if not whop_user_id and not email:
        logger.warning("Webhook missing user identity — ignored")
        return jsonify({"warning": "no user identity"}), 200

    ACTIVE   = {"membership.went_valid", "payment.succeeded", "membership.created"}
    INACTIVE = {"membership.went_invalid", "membership.cancelled"}
    EXPIRED  = {"membership.expired"}

    if event_type in ACTIVE:
        upsert_license(whop_user_id, email, plan_id, "active")
    elif event_type in INACTIVE:
        upsert_license(whop_user_id, email, plan_id, "cancelled")
    elif event_type in EXPIRED:
        upsert_license(whop_user_id, email, plan_id, "expired")
    else:
        logger.info(f"Unhandled event '{event_type}' — ignored")

    return jsonify({"received": True}), 200


# ── 2. License Check (EA calls this on startup) ───────────────────────────────

@app.route("/check-license", methods=["POST"])
@limiter.limit("30 per minute")
def check_license():
    """
    EA sends:
      {
        "api_key":        "YOUR_API_SECRET_KEY",
        "account_number": "12345678",
        "email":          "trader@example.com"
      }

    Response:
      { "valid": true,  "status": "active"    }   → EA runs
      { "valid": false, "status": "cancelled" }   → EA stops
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"valid": False, "status": "bad_request"}), 400

    if data.get("api_key") != API_SECRET_KEY:
        logger.warning(f"Bad API key from {get_remote_address()}")
        return jsonify({"valid": False, "status": "unauthorized"}), 401

    email        = (data.get("email",       "") or "").strip().lower()
    license_key  = (data.get("license_key", "") or "").strip()
    account_num  =  data.get("account_number", "?")

    if not email and not license_key:
        return jsonify({"valid": False, "status": "missing_identity"}), 400

    record = None
    if license_key:
        record = License.query.filter_by(license_key=license_key).first()
    if not record and email:
        record = License.query.filter_by(email=email).first()

    if not record:
        logger.info(f"FAIL (not found) | email={email} acct={account_num}")
        return jsonify({"valid": False, "status": "not_found"}), 200

    valid = record.is_active()
    logger.info(f"{'PASS' if valid else 'FAIL'} | email={email} status={record.status} acct={account_num}")
    return jsonify({"valid": valid, "status": record.status}), 200


# ── 3. Admin Routes ───────────────────────────────────────────────────────────

@app.route("/admin/licenses", methods=["GET"])
def admin_list():
    if not require_admin(request):
        return jsonify({"error": "forbidden"}), 403
    records = License.query.order_by(License.created_at.desc()).limit(500).all()
    return jsonify([r.to_dict() for r in records]), 200


@app.route("/admin/licenses", methods=["POST"])
def admin_create():
    """Manually add a license (testers, manual sales, freebies)."""
    if not require_admin(request):
        return jsonify({"error": "forbidden"}), 403
    data  = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "email required"}), 400
    record = upsert_license(
        whop_user_id = data.get("whop_user_id", ""),
        email        = email,
        plan_id      = data.get("plan_id", "manual"),
        status       = data.get("status", "active"),
    )
    return jsonify(record.to_dict()), 201


@app.route("/admin/licenses/<identifier>", methods=["PATCH"])
def admin_update(identifier):
    """Update a license by email, whop_user_id, or license_key."""
    if not require_admin(request):
        return jsonify({"error": "forbidden"}), 403
    record = (
        License.query.filter_by(email=identifier).first()
        or License.query.filter_by(whop_user_id=identifier).first()
        or License.query.filter_by(license_key=identifier).first()
    )
    if not record:
        return jsonify({"error": "not found"}), 404
    new_status = (request.get_json(silent=True) or {}).get("status")
    if new_status not in ("active", "cancelled", "expired"):
        return jsonify({"error": "status must be: active, cancelled, or expired"}), 400
    record.status     = new_status
    record.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    logger.info(f"Admin updated '{identifier}' → {new_status}")
    return jsonify(record.to_dict()), 200


# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
