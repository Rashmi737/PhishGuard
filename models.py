"""
PhishGuard – Database models (SQLite via Flask-SQLAlchemy).

Two tables:
    users   – registered accounts (passwords are stored ONLY as hashes)
    scans   – one row per URL analysis, owned by exactly one user
"""

from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utcnow():
    """Timezone-aware UTC now, stored as a naive datetime for SQLite."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(120), nullable=False)
    email         = db.Column(db.String(254), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at    = db.Column(db.DateTime, nullable=False, default=utcnow)

    # One user -> many scans. Deleting a user deletes their scans.
    scans = db.relationship(
        "Scan",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="Scan.scanned_at.desc()",
    )

    def __repr__(self):  # never include password material
        return f"<User {self.email}>"


class Scan(db.Model):
    __tablename__ = "scans"

    id                  = db.Column(db.Integer, primary_key=True)
    user_id             = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    scanned_url         = db.Column(db.String(2048), nullable=False)
    risk_score          = db.Column(db.Integer, nullable=False)
    risk_category       = db.Column(db.String(20), nullable=False)
    detected_indicators = db.Column(db.Text, nullable=False, default="[]")  # JSON array
    scanned_at          = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    def __repr__(self):
        return f"<Scan {self.scanned_url[:40]!r} score={self.risk_score}>"


def risk_level_for(score):
    """Mirror of the detector's thresholds, used for UI/CSS classes."""
    try:
        score = int(score)
    except (TypeError, ValueError):
        score = 0
    if score < 30:
        return "low"
    if score < 70:
        return "medium"
    return "high"
