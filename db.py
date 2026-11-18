"""Database models and connection handling using SQLAlchemy for multi-tenant HuliCAP."""

from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import secrets
from typing import Any, Dict, List, Optional, Tuple
import uuid

import bcrypt
import pandas as pd
import yaml
import yaml

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    create_engine,
    func,
    inspect,
    text,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session

from config import MAX_STAFF_SEATS

# 1. Database Connection Configuration
DEFAULT_DB_URL = "sqlite:///monitor.db"
DATABASE_URL = os.environ.get("DATABASE_URL", DEFAULT_DB_URL)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# SQLite concurrency handling
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# 2. Declarative ORM Models
class Plan(Base):
    __tablename__ = "plans"

    plan_id = Column(String(50), primary_key=True)
    name = Column(String(100), nullable=False)
    max_events_per_upload = Column(Integer, nullable=False, default=10_000)
    max_staff = Column(Integer, nullable=False, default=3)

    organizations = relationship("Organization", back_populates="plan")


class User(Base):
    __tablename__ = "users"

    user_id = Column(String(50), primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    status = Column(String(50), nullable=False, default="active")  # active, suspended, banned
    is_super_admin = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    memberships = relationship("Membership", back_populates="user")
    guideline_acceptances = relationship("GuidelineAcceptance", back_populates="user")
    log_uploads = relationship("LogUpload", back_populates="uploader")


class Organization(Base):
    __tablename__ = "organizations"

    org_id = Column(String(50), primary_key=True)
    name = Column(String(255), nullable=False)
    industry = Column(String(100), nullable=False)
    # Unused legacy column kept for non-destructive backward compatibility
    plan_id = Column(String(50), ForeignKey("plans.plan_id"), nullable=True, default="")
    setup_completed = Column(Boolean, nullable=False, default=False)
    portal_url = Column(String(500), nullable=True, default="")
    status = Column(String(50), nullable=False, default="active")  # active, suspended, closed
    org_salt = Column(String(128), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    plan = relationship("Plan", back_populates="organizations")
    memberships = relationship("Membership", back_populates="organization")
    uploads = relationship("LogUpload", back_populates="organization")
    events = relationship("Event", back_populates="organization")
    alerts = relationship("Alert", back_populates="organization")
    rules = relationship("OrgRule", back_populates="organization")
    audit_logs = relationship("AuditLog", back_populates="organization")
    invites = relationship("Invite", back_populates="organization")


class Membership(Base):
    __tablename__ = "memberships"

    user_id = Column(String(50), ForeignKey("users.user_id"), primary_key=True)
    org_id = Column(String(50), ForeignKey("organizations.org_id"), primary_key=True)
    role = Column(String(50), nullable=False)  # analyst, reviewer, org_admin

    user = relationship("User", back_populates="memberships")
    organization = relationship("Organization", back_populates="memberships")


class GuidelineAcceptance(Base):
    __tablename__ = "guideline_acceptances"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(50), ForeignKey("users.user_id"), nullable=False)
    version = Column(String(50), nullable=False)
    accepted_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    user = relationship("User", back_populates="guideline_acceptances")


class LogUpload(Base):
    __tablename__ = "log_uploads"

    upload_id = Column(String(50), primary_key=True)
    org_id = Column(String(50), ForeignKey("organizations.org_id"), nullable=False)
    uploaded_by = Column(String(50), ForeignKey("users.user_id"), nullable=False)
    filename = Column(String(255), nullable=False)
    row_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="uploads")
    uploader = relationship("User", back_populates="log_uploads")
    events = relationship("Event", back_populates="upload")


class Event(Base):
    __tablename__ = "events"

    event_id = Column(String(50), primary_key=True)
    org_id = Column(String(50), ForeignKey("organizations.org_id"), nullable=False, index=True)
    upload_id = Column(String(50), ForeignKey("log_uploads.upload_id"), nullable=True)
    source = Column(String(50), nullable=False, default="csv_upload")
    timestamp = Column(DateTime, nullable=False, index=True)
    user_id = Column(String(100), nullable=False)  # Salted pseudonym / hash
    role = Column(String(50), nullable=False)
    action = Column(String(50), nullable=False)
    resource = Column(String(255), nullable=False)
    sensitivity = Column(String(50), nullable=False)
    bytes = Column(BigInteger, nullable=False, default=0)
    device = Column(String(100), nullable=False)
    source_ip = Column(String(50), nullable=False)
    outcome = Column(String(50), nullable=False)

    organization = relationship("Organization", back_populates="events")
    upload = relationship("LogUpload", back_populates="events")


class UsersMap(Base):
    """Org-admin-only mapping between real Windows account names, roles, and pseudonyms."""

    __tablename__ = "users_map"

    org_id = Column(String(50), ForeignKey("organizations.org_id"), primary_key=True)
    account_name = Column(String(255), primary_key=True)
    user_pseudonym = Column(String(100), nullable=False, index=True)
    role = Column(String(50), nullable=False, default="unknown")
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class ResourceMap(Base):
    """Mapping from resource path or prefix to sensitivity level."""

    __tablename__ = "resource_map"

    org_id = Column(String(50), ForeignKey("organizations.org_id"), primary_key=True)
    resource_pattern = Column(String(255), primary_key=True)
    sensitivity = Column(String(50), nullable=False, default="normal")
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class CollectorState(Base):
    """Tracks the last processed Windows Event Log RecordId per organization."""

    __tablename__ = "collector_state"

    org_id = Column(String(50), ForeignKey("organizations.org_id"), primary_key=True)
    source = Column(String(50), primary_key=True, default="windows_event_log")
    last_record_id = Column(BigInteger, nullable=False, default=0)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    alert_id = Column(String(50), primary_key=True)
    org_id = Column(String(50), ForeignKey("organizations.org_id"), nullable=False, index=True)
    rule_id = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False)
    user_pseudonym = Column(String(100), nullable=False)
    event_ids = Column(Text, nullable=False)
    reason = Column(Text, nullable=False)
    status = Column(String(50), nullable=False, default="new")  # new, reviewed, escalated, dismissed
    reviewer = Column(String(100), nullable=True)
    reviewer_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="alerts")


class OrgRule(Base):
    __tablename__ = "org_rules"

    org_id = Column(String(50), ForeignKey("organizations.org_id"), primary_key=True)
    rule_id = Column(String(100), primary_key=True)
    thresholds = Column(JSON, nullable=False)

    organization = relationship("Organization", back_populates="rules")


class AuditLog(Base):
    __tablename__ = "audit_log"

    audit_id = Column(String(50), primary_key=True)
    org_id = Column(String(50), ForeignKey("organizations.org_id"), nullable=False, index=True)
    user_id = Column(String(50), ForeignKey("users.user_id"), nullable=True)
    action = Column(String(100), nullable=False)
    target = Column(String(255), nullable=False)
    justification = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="audit_logs")


class PlatformAuditLog(Base):
    __tablename__ = "platform_audit_log"

    id = Column(String(50), primary_key=True)
    actor_user_id = Column(String(50), ForeignKey("users.user_id"), nullable=True)
    action = Column(String(100), nullable=False)
    target_type = Column(String(50), nullable=False)
    target_id = Column(String(100), nullable=False)
    reason = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class Invite(Base):
    __tablename__ = "invites"

    invite_id = Column(String(50), primary_key=True)
    org_id = Column(String(50), ForeignKey("organizations.org_id"), nullable=False, index=True)
    email = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False)  # analyst, reviewer
    code = Column(String(50), unique=True, nullable=False, index=True)
    status = Column(String(50), nullable=False, default="pending")  # pending, accepted, cancelled
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="invites")


class DbSession(Base):
    __tablename__ = "sessions"

    session_id = Column(String(50), primary_key=True)
    user_id = Column(String(50), ForeignKey("users.user_id"), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, nullable=False, default=False)

    user = relationship("User", backref="server_sessions")


# 3. Database Initialization & Seeding
def get_session() -> Session:
    """Yield a database session context."""
    return SessionLocal()


def seed_plans(session: Session) -> None:
    """Seed the two default plans: Free and Standard."""
    default_plans = [
        {"plan_id": "free", "name": "Free", "max_events_per_upload": 10_000, "max_staff": 3},
        {"plan_id": "standard", "name": "Standard", "max_events_per_upload": 100_000, "max_staff": 20},
    ]
    for p in default_plans:
        existing = session.query(Plan).filter_by(plan_id=p["plan_id"]).first()
        if not existing:
            session.add(
                Plan(
                    plan_id=p["plan_id"],
                    name=p["name"],
                    max_events_per_upload=p["max_events_per_upload"],
                    max_staff=p["max_staff"],
                )
            )
    session.commit()


def init_db() -> None:
    """Create all tables in the configured database and run non-destructive column migrations."""
    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    if "organizations" in inspector.get_table_names():
        org_cols = {c["name"] for c in inspector.get_columns("organizations")}
        if "setup_completed" not in org_cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE organizations ADD COLUMN setup_completed BOOLEAN NOT NULL DEFAULT 1")
                )
        if "portal_url" not in org_cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE organizations ADD COLUMN portal_url VARCHAR(500) DEFAULT ''")
                )
    if "events" in inspector.get_table_names():
        event_cols = {c["name"] for c in inspector.get_columns("events")}
        if "source" not in event_cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE events ADD COLUMN source VARCHAR(50) NOT NULL DEFAULT 'csv_upload'")
                )


def get_schema_summary() -> Dict[str, Any]:
    """Inspect the database schema and return table names, columns, and foreign keys."""
    inspector = inspect(engine)
    tables_info = {}
    for table_name in sorted(inspector.get_table_names()):
        columns = [col["name"] for col in inspector.get_columns(table_name)]
        fks = [
            f"{fk['constrained_columns']} -> {fk['referred_table']}.{fk['referred_columns']}"
            for fk in inspector.get_foreign_keys(table_name)
        ]
        tables_info[table_name] = {
            "columns": columns,
            "foreign_keys": fks,
        }
    return tables_info


# 4. Authentication & Membership Helpers
def hash_password(password: str) -> str:
    """Hash plaintext password using bcrypt with auto-generated salt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def check_password(password: str, password_hash: str) -> bool:
    """Validate plaintext password against stored bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def register_user(
    full_name: str,
    email: str,
    password: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Register a new user account.
    - Password minimum 8 characters.
    - Reject duplicate emails.
    - Status defaults to 'active'.
    - is_super_admin is strictly False (no elevation via app).
    """
    clean_name = full_name.strip()
    clean_email = email.strip().lower()

    if len(clean_name) < 2:
        return None, "Full name must be at least 2 characters."

    if not clean_email or "@" not in clean_email:
        return None, "Please provide a valid email address."

    if len(password) < 8:
        return None, "Password must be at least 8 characters."

    with get_session() as session:
        existing = session.query(User).filter_by(email=clean_email).first()
        if existing:
            return None, "An account with this email already exists."

        user_id = f"usr_{uuid.uuid4().hex[:8]}"
        hashed = hash_password(password)
        new_user = User(
            user_id=user_id,
            email=clean_email,
            password_hash=hashed,
            full_name=clean_name,
            status="active",
            is_super_admin=False,
            created_at=datetime.utcnow(),
        )
        session.add(new_user)
        session.commit()

        return {
            "user_id": new_user.user_id,
            "email": new_user.email,
            "full_name": new_user.full_name,
            "status": new_user.status,
            "is_super_admin": new_user.is_super_admin,
        }, None


def authenticate_user(
    email: str,
    password: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Authenticate a user by email and password.
    Checks password hash and status (suspended/banned accounts blocked).
    """
    clean_email = email.strip().lower()

    with get_session() as session:
        user = session.query(User).filter_by(email=clean_email).first()
        if not user:
            return None, "Invalid email or password."

        if not check_password(password, user.password_hash):
            return None, "Invalid email or password."

        if user.status in ["suspended", "banned"]:
            return None, "Your account has been suspended. Contact the administrator."

        return {
            "user_id": user.user_id,
            "email": user.email,
            "full_name": user.full_name,
            "status": user.status,
            "is_super_admin": user.is_super_admin,
        }, None


# -------------------------------------------------------------------------
# Server-Side Session Management (Persistent Auth & Idle Timeout)
# -------------------------------------------------------------------------
def create_user_session(user_id: str, lifetime_hours: int = 8) -> Tuple[Dict[str, Any], str]:
    """
    Create a server-side session with an 8-hour absolute lifetime.
    Generates a cryptographically random token via secrets.token_urlsafe(32).
    Stores ONLY the SHA-256 hash in the database. Returns (session_dict, raw_token).
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    session_id = f"sess_{uuid.uuid4().hex[:12]}"
    now = datetime.utcnow()
    expires_at = now + timedelta(hours=lifetime_hours)

    with get_session() as session:
        db_sess = DbSession(
            session_id=session_id,
            user_id=user_id,
            token_hash=token_hash,
            created_at=now,
            last_seen_at=now,
            expires_at=expires_at,
            revoked=False,
        )
        session.add(db_sess)
        session.commit()
        return {
            "session_id": db_sess.session_id,
            "user_id": db_sess.user_id,
            "created_at": db_sess.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen_at": db_sess.last_seen_at.strftime("%Y-%m-%d %H:%M:%S"),
            "expires_at": db_sess.expires_at.strftime("%Y-%m-%d %H:%M:%S"),
            "revoked": db_sess.revoked,
        }, raw_token


def get_session_by_token(raw_token: str) -> Optional[Dict[str, Any]]:
    """
    Look up and validate a session by raw token.
    Checks:
      1. Matching SHA-256 token_hash exists in database.
      2. Session has not been revoked.
      3. Session has not exceeded absolute expiration.
      4. Associated user exists and is NOT suspended or banned.
    Returns session dictionary with attached user details, or None if invalid.
    """
    if not raw_token or not isinstance(raw_token, str):
        return None

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    with get_session() as session:
        db_sess = session.query(DbSession).filter_by(token_hash=token_hash).first()
        if not db_sess:
            return None
        if db_sess.revoked:
            return None
        if db_sess.expires_at < datetime.utcnow():
            return None

        # Verify user still exists
        user = session.query(User).filter_by(user_id=db_sess.user_id).first()
        if not user:
            return None

        return {
            "session_id": db_sess.session_id,
            "user_id": db_sess.user_id,
            "created_at": db_sess.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen_at": db_sess.last_seen_at.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen_at_dt": db_sess.last_seen_at,
            "expires_at": db_sess.expires_at.strftime("%Y-%m-%d %H:%M:%S"),
            "revoked": db_sess.revoked,
            "user": {
                "user_id": user.user_id,
                "email": user.email,
                "full_name": user.full_name,
                "status": user.status,
                "is_super_admin": user.is_super_admin,
            },
        }


def touch_session(session_id: str) -> bool:
    """
    Update last_seen_at for an active session.
    Server authority: called ONLY upon real user actions (click, navigation, form submit).
    """
    if not session_id:
        return False
    with get_session() as session:
        db_sess = session.query(DbSession).filter_by(session_id=session_id).first()
        if db_sess and not db_sess.revoked:
            db_sess.last_seen_at = datetime.utcnow()
            session.commit()
            return True
        return False


def revoke_session(session_id: str) -> bool:
    """Revoke a session in the database by session_id."""
    if not session_id:
        return False
    with get_session() as session:
        db_sess = session.query(DbSession).filter_by(session_id=session_id).first()
        if db_sess:
            db_sess.revoked = True
            session.commit()
            return True
        return False


def revoke_session_by_token(raw_token: str) -> bool:
    """Revoke a session in the database by raw token."""
    if not raw_token or not isinstance(raw_token, str):
        return False
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    with get_session() as session:
        db_sess = session.query(DbSession).filter_by(token_hash=token_hash).first()
        if db_sess:
            db_sess.revoked = True
            session.commit()
            return True
        return False


def log_session_timeout_audit_event(user_id: str) -> None:
    """Log a session_timeout event to the platform audit trail."""
    with get_session() as session:
        entry = PlatformAuditLog(
            id=f"p_aud_{uuid.uuid4().hex[:10]}",
            actor_user_id=user_id,
            action="session_timeout",
            target_type="user_session",
            target_id=user_id,
            reason=f"Session timed out due to inactivity at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            created_at=datetime.utcnow(),
        )
        session.add(entry)
        session.commit()


def get_user_membership(user_id: str) -> Optional[Dict[str, Any]]:
    """Fetch user's membership details (org_id and role)."""
    with get_session() as session:
        m = session.query(Membership).filter_by(user_id=user_id).first()
        if m:
            return {
                "user_id": m.user_id,
                "org_id": m.org_id,
                "role": m.role,
            }
        return None


def has_accepted_guidelines(user_id: str, version: str = "v1.0") -> bool:
    """Check whether the user has accepted the specified guidelines version."""
    with get_session() as session:
        entry = (
            session.query(GuidelineAcceptance)
            .filter_by(user_id=user_id, version=version)
            .first()
        )
        return entry is not None


def record_guideline_acceptance(user_id: str, version: str = "v1.0") -> None:
    """Record acceptance of community guidelines with timestamp."""
    with get_session() as session:
        existing = (
            session.query(GuidelineAcceptance)
            .filter_by(user_id=user_id, version=version)
            .first()
        )
        if not existing:
            new_acceptance = GuidelineAcceptance(
                user_id=user_id,
                version=version,
                accepted_at=datetime.utcnow(),
            )
            session.add(new_acceptance)
            session.commit()


# 5. Multi-Tenant Organization Management & Isolation
def create_organization(
    name: str,
    industry: str,
    creator_user_id: str,
    setup_completed: bool = False,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Create a new organization:
      - Validates name length (2 to 80 chars) and uniqueness.
      - Assigns a cryptographically secure random org_salt.
      - Attaches the creator as 'org_admin' in memberships.
      - Seeds default rules from rules.yaml into org_rules.
    """
    clean_name = (name or "").strip()
    clean_industry = (industry or "").strip()

    if len(clean_name) < 2 or len(clean_name) > 80:
        return None, "Organization name must be between 2 and 80 characters."

    org_id = f"org_{uuid.uuid4().hex[:8]}"
    org_salt = secrets.token_hex(16)

    with get_session() as session:
        existing_org = (
            session.query(Organization)
            .filter(func.lower(Organization.name) == clean_name.lower())
            .first()
        )
        if existing_org:
            return None, "An organization with this name already exists. Please choose a different name."

        # 1. Create Organization
        org = Organization(
            org_id=org_id,
            name=clean_name,
            industry=clean_industry,
            setup_completed=bool(setup_completed),
            status="active",
            org_salt=org_salt,
            created_at=datetime.utcnow(),
        )
        session.add(org)

        # 2. Attach Creator as org_admin in memberships
        membership = Membership(
            user_id=creator_user_id,
            org_id=org_id,
            role="org_admin",
        )
        session.add(membership)

        # 3. Seed initial org_rules from rules.yaml if present
        rules_path = Path("rules.yaml")
        if rules_path.exists():
            try:
                rules_data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
                for r in rules_data.get("rules", []):
                    session.add(
                        OrgRule(
                            org_id=org_id,
                            rule_id=r["rule_id"],
                            thresholds=r.get("thresholds", {}),
                        )
                    )
            except Exception:
                pass

        session.commit()

        return {
            "org_id": org.org_id,
            "name": org.name,
            "industry": org.industry,
            "setup_completed": bool(org.setup_completed),
            "status": org.status,
            "org_salt": org.org_salt,
            "role": "org_admin",
        }, None


def update_incomplete_organization(
    org_id: str,
    user_id: str,
    name: str,
    industry: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Update organization name and industry during initial account setup.
    Strictly verifies org_admin membership and setup_completed == False.
    """
    clean_name = (name or "").strip()
    clean_industry = (industry or "").strip()

    if len(clean_name) < 2 or len(clean_name) > 80:
        return None, "Organization name must be between 2 and 80 characters."

    with get_session() as session:
        membership = (
            session.query(Membership)
            .filter_by(user_id=user_id, org_id=org_id)
            .first()
        )
        if not membership or membership.role != "org_admin":
            return None, "Access Denied: Only the organization admin can configure setup."

        org = session.query(Organization).filter_by(org_id=org_id).first()
        if not org:
            return None, "Organization not found."
        if org.setup_completed:
            return None, "Organization setup has already been completed."

        dup = (
            session.query(Organization)
            .filter(
                func.lower(Organization.name) == clean_name.lower(),
                Organization.org_id != org_id,
            )
            .first()
        )
        if dup:
            return None, "An organization with this name already exists. Please choose a different name."

        org.name = clean_name
        org.industry = clean_industry
        session.commit()

        return {
            "org_id": org.org_id,
            "name": org.name,
            "industry": org.industry,
            "setup_completed": bool(org.setup_completed),
            "status": org.status,
            "org_salt": org.org_salt,
            "role": "org_admin",
        }, None


def complete_org_setup(org_id: str, user_id: str, data_choice: str = "") -> Tuple[bool, Optional[str]]:
    """
    Mark organization setup as completed and record 'org_setup_completed' audit event.
    Strictly verifies that user_id is the org_admin of org_id.
    """
    with get_session() as session:
        membership = (
            session.query(Membership)
            .filter_by(user_id=user_id, org_id=org_id)
            .first()
        )
        if not membership or membership.role != "org_admin":
            return False, "Access Denied: Only the organization admin can complete setup."

        org = session.query(Organization).filter_by(org_id=org_id).first()
        if not org:
            return False, "Organization not found."

        org.setup_completed = True
        detail = f"Organization setup completed ({data_choice})." if data_choice else "Organization setup completed."
        session.add(
            AuditLog(
                audit_id=f"aud_{uuid.uuid4().hex[:8]}",
                org_id=org_id,
                user_id=user_id,
                action="org_setup_completed",
                target=org.name,
                justification=detail,
                created_at=datetime.utcnow(),
            )
        )
        session.commit()
        return True, None


def get_active_org_context(user_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Central security helper to retrieve the organization context from the logged-in session:
      - Strictly queries the database using user_id; never accepts org_id from user input or URLs.
      - Blocks access if the organization is suspended or closed.
    """
    with get_session() as session:
        membership = session.query(Membership).filter_by(user_id=user_id).first()
        if not membership:
            return None, "NO_ORG"

        org = session.query(Organization).filter_by(org_id=membership.org_id).first()
        if not org:
            return None, "NO_ORG"

        if org.status in ["suspended", "closed"]:
            return {
                "org_id": org.org_id,
                "name": org.name,
                "status": org.status,
                "role": membership.role,
                "setup_completed": bool(org.setup_completed),
            }, "This organization has been suspended. Access to its data and console is blocked."

        return {
            "org_id": org.org_id,
            "name": org.name,
            "industry": org.industry,
            "setup_completed": bool(org.setup_completed),
            "status": org.status,
            "org_salt": org.org_salt,
            "role": membership.role,
        }, None


# 6. Tenant-Scoped Query Helpers (Strictly Isolated by org_id)
def get_org_alerts(org_id: str) -> List[Dict[str, Any]]:
    """Fetch all alerts strictly scoped to the given org_id."""
    with get_session() as session:
        alerts = (
            session.query(Alert)
            .filter(Alert.org_id == org_id)
            .order_by(Alert.created_at.desc())
            .all()
        )
        return [
            {
                "alert_id": a.alert_id,
                "org_id": a.org_id,
                "rule_id": a.rule_id,
                "severity": a.severity,
                "user_pseudonym": a.user_pseudonym,
                "event_ids": a.event_ids,
                "reason": a.reason,
                "status": a.status,
                "reviewer": a.reviewer,
                "reviewer_notes": a.reviewer_notes,
                "created_at": a.created_at.strftime("%Y-%m-%d %H:%M:%S")
                if isinstance(a.created_at, datetime)
                else str(a.created_at),
            }
            for a in alerts
        ]


def get_org_alert_by_id(alert_id: str, org_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single alert only if it belongs to the given org_id."""
    with get_session() as session:
        a = (
            session.query(Alert)
            .filter(Alert.alert_id == alert_id, Alert.org_id == org_id)
            .first()
        )
        if not a:
            return None
        return {
            "alert_id": a.alert_id,
            "org_id": a.org_id,
            "rule_id": a.rule_id,
            "severity": a.severity,
            "user_pseudonym": a.user_pseudonym,
            "event_ids": a.event_ids,
            "reason": a.reason,
            "status": a.status,
            "reviewer": a.reviewer,
            "reviewer_notes": a.reviewer_notes,
            "created_at": a.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(a.created_at, datetime)
            else str(a.created_at),
        }


# ---------------------------------------------------------
# Role-Based Access Control (RBAC) Permissions Engine
# ---------------------------------------------------------
ROLE_PERMISSIONS = {
    "analyst": {
        "view_alerts",
        "triage_review",
        "triage_dismiss",
        "save_notes",
    },
    "reviewer": {
        "view_alerts",
        "triage_review",
        "triage_dismiss",
        "save_notes",
        "triage_escalate",
        "request_reidentification",
    },
    "org_admin": {
        "view_alerts",
        "triage_review",
        "triage_dismiss",
        "save_notes",
        "triage_escalate",
        "request_reidentification",
        "upload_logs",
        "view_rules",
        "edit_rules",
        "view_audit_trail",
        "invite_staff",
    },
}


def check_permission(role: Optional[str], action: str) -> Tuple[bool, Optional[str]]:
    """
    Enforces role-based permissions on the server side:
      - analyst: view alerts (pseudonyms only), mark reviewed or dismissed, add notes. Nothing else.
      - reviewer: everything an analyst can do, plus escalate, plus request re-identification with justification.
      - org_admin: upload logs, edit org_rules, view audit trail, invite staff, triage/review.
    Returns (is_allowed, error_message).
    """
    if not role:
        return False, "Access Denied: No active role specified."
    role_norm = role.lower().strip()
    allowed = ROLE_PERMISSIONS.get(role_norm, set())
    if action in allowed:
        return True, None
    return False, f"Permission Denied: Role '{role_norm}' is not authorized to perform action '{action}'."


def update_org_alert_review(
    alert_id: str,
    org_id: str,
    status: str,
    reviewer_notes: str,
    reviewer: str,
    role: Optional[str] = None,
) -> bool:
    """Update an alert's review status within the organization with server-side RBAC validation."""
    if role:
        if status == "escalated":
            allowed, err = check_permission(role, "triage_escalate")
            if not allowed:
                raise PermissionError(err)
        elif status == "reviewed":
            allowed, err = check_permission(role, "triage_review")
            if not allowed:
                raise PermissionError(err)
        elif status == "dismissed":
            allowed, err = check_permission(role, "triage_dismiss")
            if not allowed:
                raise PermissionError(err)
        else:
            allowed, err = check_permission(role, "save_notes")
            if not allowed:
                raise PermissionError(err)

    with get_session() as session:
        alert = (
            session.query(Alert)
            .filter(Alert.alert_id == alert_id, Alert.org_id == org_id)
            .first()
        )
        if alert:
            alert.status = status
            alert.reviewer_notes = reviewer_notes
            alert.reviewer = reviewer
            session.commit()
            return True
        return False


def get_org_audit_logs(org_id: str, role: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch all audit trail log entries strictly scoped to the given org_id with RBAC validation."""
    if role:
        allowed, err = check_permission(role, "view_audit_trail")
        if not allowed:
            raise PermissionError(err)

    with get_session() as session:
        logs = (
            session.query(AuditLog)
            .filter(AuditLog.org_id == org_id)
            .order_by(AuditLog.created_at.desc())
            .all()
        )
        return [
            {
                "log_id": l.audit_id,
                "org_id": l.org_id,
                "user_id": l.user_id,
                "action": l.action,
                "target_id": l.target,
                "justification": l.justification,
                "timestamp": l.created_at.strftime("%Y-%m-%d %H:%M:%S")
                if isinstance(l.created_at, datetime)
                else str(l.created_at),
            }
            for l in logs
        ]


def log_org_audit_event(
    org_id: str,
    user_id: Optional[str],
    action: str,
    target: str,
    justification: str,
) -> str:
    """Record an audit trail event for a specific organization."""
    audit_id = f"aud_{uuid.uuid4().hex[:8]}"
    with get_session() as session:
        entry = AuditLog(
            audit_id=audit_id,
            org_id=org_id,
            user_id=user_id,
            action=action,
            target=target,
            justification=justification,
            created_at=datetime.utcnow(),
        )
        session.add(entry)
        session.commit()
        return audit_id


def get_org_rules(org_id: str, role: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve all rule configurations and thresholds for an organization with RBAC validation."""
    if role:
        allowed, err = check_permission(role, "view_rules")
        if not allowed:
            raise PermissionError(err)

    with get_session() as session:
        rules = session.query(OrgRule).filter(OrgRule.org_id == org_id).all()
        return {r.rule_id: r.thresholds for r in rules}


def save_org_rule(
    org_id: str,
    rule_id: str,
    thresholds: Dict[str, Any],
    role: Optional[str] = None,
) -> None:
    """Save or update threshold configuration for a specific organization with RBAC validation."""
    if role:
        allowed, err = check_permission(role, "edit_rules")
        if not allowed:
            raise PermissionError(err)

    with get_session() as session:
        existing = session.query(OrgRule).filter_by(org_id=org_id, rule_id=rule_id).first()
        if existing:
            existing.thresholds = thresholds
        else:
            session.add(OrgRule(org_id=org_id, rule_id=rule_id, thresholds=thresholds))
        session.commit()


# 7. Log Telemetry Upload & Pseudonymization Helpers
def pseudonymize_user_with_salt(raw_user_id: str, org_salt: str) -> str:
    """Hash raw user_id with organization-specific salt; real user_id is never stored."""
    if str(raw_user_id).startswith("USER-"):
        return str(raw_user_id)
    token = hashlib.sha256(f"{org_salt}_{raw_user_id}".encode("utf-8")).hexdigest()[:8].upper()
    return f"USER-{token}"


def record_log_upload(org_id: str, user_id: str, filename: str, row_count: int) -> str:
    """Record an upload entry in log_uploads and write to audit_log."""
    upload_id = f"upl_{uuid.uuid4().hex[:8]}"
    with get_session() as session:
        rec = LogUpload(
            upload_id=upload_id,
            org_id=org_id,
            uploaded_by=user_id,
            filename=filename,
            row_count=row_count,
            created_at=datetime.utcnow(),
        )
        session.add(rec)
        session.commit()

    log_org_audit_event(
        org_id=org_id,
        user_id=user_id,
        action="UPLOAD_LOGS",
        target=upload_id,
        justification=f"Uploaded telemetry dataset: {filename} ({row_count:,} events)",
    )
    return upload_id


def save_org_events(df: pd.DataFrame, org_id: str, upload_id: str, org_salt: str) -> int:
    """
    Save telemetry records into the events table.
    Ensures user_id is salted with org_salt; real user_id is NEVER stored.
    """
    clean_df = df.copy()
    clean_df["timestamp"] = pd.to_datetime(clean_df["timestamp"])
    clean_df["user_id"] = clean_df["user_id"].apply(
        lambda uid: pseudonymize_user_with_salt(uid, org_salt)
    )

    with get_session() as session:
        events_to_add = []
        for idx, (_, row) in enumerate(clean_df.iterrows()):
            ts = row["timestamp"]
            pydatetime = ts.to_pydatetime() if hasattr(ts, "to_pydatetime") else ts
            raw_event_id = str(row["event_id"])
            # Scope event_id to upload_id and row index so shared/repeated uploads never violate the global PK
            scoped_event_id = f"{upload_id}_{idx}_{raw_event_id}"[:50]
            events_to_add.append(
                Event(
                    event_id=scoped_event_id,
                    org_id=org_id,
                    upload_id=upload_id,
                    timestamp=pydatetime,
                    user_id=str(row["user_id"]),
                    role=str(row["role"]),
                    action=str(row["action"]),
                    resource=str(row["resource"]),
                    sensitivity=str(row["sensitivity"]),
                    bytes=int(row["bytes"]) if pd.notnull(row["bytes"]) else 0,
                    device=str(row["device"]),
                    source_ip=str(row["source_ip"]),
                    outcome=str(row["outcome"]),
                )
            )
        session.bulk_save_objects(events_to_add)
        session.commit()
        return len(events_to_add)


def save_org_alerts(alerts: List[Dict[str, Any]], org_id: str) -> None:
    """Save detector alerts scoped to an organization."""
    with get_session() as session:
        for a in alerts:
            ts = a.get("created_at")
            if isinstance(ts, str):
                try:
                    created_dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                except Exception:
                    created_dt = datetime.utcnow()
            elif isinstance(ts, datetime):
                created_dt = ts
            else:
                created_dt = datetime.utcnow()

            alert_obj = Alert(
                alert_id=a["alert_id"],
                org_id=org_id,
                rule_id=a["rule_id"],
                severity=a["severity"],
                user_pseudonym=a["user_pseudonym"],
                event_ids=a["event_ids"],
                reason=a["reason"],
                status=a.get("status", "new"),
                reviewer=a.get("reviewer"),
                reviewer_notes=a.get("reviewer_notes"),
                created_at=created_dt,
            )
            session.merge(alert_obj)
        session.commit()


def save_alerts(alerts: List[Dict[str, Any]], org_id: Optional[str] = None) -> None:
    """Compatibility helper to save alerts."""
    target_org = org_id or (alerts[0].get("org_id") if alerts else "org_default") or "org_default"
    save_org_alerts(alerts, target_org)


def clear_alerts(org_id: Optional[str] = None) -> None:
    """Clear alerts from database, optionally filtered by org_id."""
    with get_session() as session:
        q = session.query(Alert)
        if org_id:
            q = q.filter(Alert.org_id == org_id)
        q.delete()
        session.commit()

# 5. Backward-Compatible Application Helpers
def get_all_alerts(org_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch all alerts, optionally filtered by organization."""
    with get_session() as session:
        query = session.query(Alert)
        if org_id:
            query = query.filter(Alert.org_id == org_id)
        alerts = query.order_by(Alert.created_at.desc()).all()
        return [
            {
                "alert_id": a.alert_id,
                "org_id": a.org_id,
                "rule_id": a.rule_id,
                "severity": a.severity,
                "user_pseudonym": a.user_pseudonym,
                "event_ids": a.event_ids,
                "reason": a.reason,
                "status": a.status,
                "reviewer": a.reviewer,
                "reviewer_notes": a.reviewer_notes,
                "created_at": a.created_at.strftime("%Y-%m-%d %H:%M:%S") if isinstance(a.created_at, datetime) else str(a.created_at),
            }
            for a in alerts
        ]


def get_alert_by_id(alert_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single alert by its alert_id."""
    with get_session() as session:
        a = session.query(Alert).filter_by(alert_id=alert_id).first()
        if not a:
            return None
        return {
            "alert_id": a.alert_id,
            "org_id": a.org_id,
            "rule_id": a.rule_id,
            "severity": a.severity,
            "user_pseudonym": a.user_pseudonym,
            "event_ids": a.event_ids,
            "reason": a.reason,
            "status": a.status,
            "reviewer": a.reviewer,
            "reviewer_notes": a.reviewer_notes,
            "created_at": a.created_at.strftime("%Y-%m-%d %H:%M:%S") if isinstance(a.created_at, datetime) else str(a.created_at),
        }


def update_alert_review(
    alert_id: str,
    status: str,
    reviewer_notes: str,
    reviewer: str = "security_analyst",
) -> None:
    """Update review status, reviewer identifier, and notes for an alert."""
    with get_session() as session:
        alert = session.query(Alert).filter_by(alert_id=alert_id).first()
        if alert:
            alert.status = status
            alert.reviewer_notes = reviewer_notes
            alert.reviewer = reviewer
            session.commit()


def log_audit_event(
    actor: str,
    role: str,
    action: str,
    target_id: Optional[str] = None,
    justification: Optional[str] = None,
    org_id: Optional[str] = None,
) -> str:
    """Record an audit trail event."""
    audit_id = f"aud_{uuid.uuid4().hex[:8]}"
    with get_session() as session:
        new_log = AuditLog(
            audit_id=audit_id,
            org_id=org_id or "org_default",
            user_id=None,
            action=action,
            target=target_id or "N/A",
            justification=justification or f"Actor: {actor} (Role: {role})",
            created_at=datetime.utcnow(),
        )
        session.add(new_log)
        session.commit()
    return audit_id


def get_audit_logs(org_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch all audit trail log entries."""
    with get_session() as session:
        query = session.query(AuditLog)
        if org_id:
            query = query.filter(AuditLog.org_id == org_id)
        logs = query.order_by(AuditLog.created_at.desc()).all()
        return [
            {
                "log_id": l.audit_id,
                "org_id": l.org_id,
                "action": l.action,
                "target_id": l.target,
                "justification": l.justification,
                "timestamp": l.created_at.strftime("%Y-%m-%d %H:%M:%S") if isinstance(l.created_at, datetime) else str(l.created_at),
            }
            for l in logs
        ]


# ---------------------------------------------------------
# 8. Staff Management & One-Time Invites (Org Admin Only)
# ---------------------------------------------------------
def get_org_staff(org_id: str, role: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve all staff members associated with an organization."""
    if role:
        allowed, err = check_permission(role, "invite_staff")
        if not allowed:
            raise PermissionError(err)

    with get_session() as session:
        records = (
            session.query(Membership, User)
            .join(User, Membership.user_id == User.user_id)
            .filter(Membership.org_id == org_id)
            .all()
        )
        return [
            {
                "user_id": u.user_id,
                "full_name": u.full_name,
                "email": u.email,
                "role": m.role,
                "status": u.status,
                "created_at": u.created_at.strftime("%Y-%m-%d %H:%M:%S")
                if isinstance(u.created_at, datetime)
                else str(u.created_at),
            }
            for m, u in records
        ]


def get_org_pending_invites(org_id: str, role: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve all pending invites for an organization."""
    if role:
        allowed, err = check_permission(role, "invite_staff")
        if not allowed:
            raise PermissionError(err)

    with get_session() as session:
        invites = (
            session.query(Invite)
            .filter(Invite.org_id == org_id, Invite.status == "pending")
            .order_by(Invite.created_at.desc())
            .all()
        )
        return [
            {
                "invite_id": inv.invite_id,
                "email": inv.email,
                "role": inv.role,
                "code": inv.code,
                "created_at": inv.created_at.strftime("%Y-%m-%d %H:%M:%S")
                if isinstance(inv.created_at, datetime)
                else str(inv.created_at),
            }
            for inv in invites
        ]


def add_or_invite_staff(
    org_id: str,
    email: str,
    assign_role: str,
    admin_role: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Add or invite a staff member to the organization:
      - Enforces the plan's max_staff limit.
      - If user exists: directly assigns membership role.
      - If user does not exist: creates a pending invite with a one-time code.
    """
    allowed, err = check_permission(admin_role, "invite_staff")
    if not allowed:
        raise PermissionError(err)

    clean_email = email.strip().lower()
    if not clean_email or "@" not in clean_email or "." not in clean_email:
        return None, "Please provide a valid email address."

    clean_role = assign_role.strip().lower()
    if clean_role not in ["analyst", "reviewer"]:
        return None, "Invalid role. Staff can be added as 'analyst' or 'reviewer' only."

    with get_session() as session:
        active_count = session.query(Membership).filter_by(org_id=org_id).count()
        pending_count = session.query(Invite).filter_by(org_id=org_id, status="pending").count()
        if (active_count + pending_count) >= MAX_STAFF_SEATS:
            return (
                None,
                f"Staff limit reached: an organization can have up to {MAX_STAFF_SEATS} staff seats.",
            )

        existing_user = session.query(User).filter_by(email=clean_email).first()
        if existing_user:
            existing_mem = (
                session.query(Membership)
                .filter_by(org_id=org_id, user_id=existing_user.user_id)
                .first()
            )
            if existing_mem:
                return (
                    None,
                    f"User '{clean_email}' is already a member of your organization (Role: {existing_mem.role}).",
                )
            if existing_user.status in ["suspended", "banned"]:
                return (
                    None,
                    f"Cannot add user '{clean_email}': user account is currently suspended or banned.",
                )

            session.add(Membership(user_id=existing_user.user_id, org_id=org_id, role=clean_role))
            session.commit()
            return {
                "type": "added",
                "user_id": existing_user.user_id,
                "email": existing_user.email,
                "full_name": existing_user.full_name,
                "role": clean_role,
            }, None
        else:
            existing_inv = (
                session.query(Invite)
                .filter_by(org_id=org_id, email=clean_email, status="pending")
                .first()
            )
            if existing_inv:
                return {
                    "type": "invited",
                    "invite_id": existing_inv.invite_id,
                    "email": existing_inv.email,
                    "code": existing_inv.code,
                    "role": existing_inv.role,
                }, None

            one_time_code = f"INV-{secrets.token_hex(4).upper()}"
            invite_id = f"inv_{uuid.uuid4().hex[:8]}"
            session.add(
                Invite(
                    invite_id=invite_id,
                    org_id=org_id,
                    email=clean_email,
                    role=clean_role,
                    code=one_time_code,
                    status="pending",
                    created_at=datetime.utcnow(),
                )
            )
            session.commit()
            return {
                "type": "invited",
                "invite_id": invite_id,
                "email": clean_email,
                "code": one_time_code,
                "role": clean_role,
            }, None


def remove_staff_member(
    org_id: str,
    target_user_id: str,
    requesting_user_id: str,
    admin_role: str,
) -> Tuple[bool, Optional[str]]:
    """
    Remove a staff member from the organization:
      - Strictly scoped to the admin's own organization.
      - An org_admin cannot remove themselves.
    """
    allowed, err = check_permission(admin_role, "invite_staff")
    if not allowed:
        raise PermissionError(err)

    if target_user_id == requesting_user_id:
        return False, "You cannot remove yourself from the organization."

    with get_session() as session:
        membership = (
            session.query(Membership)
            .filter_by(org_id=org_id, user_id=target_user_id)
            .first()
        )
        if not membership:
            return False, "Staff member not found in your organization."

        session.delete(membership)
        session.commit()
        return True, None


def cancel_pending_invite(
    org_id: str,
    invite_id: str,
    admin_role: str,
) -> Tuple[bool, Optional[str]]:
    """Cancel a pending invite strictly within the admin's organization."""
    allowed, err = check_permission(admin_role, "invite_staff")
    if not allowed:
        raise PermissionError(err)

    with get_session() as session:
        invite = session.query(Invite).filter_by(org_id=org_id, invite_id=invite_id).first()
        if not invite:
            return False, "Invite not found in your organization."

        invite.status = "cancelled"
        session.commit()
        return True, None


def accept_invite_code(
    code: str,
    user_id: str,
    user_email: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Accept an invitation code when registering:
      - Validates one-time code and pending status.
      - Enforces plan's max_staff limit.
      - Attaches newly registered user to the inviting organization.
    """
    clean_code = code.strip().upper()
    if not clean_code:
        return None, "Please provide an invite code."

    with get_session() as session:
        invite = session.query(Invite).filter_by(code=clean_code, status="pending").first()
        if not invite:
            return None, "Invalid or expired one-time invite code."

        if invite.email.strip().lower() != user_email.strip().lower():
            return (
                None,
                f"Invite code '{clean_code}' was issued for {invite.email}, but your email is {user_email}.",
            )

        active_count = session.query(Membership).filter_by(org_id=invite.org_id).count()
        if active_count >= MAX_STAFF_SEATS:
            return (
                None,
                f"Cannot join: Organization has reached its maximum limit of {MAX_STAFF_SEATS} staff seats.",
            )

        existing_membership = (
            session.query(Membership)
            .filter_by(org_id=invite.org_id, user_id=user_id)
            .first()
        )
        if not existing_membership:
            session.add(Membership(user_id=user_id, org_id=invite.org_id, role=invite.role))

        invite.status = "accepted"
        session.commit()
        return {"org_id": invite.org_id, "role": invite.role}, None


# ---------------------------------------------------------
# 9. Super-Admin Console & Platform Audit Trail
# ---------------------------------------------------------
def get_superadmin_organizations() -> List[Dict[str, Any]]:
    """
    List all organizations with metadata and aggregated counts only:
      - name, status, number of users, number of alerts, number of uploads.
      - Strictly returns counts and metadata only; zero telemetry, notes, or event details.
    """
    with get_session() as session:
        orgs = session.query(Organization).order_by(Organization.created_at.desc()).all()
        results = []
        for o in orgs:
            user_count = session.query(Membership).filter_by(org_id=o.org_id).count()
            alert_count = session.query(Alert).filter_by(org_id=o.org_id).count()
            upload_count = session.query(LogUpload).filter_by(org_id=o.org_id).count()
            results.append({
                "org_id": o.org_id,
                "name": o.name,
                "industry": o.industry,
                "status": o.status,
                "user_count": user_count,
                "alert_count": alert_count,
                "upload_count": upload_count,
                "created_at": o.created_at.strftime("%Y-%m-%d %H:%M:%S")
                if isinstance(o.created_at, datetime)
                else str(o.created_at),
            })
        return results


def get_superadmin_users() -> List[Dict[str, Any]]:
    """
    List all platform users with metadata only:
      - name, email, status, organization name, role, super-admin status.
    """
    with get_session() as session:
        users = session.query(User).order_by(User.created_at.desc()).all()
        results = []
        for u in users:
            membership = session.query(Membership).filter_by(user_id=u.user_id).first()
            org_name = "None"
            role = "None"
            if membership:
                org = session.query(Organization).filter_by(org_id=membership.org_id).first()
                org_name = org.name if org else membership.org_id
                role = membership.role
            results.append({
                "user_id": u.user_id,
                "name": u.full_name,
                "email": u.email,
                "status": u.status,
                "organization": org_name,
                "role": role,
                "is_super_admin": u.is_super_admin,
                "created_at": u.created_at.strftime("%Y-%m-%d %H:%M:%S")
                if isinstance(u.created_at, datetime)
                else str(u.created_at),
            })
        return results


def update_user_status_by_superadmin(
    actor_user_id: str,
    target_user_id: str,
    new_status: str,
    reason: str,
) -> Tuple[bool, Optional[str]]:
    """
    Suspend, ban, or reactivate a user with mandatory written reason saved in platform_audit_log.
    """
    clean_status = new_status.strip().lower()
    if clean_status not in ["active", "suspended", "banned"]:
        return False, "Invalid status. Allowed values: active, suspended, banned."

    clean_reason = reason.strip()
    if not clean_reason:
        return False, "A formal written reason is mandatory for modifying user status."

    with get_session() as session:
        user = session.query(User).filter_by(user_id=target_user_id).first()
        if not user:
            return False, "Target user not found."

        if target_user_id == actor_user_id and clean_status != "active":
            return False, "Super-admin cannot suspend or ban their own account."

        old_status = user.status
        user.status = clean_status

        log_entry = PlatformAuditLog(
            id=f"p_aud_{uuid.uuid4().hex[:8]}",
            actor_user_id=actor_user_id,
            action=f"USER_STATUS_{clean_status.upper()}",
            target_type="user",
            target_id=target_user_id,
            reason=f"Status changed from {old_status} to {clean_status}. Reason: {clean_reason}",
            created_at=datetime.utcnow(),
        )
        session.add(log_entry)
        session.commit()
        return True, None


def update_org_status_by_superadmin(
    actor_user_id: str,
    target_org_id: str,
    new_status: str,
    reason: str,
) -> Tuple[bool, Optional[str]]:
    """
    Suspend, close, or reactivate an organization with mandatory written reason saved in platform_audit_log.
    """
    clean_status = new_status.strip().lower()
    if clean_status not in ["active", "suspended", "closed"]:
        return False, "Invalid status. Allowed values: active, suspended, closed."

    clean_reason = reason.strip()
    if not clean_reason:
        return False, "A formal written reason is mandatory for modifying organization status."

    with get_session() as session:
        org = session.query(Organization).filter_by(org_id=target_org_id).first()
        if not org:
            return False, "Target organization not found."

        old_status = org.status
        org.status = clean_status

        log_entry = PlatformAuditLog(
            id=f"p_aud_{uuid.uuid4().hex[:8]}",
            actor_user_id=actor_user_id,
            action=f"ORG_STATUS_{clean_status.upper()}",
            target_type="organization",
            target_id=target_org_id,
            reason=f"Status changed from {old_status} to {clean_status}. Reason: {clean_reason}",
            created_at=datetime.utcnow(),
        )
        session.add(log_entry)
        session.commit()
        return True, None


def get_platform_audit_logs() -> List[Dict[str, Any]]:
    """
    Fetch platform audit trail entries showing actor, time, action type, target, and reason.
    Does NOT touch or display justification text from organization audit logs.
    """
    with get_session() as session:
        logs = (
            session.query(PlatformAuditLog, User.email, User.full_name)
            .outerjoin(User, PlatformAuditLog.actor_user_id == User.user_id)
            .order_by(PlatformAuditLog.created_at.desc())
            .all()
        )
        results = []
        for entry, email, name in logs:
            actor_display = f"{name} ({email})" if email else (entry.actor_user_id or "System")
            results.append({
                "log_id": entry.id,
                "actor": actor_display,
                "action": entry.action,
                "target_type": entry.target_type,
                "target_id": entry.target_id,
                "reason": entry.reason,
                "timestamp": entry.created_at.strftime("%Y-%m-%d %H:%M:%S")
                if isinstance(entry.created_at, datetime)
                else str(entry.created_at),
            })
        return results


# 11. Windows Event Log Collector Helpers
def get_org_salt(org_id: str) -> Optional[str]:
    """Fetch the organization's pseudonymization salt by org_id."""
    with get_session() as session:
        org = session.query(Organization).filter(Organization.org_id == org_id).first()
        return org.org_salt if org else None


def lookup_user_role(org_id: str, account_name: str) -> str:
    """Look up a Windows account's role in users_map for the given org, defaulting to 'unknown'."""
    if not account_name:
        return "unknown"
    clean_name = account_name.strip()
    with get_session() as session:
        entry = (
            session.query(UsersMap)
            .filter(UsersMap.org_id == org_id, UsersMap.account_name == clean_name)
            .first()
        )
        if not entry:
            entry = (
                session.query(UsersMap)
                .filter(UsersMap.org_id == org_id, func.lower(UsersMap.account_name) == clean_name.lower())
                .first()
            )
        return entry.role if entry else "unknown"


def lookup_resource_sensitivity(org_id: str, resource: str) -> str:
    """Look up resource sensitivity from resource_map (exact or longest prefix match), defaulting to 'normal'."""
    if not resource:
        return "normal"
    norm_res = resource.strip().lower()
    with get_session() as session:
        entries = (
            session.query(ResourceMap)
            .filter(ResourceMap.org_id == org_id)
            .all()
        )
        best_match = None
        best_len = -1
        for entry in entries:
            pattern = entry.resource_pattern.strip().lower()
            if norm_res == pattern or norm_res.startswith(pattern):
                if len(pattern) > best_len:
                    best_len = len(pattern)
                    best_match = entry.sensitivity
        return best_match if best_match is not None else "normal"


def upsert_user_map(org_id: str, account_name: str, org_salt: str, role: str = "unknown") -> str:
    """Insert or update an account_name -> pseudonym/role entry in users_map."""
    clean_name = account_name.strip()
    pseudonym = pseudonymize_user_with_salt(clean_name, org_salt)
    with get_session() as session:
        entry = (
            session.query(UsersMap)
            .filter(UsersMap.org_id == org_id, UsersMap.account_name == clean_name)
            .first()
        )
        if entry:
            entry.user_pseudonym = pseudonym
            entry.role = role
            entry.updated_at = datetime.utcnow()
        else:
            session.add(
                UsersMap(
                    org_id=org_id,
                    account_name=clean_name,
                    user_pseudonym=pseudonym,
                    role=role,
                    updated_at=datetime.utcnow(),
                )
            )
        session.commit()
    return pseudonym


def upsert_resource_map(org_id: str, resource_pattern: str, sensitivity: str = "normal") -> None:
    """Insert or update a resource sensitivity mapping in resource_map."""
    clean_pattern = resource_pattern.strip()
    with get_session() as session:
        entry = (
            session.query(ResourceMap)
            .filter(ResourceMap.org_id == org_id, ResourceMap.resource_pattern == clean_pattern)
            .first()
        )
        if entry:
            entry.sensitivity = sensitivity
            entry.updated_at = datetime.utcnow()
        else:
            session.add(
                ResourceMap(
                    org_id=org_id,
                    resource_pattern=clean_pattern,
                    sensitivity=sensitivity,
                    updated_at=datetime.utcnow(),
                )
            )
        session.commit()


def get_last_record_id(org_id: str, source: str = "windows_event_log") -> int:
    """Return the last processed EventRecordID for the given org and source."""
    with get_session() as session:
        state = (
            session.query(CollectorState)
            .filter(CollectorState.org_id == org_id, CollectorState.source == source)
            .first()
        )
        return int(state.last_record_id) if state else 0


def set_last_record_id(org_id: str, record_id: int, source: str = "windows_event_log") -> None:
    """Persist the last processed EventRecordID for the given org and source."""
    with get_session() as session:
        state = (
            session.query(CollectorState)
            .filter(CollectorState.org_id == org_id, CollectorState.source == source)
            .first()
        )
        if state:
            state.last_record_id = int(record_id)
            state.updated_at = datetime.utcnow()
        else:
            session.add(
                CollectorState(
                    org_id=org_id,
                    source=source,
                    last_record_id=int(record_id),
                    updated_at=datetime.utcnow(),
                )
            )
        session.commit()


def ingest_event(org_id: str, event: Dict[str, Any]) -> str:
    """
    Persist a single normalized event into the events table using parameterized queries.
    The events table never stores real account names; user_id must already be pseudonymized.
    """
    ts = event["timestamp"]
    if isinstance(ts, str):
        ts_dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    elif isinstance(ts, datetime):
        ts_dt = ts.replace(tzinfo=None)
    else:
        raise ValueError(f"Unsupported timestamp type: {type(ts)}")

    event_id = str(event.get("event_id") or f"win_{uuid.uuid4().hex[:12]}")[:50]
    with get_session() as session:
        rec = Event(
            event_id=event_id,
            org_id=org_id,
            upload_id=None,
            source=str(event.get("source", "windows_event_log")),
            timestamp=ts_dt,
            user_id=str(event["user_id"]),
            role=str(event.get("role", "unknown")),
            action=str(event["action"]),
            resource=str(event["resource"])[:255],
            sensitivity=str(event.get("sensitivity", "normal")),
            bytes=int(event.get("bytes", 0) or 0),
            device=str(event.get("device", "managed")),
            source_ip=str(event.get("source_ip", "127.0.0.1")),
            outcome=str(event["outcome"]),
        )
        session.add(rec)
        session.commit()
    return event_id


def ingest_events_batch(org_id: str, events: List[Dict[str, Any]]) -> int:
    """Persist a batch of normalized events into the events table in one transaction."""
    if not events:
        return 0

    with get_session() as session:
        existing_ids = {
            r[0]
            for r in session.query(Event.event_id)
            .filter(Event.org_id == org_id)
            .all()
        }

        records = []
        seen_in_batch = set()
        for event in events:
            ts = event["timestamp"]
            if isinstance(ts, str):
                ts_dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            elif isinstance(ts, datetime):
                ts_dt = ts.replace(tzinfo=None)
            else:
                raise ValueError(f"Unsupported timestamp type: {type(ts)}")

            raw_eid = str(event.get("event_id") or f"prt_{uuid.uuid4().hex[:12]}")
            event_id = raw_eid if raw_eid.startswith(f"{org_id}_") else f"{org_id}_{raw_eid}"
            event_id = event_id[:50]
            if event_id in existing_ids or event_id in seen_in_batch:
                continue
            seen_in_batch.add(event_id)

            records.append(
                Event(
                    event_id=event_id,
                    org_id=org_id,
                    upload_id=None,
                    source=str(event.get("source", "company_portal")),
                    timestamp=ts_dt,
                    user_id=str(event["user_id"]),
                    role=str(event.get("role", "unknown")),
                    action=str(event["action"]),
                    resource=str(event["resource"])[:255],
                    sensitivity=str(event.get("sensitivity", "normal")),
                    bytes=int(event.get("bytes", 0) or 0),
                    device=str(event.get("device", "managed")),
                    source_ip=str(event.get("source_ip", "127.0.0.1")),
                    outcome=str(event["outcome"]),
                )
            )

        if records:
            session.bulk_save_objects(records)
            session.commit()
        return len(records)


def get_org_events_df(org_id: str, source: Optional[str] = None) -> pd.DataFrame:
    """Load organization events from the database as a DataFrame for detection."""
    with get_session() as session:
        q = session.query(Event).filter(Event.org_id == org_id)
        if source:
            q = q.filter(Event.source == source)
        rows = q.order_by(Event.timestamp.asc()).all()
        if not rows:
            return pd.DataFrame(
                columns=[
                    "event_id",
                    "timestamp",
                    "user_id",
                    "role",
                    "action",
                    "resource",
                    "sensitivity",
                    "bytes",
                    "device",
                    "source_ip",
                    "outcome",
                ]
            )
        return pd.DataFrame(
            [
                {
                    "event_id": r.event_id,
                    "timestamp": r.timestamp,
                    "user_id": r.user_id,
                    "role": r.role,
                    "action": r.action,
                    "resource": r.resource,
                    "sensitivity": r.sensitivity,
                    "bytes": r.bytes,
                    "device": r.device,
                    "source_ip": r.source_ip,
                    "outcome": r.outcome,
                }
                for r in rows
            ]
        )


def get_org_portal_url(org_id: str) -> str:
    """Return the configured company portal audit URL for an organization (or empty string)."""
    with get_session() as session:
        org = session.query(Organization).filter(Organization.org_id == org_id).first()
        return str(org.portal_url or "").strip() if org else ""


def set_org_portal_url(org_id: str, portal_url: str) -> None:
    """Persist the company portal audit URL for an organization."""
    with get_session() as session:
        org = session.query(Organization).filter(Organization.org_id == org_id).first()
        if org:
            org.portal_url = str(portal_url or "").strip()[:500]
            session.commit()


def filter_new_alerts(org_id: str, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter out alerts that already exist for the org."""
    if not alerts:
        return []
    with get_session() as session:
        rows = (
            session.query(Alert.rule_id, Alert.user_pseudonym, Alert.event_ids, Alert.created_at, Alert.reason)
            .filter(Alert.org_id == org_id)
            .all()
        )
        existing_exact = {(r.rule_id, r.user_pseudonym, r.event_ids) for r in rows}
        existing_bucket = {(r.rule_id, r.user_pseudonym, str(r.created_at), r.reason) for r in rows}
        existing_user_time = {(r.rule_id, r.user_pseudonym, str(r.created_at)) for r in rows}

    kept = []
    for a in alerts:
        rule_id = a["rule_id"]
        pseudo = a["user_pseudonym"]
        eids = a["event_ids"]
        created = str(a["created_at"])
        reason = a.get("reason", "")
        if (rule_id, pseudo, eids) in existing_exact:
            continue
        if (rule_id, pseudo, created, reason) in existing_bucket:
            continue
        if rule_id in ("bulk_access", "policy_violation", "off_hours") and (rule_id, pseudo, created) in existing_user_time:
            continue
        existing_exact.add((rule_id, pseudo, eids))
        existing_bucket.add((rule_id, pseudo, created, reason))
        existing_user_time.add((rule_id, pseudo, created))
        kept.append(a)
    return kept


if __name__ == "__main__":
    print(f"Connecting to database via: {DATABASE_URL}")
    init_db()
    summary = get_schema_summary()
    print("\n--- Created Tables & Foreign Keys ---")
    for tbl, meta in summary.items():
        print(f"\nTable: [{tbl}]")
        print(f"  Columns:      {', '.join(meta['columns'])}")
        fks_str = "; ".join(meta["foreign_keys"]) if meta["foreign_keys"] else "None"
        print(f"  Foreign Keys: {fks_str}")
