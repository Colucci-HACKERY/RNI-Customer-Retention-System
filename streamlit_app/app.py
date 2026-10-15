# ============================================================
# RNI CUSTOMER RETENTION SYSTEM
# ------------------------------------------------------------
# A governed, role-separated customer retention analytics
# pipeline that ingests online retail transactions, validates
# and cleans them, engineers RFM features, evaluates the
# retention-risk model, and publishes approved datasets to a
# Power BI business layer.
#
# Technical workspace flow
# ------------------------
# Pipeline Overview
# Dataset Ingestion
# Data Validation
# Data Cleaning
# RFM Feature Engineering
# Model Evaluation
# Version & Publish
# Audit Trail
# User Management
#
# Business workspace
# ------------------
# Pipeline Status
# Quick Analytics (Overview, Products & Basket, Geography)
# Power BI Dashboard
#
# Structure
# ---------
# 1.  Imports and optional dependencies
# 2.  Page configuration and styling
# 3.  Filesystem paths and directory bootstrap
# 4.  Configuration and deployment secrets loading
# 5.  Persistent user database and RBAC helpers
# 6.  Password hashing, validation and user administration
# 7.  Audit trail utilities
# 8.  Authentication and session bootstrap
# 9.  Sidebar navigation, session state and pipeline helpers
# 10. Country standardisation and geographic validation
# 11. Shared data utilities
# 12. Data ingestion, validation, cleaning and RFM engineering
# 13. Publication, versioning and Power BI hand-off
# 14. Technical workspace pages
# 15. Business workspace pages
# ============================================================


# ------------------------------------------------------------
# 1. Imports and optional dependencies
# ------------------------------------------------------------

from __future__ import annotations

import io
import re
import sqlite3
import zipfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Optional

import bcrypt
import pandas as pd
import streamlit as st
import streamlit_authenticator as stauth
import yaml

# Plotly is used for interactive charts. It is optional so the
# application still runs if the dependency is unavailable.
try:
    import plotly.express as px

    PLOTLY_AVAILABLE = True
except ImportError:  # pragma: no cover - environment dependent
    px = None  # type: ignore[assignment]
    PLOTLY_AVAILABLE = False

# mlxtend provides Apriori and association rules for the
# optional Market Basket Analysis feature.
try:
    from mlxtend.frequent_patterns import apriori, association_rules

    MLXTEND_AVAILABLE = True
except ImportError:  # pragma: no cover - environment dependent
    apriori = None  # type: ignore[assignment]
    association_rules = None  # type: ignore[assignment]
    MLXTEND_AVAILABLE = False


# ------------------------------------------------------------
# 2. Page configuration and styling
# ------------------------------------------------------------

st.set_page_config(
    page_title="RNI Customer Retention System",
    page_icon="CRS",
    layout="wide",
)

_APP_CSS = """
<style>
    .block-container {
        padding-top: 1.6rem;
        padding-bottom: 2.5rem;
    }
    div[data-testid="stMetric"] {
        border: 1px solid rgba(120, 120, 120, 0.18);
        border-radius: 12px;
        padding: 0.75rem 0.9rem;
        background: rgba(250, 250, 250, 0.02);
    }
    div[data-baseweb="tab-list"] {
        flex-wrap: wrap !important;
        row-gap: 0.4rem !important;
    }
    div[data-baseweb="tab-list"] button[role="tab"] {
        flex: 1 1 calc(33.333% - 0.5rem) !important;
        max-width: calc(33.333% - 0.5rem) !important;
        min-width: 180px !important;
    }
    @media (max-width: 900px) {
        div[data-baseweb="tab-list"] button[role="tab"] {
            flex-basis: 100% !important;
            max-width: 100% !important;
        }
    }
    .pipeline-breadcrumb {
        font-size: 0.85rem;
        color: #4a5568;
        padding: 0.5rem 0.85rem;
        border-radius: 8px;
        background: rgba(120, 120, 120, 0.08);
        border: 1px solid rgba(120, 120, 120, 0.12);
        margin-bottom: 0.85rem;
    }
    @keyframes rni_spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    .rni-inline-loading {
        display: flex;
        align-items: center;
        gap: 0.85rem;
        padding: 0.85rem 1.1rem;
        border-radius: 12px;
        background: rgba(26,82,118,0.05);
        border: 1px solid rgba(26,82,118,0.15);
        margin-bottom: 1rem;
    }
    .rni-inline-loading .spinner {
        width: 24px;
        height: 24px;
        border: 3px solid #e8ecf1;
        border-top-color: #1a5276;
        border-radius: 50%;
        animation: rni_spin 1s linear infinite;
    }
    .rni-inline-loading .text {
        font-size: 0.95rem;
        color: #1a2a4a;
    }
</style>
"""

st.markdown(_APP_CSS, unsafe_allow_html=True)

# Additional presentation styling. Core app behaviour remains unchanged.
_STYLESHEET_PATH = Path(__file__).parent / "RNI_styles.css"
if _STYLESHEET_PATH.is_file():
    st.markdown(
        "<style>" + _STYLESHEET_PATH.read_text(encoding="utf-8") + "</style>",
        unsafe_allow_html=True,
    )


# ------------------------------------------------------------
# 3. Filesystem paths and directory bootstrap
# ------------------------------------------------------------

APP_DIR: Path = Path(__file__).parent

CONFIG_PATH: Path = APP_DIR / "config.yaml"

PUBLISH_DIR: Path = APP_DIR / "outputs" / "published"
ARCHIVE_DIR: Path = PUBLISH_DIR / "archive"
POWER_BI_DIR: Path = PUBLISH_DIR / "power_bi"
TEAM_OUTPUT_DIR: Path = PUBLISH_DIR / "team_outputs"

MODEL_ARTIFACT_DIR: Path = APP_DIR / "model_artifacts"

AUDIT_DIR: Path = APP_DIR / "outputs" / "audit"
AUDIT_LOG_PATH: Path = AUDIT_DIR / "audit_trail.csv"

USER_DATA_DIR: Path = APP_DIR / "data"
USER_DB_PATH: Path = USER_DATA_DIR / "users.db"

_REQUIRED_DIRECTORIES = (
    PUBLISH_DIR,
    ARCHIVE_DIR,
    POWER_BI_DIR,
    TEAM_OUTPUT_DIR,
    AUDIT_DIR,
    USER_DATA_DIR,
)

for _directory in _REQUIRED_DIRECTORIES:
    _directory.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------
# 4. Configuration and deployment secrets loading
# ------------------------------------------------------------

def load_config(config_path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Load the non-sensitive YAML configuration file.

    Args:
        config_path: Path to the YAML configuration.

    Returns:
        Parsed configuration dictionary.

    Raises:
        FileNotFoundError: If the configuration file is missing.
    """
    with open(config_path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


CONFIG: dict[str, Any] = load_config()


def load_deployment_secrets() -> dict[str, Any]:
    """Load authentication and integration secrets from Streamlit.

    Returns:
        Dictionary containing cookie settings, Power BI URL and
        bootstrap user credentials.

    Raises:
        RuntimeError: If any required secret is missing.
    """
    try:
        return {
            "cookie_name": st.secrets["cookie"]["name"],
            "cookie_key": st.secrets["cookie"]["key"],
            "cookie_expiry_days": int(st.secrets["cookie"]["expiry_days"]),
            "power_bi_url": st.secrets["power_bi"]["dashboard_url"],
            "bootstrap_users": {
                username: {
                    "email": user_data.get("email", ""),
                    "name": user_data.get("name", username),
                    "password": user_data["password"],
                    "role": user_data.get("role", "business"),
                }
                for username, user_data in st.secrets["bootstrap_users"].items()
            },
        }
    except (KeyError, AttributeError) as exc:
        raise RuntimeError(
            "Application secrets could not be loaded. Check "
            ".streamlit/secrets.toml locally, or the Secrets "
            "section in Streamlit Community Cloud."
        ) from exc


try:
    _SECRETS = load_deployment_secrets()
except RuntimeError as secrets_error:
    st.error("Application secrets could not be loaded.")
    st.info(str(secrets_error))
    st.stop()

COOKIE_NAME: str = _SECRETS["cookie_name"]
COOKIE_KEY: str = _SECRETS["cookie_key"]
COOKIE_EXPIRY_DAYS: int = _SECRETS["cookie_expiry_days"]
POWER_BI_URL: str = _SECRETS["power_bi_url"]
BOOTSTRAP_USERS: dict[str, dict[str, Any]] = _SECRETS["bootstrap_users"]

TECHNICAL_ROLE: str = CONFIG.get("roles", {}).get("technical", "technical")
BUSINESS_ROLE: str = CONFIG.get("roles", {}).get("business", "business")


# ------------------------------------------------------------
# 5. Persistent user database and RBAC helpers
# ------------------------------------------------------------

def get_user_db_connection() -> sqlite3.Connection:
    """Return a SQLite connection with row factory set to sqlite3.Row."""
    connection = sqlite3.connect(USER_DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialise_user_database() -> None:
    """Create the users table and seed bootstrap accounts when empty.

    Bootstrap accounts are only inserted if the users table is
    completely empty, ensuring that subsequent deployments do not
    overwrite existing user data.
    """
    with get_user_db_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
                    CHECK (role IN ('technical', 'business')),
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            )
            """
        )

        existing_count = connection.execute(
            "SELECT COUNT(*) AS total FROM users"
        ).fetchone()["total"]

        if existing_count > 0:
            connection.commit()
            return

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for username, user in BOOTSTRAP_USERS.items():
            clean_username = normalise_username(username)

            role = str(user.get("role", BUSINESS_ROLE)).strip().lower()
            if role not in {TECHNICAL_ROLE, BUSINESS_ROLE}:
                role = BUSINESS_ROLE

            connection.execute(
                """
                INSERT INTO users (
                    username, name, email, password_hash, role, is_active,
                    created_at, created_by, updated_at, updated_by
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    clean_username,
                    str(user.get("name", clean_username)).strip(),
                    str(user.get("email", "") or "").strip(),
                    str(user["password"]),
                    role,
                    1,
                    now,
                    "Streamlit Secrets bootstrap",
                    now,
                    "Streamlit Secrets bootstrap",
                ),
            )

        connection.commit()


def normalise_username(username: Any) -> str:
    """Normalise a username by trimming whitespace and lowercasing."""
    return str(username or "").strip().lower()


def get_user_record(username: Any) -> Optional[dict[str, Any]]:
    """Fetch a user record by username.

    Args:
        username: Raw username string.

    Returns:
        A dictionary representing the user record, or None if not found.
    """
    username = normalise_username(username)
    if not username:
        return None

    with get_user_db_connection() as connection:
        row = connection.execute(
            """
            SELECT
                username, name, email, password_hash, role, is_active,
                created_at, created_by, updated_at, updated_by
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

    return dict(row) if row else None


def load_users_dataframe() -> pd.DataFrame:
    """Return all users as a business-friendly dataframe."""
    with get_user_db_connection() as connection:
        return pd.read_sql_query(
            """
            SELECT
                username AS Username,
                name AS Name,
                email AS Email,
                CASE
                    WHEN role = 'technical' THEN 'Technical'
                    ELSE 'Business'
                END AS Role,
                CASE
                    WHEN is_active = 1 THEN 'Active'
                    ELSE 'Inactive'
                END AS Status,
                created_at AS Created,
                created_by AS CreatedBy,
                updated_at AS LastModified,
                updated_by AS ModifiedBy
            FROM users
            ORDER BY role DESC, username
            """,
            connection,
        )


def load_authentication_credentials() -> dict[str, Any]:
    """Return only active users in a streamlit-authenticator format."""
    credentials: dict[str, Any] = {"usernames": {}}

    with get_user_db_connection() as connection:
        rows = connection.execute(
            """
            SELECT username, name, email, password_hash, role
            FROM users
            WHERE is_active = 1
            ORDER BY username
            """
        ).fetchall()

    for row in rows:
        credentials["usernames"][row["username"]] = {
            "name": row["name"],
            "email": row["email"] or "",
            "password": row["password_hash"],
            "role": row["role"],
            "logged_in": False,
        }

    return credentials


# ------------------------------------------------------------
# 6. Password hashing, validation and user administration
# ------------------------------------------------------------

_MIN_PASSWORD_LENGTH = 8


def validate_password(password: str, confirmation: str) -> None:
    """Raise ValueError if a password fails policy checks."""
    password = str(password or "")
    confirmation = str(confirmation or "")

    if password != confirmation:
        raise ValueError("Password confirmation does not match.")

    if len(password) < _MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password must contain at least {_MIN_PASSWORD_LENGTH} characters."
        )

    if password.isspace():
        raise ValueError("Password cannot contain only spaces.")


def hash_password(password: str) -> str:
    """Return a bcrypt password hash suitable for persistent storage."""
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=12),
    ).decode("utf-8")


def count_active_technical_users() -> int:
    """Return the number of active technical administrators."""
    with get_user_db_connection() as connection:
        total = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM users
            WHERE role = 'technical' AND is_active = 1
            """
        ).fetchone()["total"]

    return int(total)


def create_application_user(
    username: str,
    name: str,
    email: str,
    password: str,
    confirmation: str,
    role: str,
    performed_by: str,
) -> None:
    """Create a new application user with validated inputs.

    Raises:
        ValueError: If any input fails validation.
    """
    username = normalise_username(username)
    name = str(name or "").strip()
    email = str(email or "").strip()
    role = str(role or "").strip().lower()

    if not username:
        raise ValueError("Username is required.")

    if not re.fullmatch(r"[a-z0-9._-]+", username):
        raise ValueError(
            "Username may contain only lowercase letters, numbers, "
            "dots, underscores and hyphens."
        )

    if not name:
        raise ValueError("Full name is required.")

    if role not in {TECHNICAL_ROLE, BUSINESS_ROLE}:
        raise ValueError("Role must be Technical or Business.")

    validate_password(password, confirmation)
    password_hash = hash_password(password)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with get_user_db_connection() as connection:
            connection.execute(
                """
                INSERT INTO users (
                    username, name, email, password_hash, role, is_active,
                    created_at, created_by, updated_at, updated_by
                )
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                """,
                (
                    username,
                    name,
                    email,
                    password_hash,
                    role,
                    now,
                    performed_by,
                    now,
                    performed_by,
                ),
            )
            connection.commit()
    except sqlite3.IntegrityError as exc:
        raise ValueError(
            f"The username '{username}' already exists."
        ) from exc


def update_application_user(
    username: str,
    name: str,
    email: str,
    role: str,
    performed_by: str,
) -> None:
    """Update a user's profile and role, protecting the last admin."""
    username = normalise_username(username)
    existing = get_user_record(username)

    if existing is None:
        raise ValueError("The selected user does not exist.")

    name = str(name or "").strip()
    email = str(email or "").strip()
    role = str(role or "").strip().lower()

    if not name:
        raise ValueError("Full name is required.")

    if role not in {TECHNICAL_ROLE, BUSINESS_ROLE}:
        raise ValueError("Role must be Technical or Business.")

    is_last_active_admin = (
        existing["role"] == TECHNICAL_ROLE
        and bool(existing["is_active"])
        and count_active_technical_users() <= 1
    )

    if is_last_active_admin and role != TECHNICAL_ROLE:
        raise ValueError(
            "The final active Technical administrator cannot be "
            "changed to Business."
        )

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_user_db_connection() as connection:
        connection.execute(
            """
            UPDATE users
            SET name = ?, email = ?, role = ?,
                updated_at = ?, updated_by = ?
            WHERE username = ?
            """,
            (name, email, role, now, performed_by, username),
        )
        connection.commit()


def set_application_user_status(
    username: str,
    active: bool,
    performed_by: str,
    current_username: str,
) -> None:
    """Activate or deactivate a user, protecting the last admin."""
    username = normalise_username(username)
    current_username = normalise_username(current_username)
    existing = get_user_record(username)

    if existing is None:
        raise ValueError("The selected user does not exist.")

    active = bool(active)

    if username == current_username and not active:
        raise ValueError(
            "You cannot deactivate your own signed-in account."
        )

    is_last_active_admin = (
        existing["role"] == TECHNICAL_ROLE
        and bool(existing["is_active"])
        and count_active_technical_users() <= 1
    )

    if is_last_active_admin and not active:
        raise ValueError(
            "The final active Technical administrator cannot be "
            "deactivated."
        )

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_user_db_connection() as connection:
        connection.execute(
            """
            UPDATE users
            SET is_active = ?, updated_at = ?, updated_by = ?
            WHERE username = ?
            """,
            (1 if active else 0, now, performed_by, username),
        )
        connection.commit()


def reset_application_user_password(
    username: str,
    password: str,
    confirmation: str,
    performed_by: str,
) -> None:
    """Reset a user's password after policy validation."""
    username = normalise_username(username)

    if get_user_record(username) is None:
        raise ValueError("The selected user does not exist.")

    validate_password(password, confirmation)
    password_hash = hash_password(password)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_user_db_connection() as connection:
        connection.execute(
            """
            UPDATE users
            SET password_hash = ?, updated_at = ?, updated_by = ?
            WHERE username = ?
            """,
            (password_hash, now, performed_by, username),
        )
        connection.commit()


def remove_application_user(
    username: str,
    current_username: str,
) -> None:
    """Permanently delete a user, protecting the last admin."""
    username = normalise_username(username)
    current_username = normalise_username(current_username)
    existing = get_user_record(username)

    if existing is None:
        raise ValueError("The selected user does not exist.")

    if username == current_username:
        raise ValueError(
            "You cannot permanently remove your own signed-in account."
        )

    is_last_active_admin = (
        existing["role"] == TECHNICAL_ROLE
        and bool(existing["is_active"])
        and count_active_technical_users() <= 1
    )

    if is_last_active_admin:
        raise ValueError(
            "The final active Technical administrator cannot be removed."
        )

    with get_user_db_connection() as connection:
        connection.execute(
            "DELETE FROM users WHERE username = ?",
            (username,),
        )
        connection.commit()


initialise_user_database()


# ------------------------------------------------------------
# 7. Audit trail utilities
# ------------------------------------------------------------

_AUDIT_COLUMNS = [
    "EventID",
    "Timestamp",
    "User",
    "Role",
    "Stage",
    "Action",
    "Status",
    "SourceFile",
    "PublicationVersion",
    "Details",
]


def log_audit_event(
    username: str,
    role: str,
    action: str,
    stage: str,
    status: str,
    details: str = "",
    source_file: Optional[str] = None,
    publication_version: Optional[str] = None,
) -> None:
    """Append a single audit event to the persistent audit trail.

    Args:
        username: Acting user, or "unknown" for anonymous events.
        role: Role label associated with the event.
        action: Short description of what occurred.
        stage: Pipeline stage or subsystem the event belongs to.
        status: Typically SUCCESS or FAILED.
        details: Human-readable supplementary information.
        source_file: Optional filename associated with the event.
        publication_version: Optional publication version identifier.
    """
    event_time = datetime.now()
    event_id = "EVT_" + event_time.strftime("%Y%m%d_%H%M%S_%f")

    audit_record = pd.DataFrame(
        {
            "EventID": [event_id],
            "Timestamp": [event_time.strftime("%Y-%m-%d %H:%M:%S")],
            "User": [username],
            "Role": [role],
            "Stage": [stage],
            "Action": [action],
            "Status": [status],
            "SourceFile": [source_file or ""],
            "PublicationVersion": [publication_version or ""],
            "Details": [details],
        }
    )

    audit_record.to_csv(
        AUDIT_LOG_PATH,
        mode="a",
        header=(not AUDIT_LOG_PATH.exists()),
        index=False,
    )


def load_audit_trail() -> pd.DataFrame:
    """Return the persisted audit trail, sorted newest first."""
    if not AUDIT_LOG_PATH.exists():
        return pd.DataFrame(columns=_AUDIT_COLUMNS)

    audit_df = pd.read_csv(
        AUDIT_LOG_PATH,
        dtype=str,
        keep_default_na=False,
    )

    if "Timestamp" in audit_df.columns:
        audit_df = (
            audit_df
            .sort_values(by="Timestamp", ascending=False, kind="stable")
            .reset_index(drop=True)
        )

    return audit_df


# ------------------------------------------------------------
# 8. Authentication and session bootstrap
# ------------------------------------------------------------

_authentication_credentials = load_authentication_credentials()

_authenticator = stauth.Authenticate(
    _authentication_credentials,
    COOKIE_NAME,
    COOKIE_KEY,
    COOKIE_EXPIRY_DAYS,
)

_authenticator.login()

_authentication_status = st.session_state.get("authentication_status")

if _authentication_status is False:
    # Failed login is deliberately recorded so the audit trail
    # captures unsuccessful access attempts alongside successful
    # operations.
    _attempted_username = normalise_username(
        st.session_state.get("username", "") or ""
    ) or "unknown"

    log_audit_event(
        username=_attempted_username,
        role="unknown",
        action="Failed login attempt",
        stage="Authentication",
        status="FAILED",
        details="Invalid credentials or inactive account.",
    )

    st.error(
        "Username or password is incorrect, or the account is inactive."
    )
    st.stop()

if _authentication_status is None:
    st.info("Please log in to continue.")
    st.stop()

current_user = normalise_username(st.session_state.get("username"))
user_data = get_user_record(current_user)

if user_data is None:
    st.error(
        "Your account could not be found in the authorised user store."
    )
    st.stop()

if not bool(user_data["is_active"]):
    st.error("This account has been deactivated.")
    st.stop()

user_role = str(user_data["role"]).lower()
user_name = user_data["name"]

# Role-aware presentation marker, not a permission or authentication control.
_ROLE_MARKER = "rni-business-marker" if user_role == BUSINESS_ROLE else "rni-technical-marker"
st.markdown(f'<span id="{_ROLE_MARKER}" style="display:none"></span>', unsafe_allow_html=True)

st.sidebar.markdown(
    '<div class="rni-sidebar-brand">'
    '<div class="rni-sidebar-logo"><span>▥</span> RNI</div>'
    '<div class="rni-sidebar-tagline">Customer Retention Analytics System</div>'
    '</div>',
    unsafe_allow_html=True,
)
st.sidebar.write(f"Logged in as **{user_name}**")
st.sidebar.caption(f"Role: {user_role.title()}")

_authenticator.logout("Logout", "sidebar")
st.sidebar.divider()


# ------------------------------------------------------------
# 9. Sidebar navigation, session state and pipeline helpers
# ------------------------------------------------------------

_PROTECTED_SESSION_KEYS = {
    "authentication_status",
    "username",
    "name",
    "logout",
}


def reset_pipeline_session() -> None:
    """Clear pipeline session state while preserving authentication."""
    for key in list(st.session_state.keys()):
        if key in _PROTECTED_SESSION_KEYS:
            continue
        if key.startswith("FormSubmitter"):
            continue
        del st.session_state[key]


if user_role == TECHNICAL_ROLE:
    if st.sidebar.button("Reset Pipeline Session", use_container_width=True):
        reset_pipeline_session()
        log_audit_event(
            username=user_name,
            role=user_role,
            action="Pipeline session reset",
            stage="Session Control",
            status="SUCCESS",
            details="Technical user cleared pipeline session state.",
        )
        st.rerun()


if user_role == TECHNICAL_ROLE:
    navigation = st.sidebar.radio(
        "Technical Workspace",
        [
            "Pipeline Overview",
            "Dataset Ingestion",
            "Data Validation",
            "Data Cleaning",
            "RFM Feature Engineering",
            "Model Evaluation",
            "Version & Publish",
            "Audit Trail",
            "User Management",
        ],
        key="technical_navigation",
    )
elif user_role == BUSINESS_ROLE:
    navigation = st.sidebar.radio(
        "Business Workspace",
        [
            "Pipeline Status",
            "Quick Analytics",
            "Power BI Dashboard",
        ],
        key="business_navigation",
    )
else:
    st.error("Your account has an unsupported role.")
    st.stop()


_SESSION_DEFAULTS: dict[str, Any] = {
    "raw_data": None,
    "uploaded_filename": None,
    "selected_sheets": [],
    "ingestion_complete": False,
    "validation_results": None,
    "validation_complete": False,
    "validation_score": None,
    "mba_rules": None,
    "mba_diagnostics": None,
    "cleaned_data": None,
    "cleaning_steps": None,
    "cleaning_summary": None,
    "cleaning_complete": False,
    "rfm_data": None,
    "rfm_summary": None,
    "rfm_complete": False,
    "model_reviewed": False,
    "publication_complete": False,
    "publication_summary": None,
    "published_rfm_data": None,
    "published_at": None,
}

for _key, _value in _SESSION_DEFAULTS.items():
    st.session_state.setdefault(_key, _value)


def reset_publication_state() -> None:
    """Clear only the publication-related session flags."""
    st.session_state.publication_complete = False
    st.session_state.publication_summary = None
    st.session_state.published_rfm_data = None
    st.session_state.published_at = None


def reset_downstream_from_ingestion() -> None:
    """Clear all pipeline stages downstream of ingestion."""
    st.session_state.validation_results = None
    st.session_state.validation_complete = False
    st.session_state.validation_score = None
    st.session_state.mba_rules = None
    st.session_state.mba_diagnostics = None

    st.session_state.cleaned_data = None
    st.session_state.cleaning_steps = None
    st.session_state.cleaning_summary = None
    st.session_state.cleaning_complete = False

    st.session_state.rfm_data = None
    st.session_state.rfm_summary = None
    st.session_state.rfm_complete = False

    st.session_state.model_reviewed = False

    reset_publication_state()


@contextmanager
def loading_overlay(
    message: str = "Please wait while the application processes your request...",
) -> Iterator[None]:
    """Display a fixed overlay while a long-running block executes."""
    overlay = st.empty()
    overlay.markdown(
        f"""
        <div style="
            position: fixed;
            inset: 0;
            z-index: 999999;
            background: rgba(255,255,255,0.94);
            display: flex;
            align-items: center;
            justify-content: center;">
            <div style="
                max-width: 460px;
                padding: 1.7rem 2.1rem;
                border-radius: 14px;
                background: white;
                border: 1px solid rgba(0,0,0,0.10);
                box-shadow: 0 12px 35px rgba(0,0,0,0.15);
                text-align: center;">
                <div style="
                    width: 44px;
                    height: 44px;
                    margin: 0 auto 0.9rem auto;
                    border: 4px solid #e8ecf1;
                    border-top-color: #1a5276;
                    border-radius: 50%;
                    animation: rni_spin 1s linear infinite;">
                </div>
                <div style="font-size:1.15rem;font-weight:700;color:#1a2a4a;">
                    Loading, please wait...
                </div>
                <div style="font-size:0.92rem;color:#555;margin-top:0.35rem;">
                    {message}
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    try:
        yield
    finally:
        overlay.empty()


def render_inline_loading(message: str) -> Any:
    """Render an inline loading banner and return the placeholder.

    The caller is expected to call ``placeholder.empty()`` once the
    page has finished rendering so the banner is not visible after
    the workspace has loaded.

    Args:
        message: Short loading message.

    Returns:
        A Streamlit placeholder that can be cleared later.
    """
    placeholder = st.empty()
    placeholder.markdown(
        f"""
        <div class="rni-inline-loading">
            <div class="spinner"></div>
            <div class="text">{message}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    return placeholder


def go_to_technical_page(page_name: str) -> None:
    """Set the technical navigation target to a specific page."""
    st.session_state["technical_navigation"] = page_name


def render_proceed_button(
    label: str,
    target_page: str,
    key: str,
) -> None:
    """Render a standard next-step button after a completed stage."""
    st.write("")
    st.button(
        label,
        type="primary",
        key=key,
        on_click=go_to_technical_page,
        args=(target_page,),
    )


def render_pipeline_breadcrumb() -> None:
    """Render current source dataset and publication version at the top of a page."""
    source_label = st.session_state.get("uploaded_filename") or "No dataset loaded"

    publication_summary = st.session_state.get("publication_summary")
    if publication_summary:
        publication_label = publication_summary.get(
            "publication_version", "Not available"
        )
    else:
        publication_label = "Not yet published"

    st.markdown(
        f"""
        <div class="pipeline-breadcrumb">
            <strong>Source:</strong> {source_label}
            &nbsp;|&nbsp;
            <strong>Publication:</strong> {publication_label}
        </div>
        """,
        unsafe_allow_html=True,
    )
    # ------------------------------------------------------------
# 10. Country standardisation and geographic validation
# ------------------------------------------------------------

_COUNTRY_RENAME_MAP: dict[str, str] = {
    "eire": "Ireland",
    "ireland": "Ireland",
    "usa": "United States",
    "us": "United States",
    "u s a": "United States",
    "u s": "United States",
    "united states": "United States",
    "united states of america": "United States",
    "rsa": "South Africa",
    "south africa": "South Africa",
    "korea": "South Korea",
    "south korea": "South Korea",
    "republic of korea": "South Korea",
    "uk": "United Kingdom",
    "u k": "United Kingdom",
    "united kingdom": "United Kingdom",
    "great britain": "United Kingdom",
}

_KNOWN_REPORTING_COUNTRIES: set[str] = {
    "Australia", "Austria", "Bahrain", "Belgium", "Bermuda", "Botswana",
    "Brazil", "Canada", "Cyprus", "Czech Republic", "Denmark", "Finland",
    "France", "Germany", "Greece", "Hong Kong", "Iceland", "Ireland",
    "Israel", "Italy", "Japan", "Lebanon", "Lithuania", "Malta",
    "Netherlands", "Nigeria", "Norway", "Poland", "Portugal",
    "Saudi Arabia", "Singapore", "South Africa", "South Korea", "Spain",
    "Sweden", "Switzerland", "Thailand", "United Arab Emirates",
    "United Kingdom", "United States",
}

_COUNTRY_MAP_EXCLUSIONS: set[str] = {
    "Unspecified",
    "European Community",
    "West Indies",
    "Channel Islands",
}


def normalise_country_key(value: Any) -> str:
    """Return a comparison key for a country label.

    Case, punctuation and repeated whitespace are ignored so that
    aliases such as "UK" and "United Kingdom" map to the same key.
    """
    if pd.isna(value):
        return ""

    text = re.sub(r"\s+", " ", str(value).strip())
    text = re.sub(r"[^a-z0-9]+", " ", text.casefold())
    return re.sub(r"\s+", " ", text).strip()


_CANONICAL_COUNTRY_BY_KEY: dict[str, str] = {
    normalise_country_key(country): country
    for country in _KNOWN_REPORTING_COUNTRIES
}

_COUNTRY_EXCLUSION_BY_KEY: dict[str, str] = {
    normalise_country_key(country): country
    for country in _COUNTRY_MAP_EXCLUSIONS
}


def standardise_country_value(value: Any) -> Any:
    """Standardise a single country label.

    Known aliases are mapped to a canonical reporting name. Values
    that are recognised but not countries (for example, "European
    Community") are preserved as excluded labels. Unresolved values
    are returned unchanged so they remain available for audit.
    """
    if pd.isna(value):
        return pd.NA

    cleaned = re.sub(r"\s+", " ", str(value).strip())
    if not cleaned:
        return pd.NA

    key = normalise_country_key(cleaned)

    if key in _COUNTRY_RENAME_MAP:
        return _COUNTRY_RENAME_MAP[key]

    if key in _CANONICAL_COUNTRY_BY_KEY:
        return _CANONICAL_COUNTRY_BY_KEY[key]

    if key in _COUNTRY_EXCLUSION_BY_KEY:
        return _COUNTRY_EXCLUSION_BY_KEY[key]

    return cleaned


def standardise_country_names(series: pd.Series) -> pd.Series:
    """Return a Series of reporting-ready country labels."""
    return series.astype("string").map(standardise_country_value)


def assess_country_labels(series: pd.Series) -> dict[str, list[str]]:
    """Classify unique country labels as recognised, excluded or unresolved."""
    source = (
        series.astype("string")
        .str.strip()
        .str.replace(r"\s+", " ", regex=True)
        .dropna()
    )
    source = source[source.ne("")]

    unique_source = list(dict.fromkeys(source.tolist()))
    recognised: list[str] = []
    excluded: list[str] = []
    unresolved: list[str] = []

    for raw_label in unique_source:
        standardised = standardise_country_value(raw_label)
        key = normalise_country_key(standardised)

        if key in _COUNTRY_EXCLUSION_BY_KEY:
            excluded.append(str(standardised))
        elif key in _CANONICAL_COUNTRY_BY_KEY:
            recognised.append(str(standardised))
        else:
            unresolved.append(str(raw_label))

    return {
        "recognised": sorted(set(recognised)),
        "excluded": sorted(set(excluded)),
        "unresolved": sorted(set(unresolved)),
    }


# ------------------------------------------------------------
# 11. Shared data utilities
# ------------------------------------------------------------

def completed_sales_view(df: Optional[pd.DataFrame]) -> pd.DataFrame:
    """Return the analytical sales view, excluding cancellations and returns."""
    if df is None or df.empty:
        return pd.DataFrame()

    working = df.copy()

    if "IsCompletedSale" in working.columns:
        return working.loc[working["IsCompletedSale"].fillna(False)].copy()

    mask = pd.Series(True, index=working.index)

    if "IsCancellation" in working.columns:
        mask &= ~working["IsCancellation"].fillna(False)

    if "Quantity" in working.columns:
        mask &= pd.to_numeric(working["Quantity"], errors="coerce").gt(0)

    if "Price" in working.columns:
        mask &= pd.to_numeric(working["Price"], errors="coerce").gt(0)

    return working.loc[mask].copy()


def get_data_period(
    df: Optional[pd.DataFrame],
) -> tuple[Optional[pd.Timestamp], Optional[pd.Timestamp]]:
    """Return the first and last valid completed-sale dates."""
    if df is None or df.empty or "InvoiceDate" not in df.columns:
        return None, None

    working = completed_sales_view(df)
    if working.empty:
        working = df.copy()

    dates = pd.to_datetime(working["InvoiceDate"], errors="coerce").dropna()
    if dates.empty:
        return None, None

    return dates.min(), dates.max()


def format_business_date(value: Any) -> str:
    """Format a date as "D Mon YYYY" for business-facing captions."""
    if value is None or pd.isna(value):
        return "Unavailable"

    parsed = pd.to_datetime(value, errors="coerce")
    if pd.isna(parsed):
        return str(value)

    return f"{parsed.day} {parsed.strftime('%b %Y')}"


def resolve_publication_data_period(
    publication_record: Optional[dict[str, Any]] = None,
    transactions_df: Optional[pd.DataFrame] = None,
) -> tuple[Optional[pd.Timestamp], Optional[pd.Timestamp]]:
    """Read the governed data period from a publication record with fallback."""
    start_value = None
    through_value = None

    if publication_record is not None:
        start_value = publication_record.get("DataStartDate")
        through_value = publication_record.get("DataThroughDate")

    start_parsed = pd.to_datetime(start_value, errors="coerce")
    through_parsed = pd.to_datetime(through_value, errors="coerce")

    if pd.isna(start_parsed) or pd.isna(through_parsed):
        fallback_start, fallback_through = get_data_period(transactions_df)
        if pd.isna(start_parsed):
            start_parsed = fallback_start
        if pd.isna(through_parsed):
            through_parsed = fallback_through

    return start_parsed, through_parsed


def calculate_data_quality_score(
    validation_results: Optional[pd.DataFrame],
) -> float:
    """Return a transparent 0-100 score for a validation dataframe."""
    if validation_results is None or validation_results.empty:
        return 0.0

    weights = {"PASS": 1.0, "WARNING": 0.5, "FAIL": 0.0}

    values = (
        validation_results["Status"]
        .astype(str)
        .str.upper()
        .map(weights)
        .fillna(0.0)
    )

    return float(values.mean() * 100)


@st.cache_data(show_spinner=False)
def read_csv_cached(path_text: str, modified_time: int) -> pd.DataFrame:
    """Read published CSV files with consistent StockCode typing."""
    del modified_time

    df = pd.read_csv(path_text)

    if "StockCode" in df.columns:
        df["StockCode"] = df["StockCode"].astype("string")

    return df


def safe_read_published_csv(path: Path) -> Optional[pd.DataFrame]:
    """Read a published CSV using a modification-aware cache."""
    path = Path(path)
    if not path.exists():
        return None

    return read_csv_cached(str(path), path.stat().st_mtime_ns)


def build_invoice_summary(cleaned_df: Optional[pd.DataFrame]) -> pd.DataFrame:
    """Build one governed row per invoice, retaining cancellations."""
    if cleaned_df is None or cleaned_df.empty:
        return pd.DataFrame()

    df = cleaned_df.copy()

    if "Revenue" not in df.columns:
        df["Revenue"] = (
            pd.to_numeric(df["Quantity"], errors="coerce").fillna(0)
            * pd.to_numeric(df["Price"], errors="coerce").fillna(0)
        )

    aggregation = {
        "InvoiceDate": "min",
        "Customer ID": "first",
        "Country": "first",
        "IsCancellation": "max",
        "Quantity": "sum",
        "Revenue": "sum",
    }

    invoice_summary = (
        df.groupby("Invoice", dropna=False)
        .agg(aggregation)
        .reset_index()
        .rename(columns={"Quantity": "TotalQuantity", "Revenue": "InvoiceValue"})
    )

    if "Description" in df.columns:
        unique_products = (
            df.groupby("Invoice", dropna=False)["Description"]
            .nunique(dropna=True)
            .rename("UniqueProducts")
            .reset_index()
        )
        invoice_summary = invoice_summary.merge(
            unique_products, on="Invoice", how="left"
        )

    invoice_summary["IsCompletedSale"] = (
        ~invoice_summary["IsCancellation"].fillna(False)
        & invoice_summary["TotalQuantity"].gt(0)
        & invoice_summary["InvoiceValue"].gt(0)
    )

    return invoice_summary


def build_rfm_customer_features(
    cleaned_df: Optional[pd.DataFrame],
    rfm_df: Optional[pd.DataFrame],
) -> pd.DataFrame:
    """Build reusable customer features from completed sales only."""
    sales = completed_sales_view(cleaned_df)

    if sales.empty or rfm_df is None or rfm_df.empty:
        return rfm_df.copy() if rfm_df is not None else pd.DataFrame()

    sales = sales.dropna(subset=["Customer ID", "InvoiceDate"]).copy()
    sales["Customer ID"] = pd.to_numeric(sales["Customer ID"], errors="coerce")
    sales = sales.dropna(subset=["Customer ID"]).copy()
    sales["Customer ID"] = sales["Customer ID"].astype(int)

    invoice_level = (
        sales[["Customer ID", "Invoice", "InvoiceDate", "Revenue"]]
        .groupby(["Customer ID", "Invoice"], as_index=False)
        .agg(
            InvoiceDate=("InvoiceDate", "min"),
            InvoiceValue=("Revenue", "sum"),
        )
    )

    observation_date = sales["InvoiceDate"].max()
    recent_start = observation_date - pd.Timedelta(days=60)
    prior_start = observation_date - pd.Timedelta(days=120)

    customer_features = (
        sales.groupby("Customer ID")
        .agg(
            AverageQuantityPerLine=("Quantity", "mean"),
            ProductDiversity=("Description", "nunique"),
            FirstPurchase=("InvoiceDate", "min"),
            LastPurchaseFeature=("InvoiceDate", "max"),
        )
        .reset_index()
    )

    order_features = (
        invoice_level.groupby("Customer ID")
        .agg(
            Orders=("Invoice", "nunique"),
            AverageOrderValue=("InvoiceValue", "mean"),
            TotalOrderValue=("InvoiceValue", "sum"),
        )
        .reset_index()
    )

    customer_features = customer_features.merge(
        order_features, on="Customer ID", how="left"
    )

    customer_features["CustomerTenureDays"] = (
        observation_date - customer_features["FirstPurchase"]
    ).dt.days

    gaps = (
        invoice_level.sort_values(["Customer ID", "InvoiceDate"])
        .assign(
            GapDays=lambda x: x.groupby("Customer ID")["InvoiceDate"]
            .diff()
            .dt.total_seconds()
            .div(86400)
        )
        .groupby("Customer ID")["GapDays"]
        .mean()
        .rename("AverageDaysBetweenOrders")
        .reset_index()
    )

    recent_counts = (
        invoice_level.loc[invoice_level["InvoiceDate"] > recent_start]
        .groupby("Customer ID")["Invoice"]
        .nunique()
        .rename("Recent60dOrders")
    )

    prior_counts = (
        invoice_level.loc[
            invoice_level["InvoiceDate"].gt(prior_start)
            & invoice_level["InvoiceDate"].le(recent_start)
        ]
        .groupby("Customer ID")["Invoice"]
        .nunique()
        .rename("Prior60dOrders")
    )

    customer_features = customer_features.merge(
        gaps, on="Customer ID", how="left"
    )
    customer_features = customer_features.merge(
        pd.concat([recent_counts, prior_counts], axis=1).fillna(0).reset_index(),
        on="Customer ID",
        how="left",
    )

    for column in ("Recent60dOrders", "Prior60dOrders"):
        customer_features[column] = (
            customer_features[column].fillna(0).astype(int)
        )

    customer_features["OrderFrequencyTrend"] = (
        customer_features["Recent60dOrders"]
        - customer_features["Prior60dOrders"]
    )

    return rfm_df.merge(customer_features, on="Customer ID", how="left")


def build_customer_summary(
    reporting_df: pd.DataFrame,
    rfm_features_df: Optional[pd.DataFrame],
    risk_df: Optional[pd.DataFrame],
    transactions_df: Optional[pd.DataFrame] = None,
) -> pd.DataFrame:
    """Build the business-facing Customer 360 master dataset.

    The final customer summary is assembled from four sources:

    1. ``reporting_df`` — RFM scores, segments, risk level and priority.
    2. ``rfm_features_df`` — behavioural features such as average order
       value, product diversity and order frequency trend.
    3. ``risk_df`` — approved predictive risk outputs.
    4. ``transactions_df`` — used only to attach each customer's
       primary country of record, which is required for geographic
       reporting in the Streamlit business workspace and in Power BI.

    Args:
        reporting_df: RFM reporting dataframe.
        rfm_features_df: Reusable customer feature dataframe.
        risk_df: Approved predictive risk dataframe.
        transactions_df: Cleaned transaction dataframe, used to source
            each customer's most frequent country of record.

    Returns:
        A Customer 360 dataframe including a ``Country`` column.
    """
    customer_summary = reporting_df.copy()

    if rfm_features_df is not None and not rfm_features_df.empty:
        extra_columns = [
            column
            for column in rfm_features_df.columns
            if column == "Customer ID" or column not in customer_summary.columns
        ]
        customer_summary = customer_summary.merge(
            rfm_features_df[extra_columns],
            on="Customer ID",
            how="left",
        )

    if risk_df is not None and not risk_df.empty:
        risk_customer_column = None
        for candidate in (
            "Customer ID",
            "CustomerID",
            "customer_id",
            "Customer_ID",
        ):
            if candidate in risk_df.columns:
                risk_customer_column = candidate
                break

        if risk_customer_column is not None:
            risk_copy = risk_df.copy()
            risk_copy[risk_customer_column] = pd.to_numeric(
                risk_copy[risk_customer_column], errors="coerce"
            )
            risk_copy = risk_copy.dropna(
                subset=[risk_customer_column]
            ).copy()
            risk_copy[risk_customer_column] = risk_copy[
                risk_customer_column
            ].astype(int)

            if risk_customer_column != "Customer ID":
                risk_copy = risk_copy.rename(
                    columns={risk_customer_column: "Customer ID"}
                )

            risk_columns = [
                column
                for column in risk_copy.columns
                if column == "Customer ID"
                or column not in customer_summary.columns
            ]

            customer_summary = customer_summary.merge(
                risk_copy[risk_columns].drop_duplicates(
                    subset=["Customer ID"]
                ),
                on="Customer ID",
                how="left",
            )

    # Attach each customer's primary country of record. Sourced from
    # the cleaned transaction layer because RFM aggregation does not
    # carry geographic attributes through the pipeline by default.
    if (
        transactions_df is not None
        and not transactions_df.empty
        and "Country" in transactions_df.columns
        and "Customer ID" in transactions_df.columns
    ):
        transaction_country = transactions_df.copy()
        transaction_country["Customer ID"] = pd.to_numeric(
            transaction_country["Customer ID"], errors="coerce"
        )
        transaction_country = transaction_country.dropna(
            subset=["Customer ID"]
        ).copy()
        transaction_country["Customer ID"] = transaction_country[
            "Customer ID"
        ].astype(int)

        transaction_country = transaction_country.dropna(
            subset=["Country"]
        ).copy()

        if not transaction_country.empty:
            transaction_country["Country"] = standardise_country_names(
                transaction_country["Country"]
            )

            completed_country_source = transaction_country
            if "IsCompletedSale" in completed_country_source.columns:
                completed_country_source = completed_country_source.loc[
                    completed_country_source["IsCompletedSale"].fillna(False)
                ].copy()

            if completed_country_source.empty:
                completed_country_source = transaction_country

            primary_country = (
                completed_country_source
                .groupby(["Customer ID", "Country"])
                .size()
                .reset_index(name="Occurrences")
                .sort_values(
                    ["Customer ID", "Occurrences"],
                    ascending=[True, False],
                )
                .drop_duplicates(subset=["Customer ID"], keep="first")
                [["Customer ID", "Country"]]
            )

            if "Country" in customer_summary.columns:
                customer_summary = customer_summary.drop(
                    columns=["Country"]
                )

            customer_summary = customer_summary.merge(
                primary_country,
                on="Customer ID",
                how="left",
            )

    if "Country" not in customer_summary.columns:
        customer_summary["Country"] = "Unavailable"

    return customer_summary


def build_data_validation_report(
    validation_results: Optional[pd.DataFrame],
    cleaning_steps: Optional[pd.DataFrame] = None,
) -> pd.DataFrame:
    """Build one auditable validation report for the team outputs."""
    validation = (
        validation_results.copy()
        if validation_results is not None
        else pd.DataFrame(
            columns=["Check", "Status", "Count", "Details"]
        )
    )

    validation["Stage"] = "Pre-Cleaning Validation"
    validation["QualityScore"] = calculate_data_quality_score(validation)

    if cleaning_steps is None or cleaning_steps.empty:
        return validation

    cleaning = cleaning_steps.copy()
    cleaning_report = pd.DataFrame(
        {
            "Check": cleaning["Step"].astype(str),
            "Status": "INFO",
            "Count": cleaning["Rows Removed"],
            "Details": cleaning["Action"].astype(str),
            "Stage": "Cleaning Audit",
            "QualityScore": calculate_data_quality_score(validation),
        }
    )

    return pd.concat([validation, cleaning_report], ignore_index=True)



def compute_market_basket(
    cleaned_df: Optional[pd.DataFrame],
    min_support: float = 0.005,
    min_confidence: float = 0.15,
    min_lift: float = 1.0,
    top_n_products: int = 50,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Calculate product-pair association rules with reduced memory use."""

    diagnostics: dict[str, Any] = {
        "status": "Not run",
        "input_rows": 0,
        "eligible_rows": 0,
        "eligible_invoices": 0,
        "products_analysed": 0,
        "frequent_itemsets": 0,
        "rules_before_lift": 0,
        "rules_after_lift": 0,
    }

    if not MLXTEND_AVAILABLE:
        diagnostics["status"] = "mlxtend is not installed"
        return pd.DataFrame(), diagnostics

    if cleaned_df is None or cleaned_df.empty:
        diagnostics["status"] = "No transaction data available"
        return pd.DataFrame(), diagnostics

    diagnostics["input_rows"] = len(cleaned_df)

    required = {"Invoice", "Description", "Quantity"}
    if not required.issubset(cleaned_df.columns):
        diagnostics["status"] = "Required product fields are missing"
        return pd.DataFrame(), diagnostics

    # Select only the columns required for MBA and sales filtering.
    columns = [
        column
        for column in (
            "Invoice",
            "Description",
            "Quantity",
            "StockCode",
            "IsCompletedSale",
            "IsCancellation",
            "Price",
        )
        if column in cleaned_df.columns
    ]

    sales = completed_sales_view(cleaned_df[columns])

    if sales.empty:
        diagnostics["status"] = "No completed sales available"
        return pd.DataFrame(), diagnostics

    sales = sales.dropna(
        subset=["Invoice", "Description"]
    ).copy()

    sales["Description"] = (
        sales["Description"].astype("string").str.strip()
    )

    sales = sales.loc[
        sales["Description"].notna()
        & sales["Description"].ne("")
    ]

    # Exclude administrative and non-product stock codes.
    if "StockCode" in sales.columns:
        stock = (
            sales["StockCode"]
            .astype("string")
            .str.upper()
            .str.strip()
        )

        admin_mask = stock.str.match(
            r"^(POST|DOT|M|D|BANK CHARGES|AMAZONFEE|S|CRUK)$",
            na=False,
        )

        sales = sales.loc[~admin_mask]

    diagnostics["eligible_rows"] = len(sales)
    diagnostics["eligible_invoices"] = int(
        sales["Invoice"].nunique()
    )

    if diagnostics["eligible_invoices"] < 2:
        diagnostics["status"] = (
            "Too few invoices for association analysis"
        )
        return pd.DataFrame(), diagnostics

    try:
        # Identify the highest-volume products.
        top_products = (
            sales.groupby("Description")["Quantity"]
            .sum()
            .nlargest(int(top_n_products))
            .index
        )

        sales = sales.loc[
            sales["Description"].isin(top_products),
            ["Invoice", "Description", "Quantity"]
        ]

        diagnostics["products_analysed"] = int(
            sales["Description"].nunique()
        )

        if sales.empty:
            diagnostics["status"] = "No eligible products found"
            return pd.DataFrame(), diagnostics

        # Remove repeat invoice-product combinations.
        # Completed-sale quantities are already positive.
        transactions = sales[
            ["Invoice", "Description"]
        ].drop_duplicates()

        # Build Boolean invoice-by-product matrix.
        basket = pd.crosstab(
            transactions["Invoice"],
            transactions["Description"]
        ).gt(0)

        del transactions
        del sales

        # Restrict Apriori to individual items and pairs.
        frequent_itemsets = apriori(
            basket,
            min_support=float(min_support),
            use_colnames=True,
            max_len=2,
            low_memory=True,
        )

        diagnostics["frequent_itemsets"] = len(
            frequent_itemsets
        )

        del basket

        if frequent_itemsets.empty:
            diagnostics["status"] = (
                "No frequent itemsets at the selected support"
            )
            return pd.DataFrame(), diagnostics

        rules = association_rules(
            frequent_itemsets,
            metric="confidence",
            min_threshold=float(min_confidence),
        )

        diagnostics["rules_before_lift"] = len(rules)

        rules = rules.loc[
            rules["lift"] >= float(min_lift)
        ].copy()

        diagnostics["rules_after_lift"] = len(rules)

        if rules.empty:
            diagnostics["status"] = (
                "No rules meet the selected confidence/lift thresholds"
            )
            return pd.DataFrame(), diagnostics

        rules["Antecedents"] = rules["antecedents"].apply(
            lambda items: ", ".join(sorted(map(str, items)))
        )

        rules["Consequents"] = rules["consequents"].apply(
            lambda items: ", ".join(sorted(map(str, items)))
        )

        output = (
            rules[
                [
                    "Antecedents",
                    "Consequents",
                    "support",
                    "confidence",
                    "lift",
                ]
            ]
            .sort_values(
                ["lift", "confidence", "support"],
                ascending=False,
            )
            .reset_index(drop=True)
        )

        diagnostics["status"] = "Success"
        return output, diagnostics

    except (ValueError, KeyError, TypeError, MemoryError) as exc:
        diagnostics["status"] = (
            f"Analysis error: {type(exc).__name__}: {exc}"
        )
        return pd.DataFrame(), diagnostics

# ------------------------------------------------------------
# 12a. Data ingestion helpers
# ------------------------------------------------------------

def get_excel_sheet_names(uploaded_file: Any) -> list[str]:
    """Return the list of sheet names in an uploaded Excel workbook."""
    workbook_bytes = uploaded_file.getvalue()
    with pd.ExcelFile(io.BytesIO(workbook_bytes)) as workbook:
        return workbook.sheet_names


def load_uploaded_data(
    uploaded_file: Any,
    selected_sheets: Optional[list[str]] = None,
) -> pd.DataFrame:
    """Load an uploaded CSV or Excel file into a dataframe.

    Multiple Excel sheets are combined only if their schemas match.

    Args:
        uploaded_file: A Streamlit UploadedFile instance.
        selected_sheets: Sheet names to load for Excel files.

    Returns:
        A combined dataframe.

    Raises:
        ValueError: If the file type is unsupported, no sheets are
            selected, or the selected sheets have mismatched schemas.
    """
    filename = uploaded_file.name.lower()

    if filename.endswith(".csv"):
        return pd.read_csv(io.BytesIO(uploaded_file.getvalue()))

    if not filename.endswith(".xlsx"):
        raise ValueError(
            "Unsupported file type. Upload a CSV or XLSX file."
        )

    if not selected_sheets:
        raise ValueError(
            "Select at least one Excel sheet before loading the dataset."
        )

    sheets = pd.read_excel(
        io.BytesIO(uploaded_file.getvalue()),
        sheet_name=list(selected_sheets),
    )

    if len(sheets) == 0:
        raise ValueError("No Excel sheets were loaded.")

    first_sheet_name = list(sheets.keys())[0]
    reference_columns = list(sheets[first_sheet_name].columns)

    incompatible_sheets = [
        sheet_name
        for sheet_name, sheet_df in sheets.items()
        if list(sheet_df.columns) != reference_columns
    ]

    if incompatible_sheets:
        raise ValueError(
            "Selected Excel sheets do not have matching structures. "
            "Incompatible sheet(s): " + ", ".join(incompatible_sheets)
        )

    return pd.concat(sheets.values(), ignore_index=True)


# ------------------------------------------------------------
# 12b. Data validation
# ------------------------------------------------------------

_REQUIRED_COLUMNS: list[str] = [
    "Invoice",
    "StockCode",
    "Description",
    "Quantity",
    "InvoiceDate",
    "Price",
    "Customer ID",
    "Country",
]


def validate_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Run the pre-cleaning validation suite on a raw dataframe.

    Args:
        df: Raw uploaded dataset.

    Returns:
        A dataframe with one row per validation check.
    """
    results: list[dict[str, Any]] = []

    missing_columns = [c for c in _REQUIRED_COLUMNS if c not in df.columns]

    if missing_columns:
        results.append(
            {
                "Check": "Required Schema",
                "Status": "FAIL",
                "Count": len(missing_columns),
                "Details": "Missing required columns: "
                + ", ".join(missing_columns),
            }
        )
        return pd.DataFrame(results)

    results.append(
        {
            "Check": "Required Schema",
            "Status": "PASS",
            "Count": 0,
            "Details": "All required columns are present.",
        }
    )

    country_assessment = assess_country_labels(df["Country"])

    results.append(
        {
            "Check": "Recognised Country Labels",
            "Status": "PASS",
            "Count": len(country_assessment["recognised"]),
            "Details": (
                f"{len(country_assessment['recognised'])} unique country "
                "label(s) are recognised after case-insensitive "
                "standardisation."
            ),
        }
    )

    excluded_labels = country_assessment["excluded"]
    results.append(
        {
            "Check": "Excluded Aggregate Country Labels",
            "Status": "PASS",
            "Count": len(excluded_labels),
            "Details": (
                "Retained for audit but excluded from the world map: "
                + ", ".join(excluded_labels)
                if excluded_labels
                else "No aggregate/non-country geography labels detected."
            ),
        }
    )

    unresolved_labels = country_assessment["unresolved"]
    results.append(
        {
            "Check": "Unresolved Country Labels",
            "Status": "WARNING" if unresolved_labels else "PASS",
            "Count": len(unresolved_labels),
            "Details": (
                "Review these labels before reporting: "
                + ", ".join(unresolved_labels)
                if unresolved_labels
                else "All country labels are recognised or explicitly "
                "excluded from mapping."
            ),
        }
    )

    missing_customer_ids = int(df["Customer ID"].isna().sum())
    results.append(
        {
            "Check": "Missing Customer IDs",
            "Status": "WARNING" if missing_customer_ids else "PASS",
            "Count": missing_customer_ids,
            "Details": (
                "Missing Customer IDs detected. These records may remain "
                "available for transaction-level analysis but cannot be "
                "used for customer-level RFM analysis."
                if missing_customer_ids
                else "No missing Customer IDs detected."
            ),
        }
    )

    missing_descriptions = int(df["Description"].isna().sum())
    results.append(
        {
            "Check": "Missing Descriptions",
            "Status": "WARNING" if missing_descriptions else "PASS",
            "Count": missing_descriptions,
            "Details": (
                "Some product descriptions are missing."
                if missing_descriptions
                else "No missing product descriptions detected."
            ),
        }
    )

    duplicate_rows = int(df.duplicated().sum())
    results.append(
        {
            "Check": "Exact Duplicate Rows",
            "Status": "WARNING" if duplicate_rows else "PASS",
            "Count": duplicate_rows,
            "Details": (
                "Exact duplicate records were detected."
                if duplicate_rows
                else "No exact duplicate records detected."
            ),
        }
    )

    invoice_text = (
        df["Invoice"].astype(str).str.strip().str.upper()
    )
    cancellation_count = int(invoice_text.str.startswith("C").sum())

    results.append(
        {
            "Check": "Cancellation Transactions",
            "Status": "WARNING" if cancellation_count else "PASS",
            "Count": cancellation_count,
            "Details": (
                "Invoices beginning with C were detected."
                if cancellation_count
                else "No cancellation invoices detected."
            ),
        }
    )

    quantity_numeric = pd.to_numeric(df["Quantity"], errors="coerce")
    invalid_quantity = int(quantity_numeric.isna().sum())
    results.append(
        {
            "Check": "Invalid Quantity Values",
            "Status": "FAIL" if invalid_quantity else "PASS",
            "Count": invalid_quantity,
            "Details": (
                "Some Quantity values could not be interpreted as numbers."
                if invalid_quantity
                else "Quantity values are numeric."
            ),
        }
    )

    negative_quantity = int((quantity_numeric < 0).sum())
    results.append(
        {
            "Check": "Negative Quantities",
            "Status": "WARNING" if negative_quantity else "PASS",
            "Count": negative_quantity,
            "Details": (
                "Negative quantities may represent returns or adjustments."
                if negative_quantity
                else "No negative quantities detected."
            ),
        }
    )

    zero_quantity = int((quantity_numeric == 0).sum())
    results.append(
        {
            "Check": "Zero Quantities",
            "Status": "WARNING" if zero_quantity else "PASS",
            "Count": zero_quantity,
            "Details": (
                "Zero quantity transactions were detected."
                if zero_quantity
                else "No zero quantities detected."
            ),
        }
    )

    price_numeric = pd.to_numeric(df["Price"], errors="coerce")
    invalid_price = int(price_numeric.isna().sum())
    results.append(
        {
            "Check": "Invalid Price Values",
            "Status": "FAIL" if invalid_price else "PASS",
            "Count": invalid_price,
            "Details": (
                "Some Price values could not be interpreted as numbers."
                if invalid_price
                else "Price values are numeric."
            ),
        }
    )

    negative_price = int((price_numeric < 0).sum())
    results.append(
        {
            "Check": "Negative Prices",
            "Status": "WARNING" if negative_price else "PASS",
            "Count": negative_price,
            "Details": (
                "Negative prices were detected and require review."
                if negative_price
                else "No negative prices detected."
            ),
        }
    )

    zero_price = int((price_numeric == 0).sum())
    results.append(
        {
            "Check": "Zero Prices",
            "Status": "WARNING" if zero_price else "PASS",
            "Count": zero_price,
            "Details": (
                "Zero-price transactions were detected."
                if zero_price
                else "No zero prices detected."
            ),
        }
    )

    parsed_dates = pd.to_datetime(df["InvoiceDate"], errors="coerce")
    invalid_dates = int(parsed_dates.isna().sum())
    results.append(
        {
            "Check": "Invalid Invoice Dates",
            "Status": "FAIL" if invalid_dates else "PASS",
            "Count": invalid_dates,
            "Details": (
                "Some InvoiceDate values could not be converted to valid dates."
                if invalid_dates
                else "All InvoiceDate values are valid."
            ),
        }
    )

    return pd.DataFrame(results)


# ------------------------------------------------------------
# 12c. Data cleaning
# ------------------------------------------------------------

def clean_dataset(
    df: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    """Clean and standardise a raw transaction dataframe.

    Cancellations and returns are preserved as flagged records so
    they remain available for cancellation reporting, while a
    boolean ``IsCompletedSale`` flag identifies the subset of rows
    eligible for revenue, RFM, product and predictive analytics.

    Args:
        df: Raw transaction dataframe.

    Returns:
        A tuple of (cleaned dataframe, cleaning steps table,
        cleaning summary dictionary).
    """
    raw_df = df.copy()
    summary_rows: list[dict[str, Any]] = []
    starting_rows = len(raw_df)

    summary_rows.append(
        {
            "Step": "Raw dataset",
            "Rows Before": starting_rows,
            "Rows Removed": 0,
            "Rows After": starting_rows,
            "Action": "Preserved source data before cleaning.",
        }
    )

    before_duplicates = len(raw_df)
    prepared_df = raw_df.drop_duplicates().copy()
    after_duplicates = len(prepared_df)
    duplicates_removed = before_duplicates - after_duplicates

    summary_rows.append(
        {
            "Step": "Exact duplicate removal",
            "Rows Before": before_duplicates,
            "Rows Removed": duplicates_removed,
            "Rows After": after_duplicates,
            "Action": "Removed only completely identical transaction rows.",
        }
    )

    for column in ("Invoice", "StockCode"):
        prepared_df[column] = prepared_df[column].astype(str).str.strip()

    prepared_df["Country"] = standardise_country_names(prepared_df["Country"])
    prepared_df["Description"] = (
        prepared_df["Description"].astype("string").str.strip()
    )

    prepared_df["InvoiceDate"] = pd.to_datetime(
        prepared_df["InvoiceDate"], errors="coerce"
    )
    prepared_df["Quantity"] = pd.to_numeric(
        prepared_df["Quantity"], errors="coerce"
    )
    prepared_df["Price"] = pd.to_numeric(
        prepared_df["Price"], errors="coerce"
    )
    prepared_df["Customer ID"] = pd.to_numeric(
        prepared_df["Customer ID"], errors="coerce"
    )

    summary_rows.append(
        {
            "Step": "Type and format standardisation",
            "Rows Before": len(prepared_df),
            "Rows Removed": 0,
            "Rows After": len(prepared_df),
            "Action": "Standardised identifiers/text and converted "
            "date/numeric fields.",
        }
    )

    prepared_df["IsCancellation"] = (
        prepared_df["Invoice"].str.upper().str.startswith("C")
    )
    cancellation_count = int(prepared_df["IsCancellation"].sum())

    summary_rows.append(
        {
            "Step": "Cancellation identification",
            "Rows Before": len(prepared_df),
            "Rows Removed": 0,
            "Rows After": len(prepared_df),
            "Action": (
                f"Flagged and preserved {cancellation_count:,} "
                "cancellation/return rows; they remain available for "
                "cancellation reporting."
            ),
        }
    )

    before_invalid = len(prepared_df)
    valid_core_mask = (
        prepared_df["InvoiceDate"].notna()
        & prepared_df["Quantity"].notna()
        & prepared_df["Price"].notna()
    )
    cleaned_df = prepared_df.loc[valid_core_mask].copy()
    invalid_removed = before_invalid - len(cleaned_df)

    summary_rows.append(
        {
            "Step": "Invalid core field removal",
            "Rows Before": before_invalid,
            "Rows Removed": invalid_removed,
            "Rows After": len(cleaned_df),
            "Action": (
                "Removed only rows with unusable InvoiceDate, Quantity "
                "or Price values. Valid cancellations and returns were "
                "retained."
            ),
        }
    )

    cleaned_df["Revenue"] = cleaned_df["Quantity"] * cleaned_df["Price"]
    cleaned_df["IsCompletedSale"] = (
        ~cleaned_df["IsCancellation"]
        & cleaned_df["Quantity"].gt(0)
        & cleaned_df["Price"].gt(0)
    )

    cleaned_df["TransactionType"] = "Other / Adjustment"
    cleaned_df.loc[
        cleaned_df["IsCancellation"], "TransactionType"
    ] = "Cancellation / Return"
    cleaned_df.loc[
        cleaned_df["IsCompletedSale"], "TransactionType"
    ] = "Completed Sale"

    cleaned_df["Year"] = cleaned_df["InvoiceDate"].dt.year
    cleaned_df["Month"] = cleaned_df["InvoiceDate"].dt.month
    cleaned_df["MonthName"] = cleaned_df["InvoiceDate"].dt.month_name()
    cleaned_df["Quarter"] = cleaned_df["InvoiceDate"].dt.quarter
    cleaned_df["Day"] = cleaned_df["InvoiceDate"].dt.day
    cleaned_df["DayOfWeek"] = cleaned_df["InvoiceDate"].dt.day_name()
    cleaned_df["Hour"] = cleaned_df["InvoiceDate"].dt.hour

    completed_sales_rows = int(cleaned_df["IsCompletedSale"].sum())
    cancellation_rows = int(cleaned_df["IsCancellation"].sum())
    non_analytical_rows = int((~cleaned_df["IsCompletedSale"]).sum())

    summary_rows.append(
        {
            "Step": "Analytical eligibility",
            "Rows Before": len(cleaned_df),
            "Rows Removed": 0,
            "Rows After": len(cleaned_df),
            "Action": (
                f"Flagged {completed_sales_rows:,} completed-sale rows "
                f"for revenue/RFM/product analysis while preserving "
                f"{non_analytical_rows:,} non-sale rows."
            ),
        }
    )

    final_rows = len(cleaned_df)
    total_removed = starting_rows - final_rows
    retained_percentage = (
        (final_rows / starting_rows) * 100 if starting_rows > 0 else 0
    )
    missing_customer_ids = int(cleaned_df["Customer ID"].isna().sum())

    final_summary: dict[str, Any] = {
        "starting_rows": starting_rows,
        "prepared_rows": len(prepared_df),
        "duplicates_removed": duplicates_removed,
        "cancellations_identified": cancellation_count,
        "invalid_core_rows_removed": invalid_removed,
        "completed_sales_rows": completed_sales_rows,
        "cancellation_rows": cancellation_rows,
        "non_analytical_rows": non_analytical_rows,
        "final_rows": final_rows,
        "total_removed": total_removed,
        "retained_percentage": retained_percentage,
        "missing_customer_ids": missing_customer_ids,
        "final_columns": len(cleaned_df.columns),
    }

    return cleaned_df, pd.DataFrame(summary_rows), final_summary


# ------------------------------------------------------------
# 12d. RFM feature engineering
# ------------------------------------------------------------

def assign_rfm_segment(score: int) -> str:
    """Map a composite RFM score to a business-friendly segment label."""
    if score >= 13:
        return "Champions"
    if score >= 10:
        return "Loyal Customers"
    if score >= 7:
        return "Potential Loyalists"
    if score >= 5:
        return "At Risk"
    return "Lost / Low Value"


def build_rfm_features(
    cleaned_df: pd.DataFrame,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Build customer-level RFM features from completed sales only.

    Args:
        cleaned_df: Cleaned transaction dataframe.

    Returns:
        A tuple of (RFM dataframe, summary dictionary).

    Raises:
        ValueError: If required fields are missing, no identifiable
            customers exist, or the customer count is too small for
            quintile scoring.
    """
    required_columns = ["Customer ID", "Invoice", "InvoiceDate", "Revenue"]
    missing_columns = [c for c in required_columns if c not in cleaned_df.columns]

    if missing_columns:
        raise ValueError(
            "RFM feature engineering cannot continue. Missing required "
            "fields: " + ", ".join(missing_columns)
        )

    analytical_sales = completed_sales_view(cleaned_df)

    rfm_df = analytical_sales.dropna(subset=["Customer ID"]).copy()

    if rfm_df.empty:
        raise ValueError(
            "No identifiable customer records are available for RFM analysis."
        )

    rfm_df["Customer ID"] = pd.to_numeric(
        rfm_df["Customer ID"], errors="coerce"
    )
    rfm_df = rfm_df.dropna(subset=["Customer ID"]).copy()
    rfm_df["Customer ID"] = rfm_df["Customer ID"].astype(int)

    unique_customers = int(rfm_df["Customer ID"].nunique())

    if unique_customers < 5:
        raise ValueError(
            "At least 5 identifiable customers are required for "
            "quintile-based RFM scoring."
        )

    observation_date = rfm_df["InvoiceDate"].max()

    if pd.isna(observation_date):
        raise ValueError(
            "A valid observation date could not be determined."
        )

    customer_invoices = rfm_df[
        ["Customer ID", "Invoice", "InvoiceDate"]
    ].drop_duplicates()

    customer_recency = (
        customer_invoices.groupby("Customer ID")["InvoiceDate"]
        .max()
        .reset_index()
        .rename(columns={"InvoiceDate": "LastPurchase"})
    )
    customer_recency["Recency"] = (
        (observation_date - customer_recency["LastPurchase"])
        .dt.total_seconds()
        / (24 * 60 * 60)
    )

    customer_frequency = (
        customer_invoices.groupby("Customer ID")["Invoice"]
        .nunique()
        .reset_index()
        .rename(columns={"Invoice": "Frequency"})
    )

    customer_monetary = (
        rfm_df.groupby("Customer ID")["Revenue"]
        .sum()
        .reset_index()
        .rename(columns={"Revenue": "Monetary"})
    )

    rfm = (
        customer_recency
        .merge(customer_frequency, on="Customer ID", how="inner")
        .merge(customer_monetary, on="Customer ID", how="inner")
    )

    rfm["R_Score"] = pd.qcut(
        rfm["Recency"], q=5, labels=[5, 4, 3, 2, 1], duplicates="drop"
    ).astype(int)
    rfm["F_Score"] = pd.qcut(
        rfm["Frequency"].rank(method="first"),
        q=5,
        labels=[1, 2, 3, 4, 5],
    ).astype(int)
    rfm["M_Score"] = pd.qcut(
        rfm["Monetary"].rank(method="first"),
        q=5,
        labels=[1, 2, 3, 4, 5],
    ).astype(int)

    rfm["RFM_Score"] = rfm["R_Score"] + rfm["F_Score"] + rfm["M_Score"]
    rfm["RFM_Segment"] = rfm["RFM_Score"].apply(assign_rfm_segment)

    rfm["AtRisk60"] = rfm["Recency"] >= 60
    rfm["RiskLevel"] = rfm["AtRisk60"].map(
        {True: "At Risk", False: "Active"}
    )

    rfm = rfm[
        [
            "Customer ID",
            "LastPurchase",
            "Recency",
            "Frequency",
            "Monetary",
            "R_Score",
            "F_Score",
            "M_Score",
            "RFM_Score",
            "RFM_Segment",
            "AtRisk60",
            "RiskLevel",
        ]
    ].copy()

    segment_counts = (
        rfm["RFM_Segment"]
        .value_counts()
        .rename_axis("RFM Segment")
        .reset_index(name="Customers")
    )
    segment_counts["Percentage"] = (
        segment_counts["Customers"] / len(rfm) * 100
    )

    risk_counts = (
        rfm["RiskLevel"]
        .value_counts()
        .rename_axis("Risk Level")
        .reset_index(name="Customers")
    )
    risk_counts["Percentage"] = risk_counts["Customers"] / len(rfm) * 100

    summary: dict[str, Any] = {
        "clean_transaction_rows": len(cleaned_df),
        "identifiable_transaction_rows": len(rfm_df),
        "customers": len(rfm),
        "observation_date": observation_date,
        "purchase_events": len(customer_invoices),
        "columns": len(rfm.columns),
        "mean_recency": rfm["Recency"].mean(),
        "mean_frequency": rfm["Frequency"].mean(),
        "mean_monetary": rfm["Monetary"].mean(),
        "median_recency": rfm["Recency"].median(),
        "median_frequency": rfm["Frequency"].median(),
        "median_monetary": rfm["Monetary"].median(),
        "at_risk_customers": int(rfm["AtRisk60"].sum()),
        "active_customers": int((~rfm["AtRisk60"]).sum()),
        "duplicate_customers": int(rfm["Customer ID"].duplicated().sum()),
        "missing_rfm_values": int(
            rfm[["Recency", "Frequency", "Monetary"]].isna().sum().sum()
        ),
        "segment_counts": segment_counts,
        "risk_counts": risk_counts,
    }

    return rfm, summary


# ------------------------------------------------------------
# 13. Publication, versioning and Power BI hand-off
# ------------------------------------------------------------

def build_reporting_dataset(
    rfm_df: pd.DataFrame,
) -> tuple[pd.DataFrame, float]:
    """Add HighValue and Priority indicators to an RFM dataframe."""
    reporting_df = rfm_df.copy()
    high_value_threshold = reporting_df["Monetary"].quantile(0.75)

    reporting_df["HighValue"] = reporting_df["Monetary"] >= high_value_threshold
    reporting_df["Priority"] = "Standard"

    reporting_df.loc[
        reporting_df["AtRisk60"] & reporting_df["HighValue"], "Priority"
    ] = "High Priority"

    reporting_df.loc[
        reporting_df["AtRisk60"] & ~reporting_df["HighValue"], "Priority"
    ] = "Retention Opportunity"

    return reporting_df, high_value_threshold


def publish_pipeline_outputs(
    cleaned_df: pd.DataFrame,
    rfm_df: pd.DataFrame,
    source_filename: str,
    username: str,
    validation_results: Optional[pd.DataFrame] = None,
    cleaning_steps: Optional[pd.DataFrame] = None,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Publish the governed application and team outputs.

    Writes the seven team deliverables, the Power BI hand-off
    datasets, the archive copies, and appends a publication record
    to the manifest.

    Args:
        cleaned_df: Cleaned transaction dataframe.
        rfm_df: RFM customer dataframe.
        source_filename: Original uploaded filename.
        username: Publishing user's display name.
        validation_results: Pre-cleaning validation dataframe.
        cleaning_steps: Cleaning audit dataframe.

    Returns:
        A tuple of (reporting dataframe, publication summary).

    Raises:
        FileNotFoundError: If approved model artifacts are missing.
        ValueError: If predictive label mapping is invalid.
    """
    publication_time = datetime.now()
    timestamp = publication_time.strftime("%Y%m%d_%H%M%S_%f")
    publication_version = f"PUB_{timestamp}"
    publication_display_time = publication_time.strftime("%Y-%m-%d %H:%M:%S")

    data_start_date, data_through_date = get_data_period(cleaned_df)
    data_start_iso = (
        data_start_date.strftime("%Y-%m-%d")
        if data_start_date is not None and not pd.isna(data_start_date)
        else ""
    )
    data_through_iso = (
        data_through_date.strftime("%Y-%m-%d")
        if data_through_date is not None and not pd.isna(data_through_date)
        else ""
    )

    reporting_df, high_value_threshold = build_reporting_dataset(rfm_df)

    cv_source = MODEL_ARTIFACT_DIR / "model_cv_results.csv"
    temporal_source = MODEL_ARTIFACT_DIR / "temporal_test_predictions.csv"

    if not cv_source.exists():
        raise FileNotFoundError(
            f"Approved model artifact not found: {cv_source}"
        )

    if not temporal_source.exists():
        raise FileNotFoundError(
            f"Approved temporal prediction artifact not found: {temporal_source}"
        )

    model_cv_df = pd.read_csv(cv_source)
    temporal_df = pd.read_csv(temporal_source)

    required_prediction_columns = {
        "PredictedRetentionRisk",
        "PredictedRiskLevel",
    }

    if required_prediction_columns.issubset(temporal_df.columns):
        invalid_mapping = temporal_df.loc[
            (
                temporal_df["PredictedRetentionRisk"].eq(1)
                & temporal_df["PredictedRiskLevel"].ne("At Risk")
            )
            | (
                temporal_df["PredictedRetentionRisk"].eq(0)
                & temporal_df["PredictedRiskLevel"].ne("Retained")
            )
        ]

        if not invalid_mapping.empty:
            raise ValueError(
                "Predictive label mapping failed: 1 must mean At Risk "
                "and 0 must mean Retained."
            )

    invoice_summary_df = build_invoice_summary(cleaned_df)
    rfm_customer_features_df = build_rfm_customer_features(cleaned_df, rfm_df)
    final_customer_risk_prediction_df = temporal_df.copy()
    customer_summary_df = build_customer_summary(
        reporting_df,
        rfm_customer_features_df,
        final_customer_risk_prediction_df,
        transactions_df=cleaned_df,
    )
    validation_report_df = build_data_validation_report(
        validation_results, cleaning_steps
    )

    team_outputs = {
        "clean_transactions": cleaned_df,
        "customer_rfm": rfm_df,
        "customer_summary": customer_summary_df,
        "data_validation_report": validation_report_df,
        "final_customer_risk_prediction": final_customer_risk_prediction_df,
        "invoice_summary": invoice_summary_df,
        "rfm_customer_features": rfm_customer_features_df,
    }

    team_paths: dict[str, Path] = {}
    team_archive_paths: dict[str, Path] = {}

    for output_name, output_df in team_outputs.items():
        latest_path = TEAM_OUTPUT_DIR / f"{output_name}.csv"
        archive_path = ARCHIVE_DIR / f"{output_name}_{timestamp}.csv"
        output_df.to_csv(latest_path, index=False)
        output_df.to_csv(archive_path, index=False)
        team_paths[output_name] = latest_path
        team_archive_paths[output_name] = archive_path

    clean_archive_path = ARCHIVE_DIR / f"clean_transactions_{timestamp}.csv"
    rfm_archive_path = ARCHIVE_DIR / f"rfm_analysis_dataset_{timestamp}.csv"
    cv_archive_path = ARCHIVE_DIR / f"model_cv_results_{timestamp}.csv"
    temporal_archive_path = (
        ARCHIVE_DIR / f"temporal_test_predictions_{timestamp}.csv"
    )

    latest_clean_path = PUBLISH_DIR / "latest_clean_transactions.csv"
    latest_rfm_path = PUBLISH_DIR / "latest_rfm_analysis_dataset.csv"
    latest_cv_path = PUBLISH_DIR / "latest_model_cv_results.csv"
    latest_temporal_path = PUBLISH_DIR / "latest_temporal_test_predictions.csv"

    power_bi_rfm_path = POWER_BI_DIR / "rfm_analysis_dataset.csv"
    power_bi_cv_path = POWER_BI_DIR / "model_cv_results.csv"
    power_bi_temporal_path = POWER_BI_DIR / "temporal_test_predictions.csv"
    power_bi_customer_summary_path = POWER_BI_DIR / "customer_summary.csv"
    power_bi_clean_transactions_path = POWER_BI_DIR / "clean_transactions.csv"
    power_bi_invoice_summary_path = POWER_BI_DIR / "invoice_summary.csv"

    manifest_path = PUBLISH_DIR / "publication_manifest.csv"

    cleaned_df.to_csv(clean_archive_path, index=False)
    reporting_df.to_csv(rfm_archive_path, index=False)
    model_cv_df.to_csv(cv_archive_path, index=False)
    temporal_df.to_csv(temporal_archive_path, index=False)

    cleaned_df.to_csv(latest_clean_path, index=False)
    reporting_df.to_csv(latest_rfm_path, index=False)
    model_cv_df.to_csv(latest_cv_path, index=False)
    temporal_df.to_csv(latest_temporal_path, index=False)

    reporting_df.to_csv(power_bi_rfm_path, index=False)
    model_cv_df.to_csv(power_bi_cv_path, index=False)
    temporal_df.to_csv(power_bi_temporal_path, index=False)
    customer_summary_df.to_csv(power_bi_customer_summary_path, index=False)
    cleaned_df.to_csv(power_bi_clean_transactions_path, index=False)
    invoice_summary_df.to_csv(power_bi_invoice_summary_path, index=False)

    high_value_customers = int(reporting_df["HighValue"].sum())
    high_value_at_risk = int(
        (reporting_df["HighValue"] & reporting_df["AtRisk60"]).sum()
    )

    priority_counts = (
        reporting_df["Priority"]
        .value_counts()
        .rename_axis("Priority")
        .reset_index(name="Customers")
    )

    if "PredictedRiskLevel" in temporal_df.columns:
        predicted_counts = (
            temporal_df["PredictedRiskLevel"]
            .value_counts()
            .rename_axis("PredictedRiskLevel")
            .reset_index(name="Customers")
        )
        predicted_at_risk = int(
            temporal_df["PredictedRiskLevel"].eq("At Risk").sum()
        )
        predicted_retained = int(
            temporal_df["PredictedRiskLevel"].eq("Retained").sum()
        )
    else:
        predicted_counts = pd.DataFrame(
            columns=["PredictedRiskLevel", "Customers"]
        )
        predicted_at_risk = 0
        predicted_retained = 0

    manifest_record = pd.DataFrame(
        {
            "PublicationTimestamp": [publication_display_time],
            "PublicationVersion": [publication_version],
            "PublishedBy": [username],
            "SourceFile": [source_filename],
            "DataStartDate": [data_start_iso],
            "DataThroughDate": [data_through_iso],
            "CleanRows": [len(cleaned_df)],
            "RFMRows": [len(reporting_df)],
            "RFMColumns": [len(reporting_df.columns)],
            "HighValueThreshold": [high_value_threshold],
            "HighValueAtRisk": [high_value_at_risk],
            "ModelCVRows": [len(model_cv_df)],
            "TemporalPredictionRows": [len(temporal_df)],
            "PredictedAtRisk": [predicted_at_risk],
            "PredictedRetained": [predicted_retained],
            "DataQualityScore": [
                calculate_data_quality_score(validation_results)
            ],
            "PowerBIRFMFile": [power_bi_rfm_path.name],
            "PowerBICVFile": [power_bi_cv_path.name],
            "PowerBITemporalFile": [power_bi_temporal_path.name],
            "PowerBICustomerSummaryFile": [
                power_bi_customer_summary_path.name
            ],
            "PowerBICleanTransactionsFile": [
                power_bi_clean_transactions_path.name
            ],
            "PowerBIInvoiceSummaryFile": [
                power_bi_invoice_summary_path.name
            ],
        }
    )

    if manifest_path.exists():
        existing_manifest = pd.read_csv(manifest_path)
        publication_manifest = pd.concat(
            [existing_manifest, manifest_record], ignore_index=True
        )
    else:
        publication_manifest = manifest_record.copy()

    publication_manifest.to_csv(manifest_path, index=False)

    publication_summary: dict[str, Any] = {
        "publication_time": publication_display_time,
        "publication_version": publication_version,
        "published_by": username,
        "source_filename": source_filename,
        "data_start_date": data_start_iso,
        "data_through_date": data_through_iso,
        "clean_rows": len(cleaned_df),
        "rfm_rows": len(reporting_df),
        "rfm_columns": len(reporting_df.columns),
        "high_value_threshold": high_value_threshold,
        "high_value_customers": high_value_customers,
        "high_value_at_risk": high_value_at_risk,
        "priority_counts": priority_counts,
        "model_cv_rows": len(model_cv_df),
        "temporal_rows": len(temporal_df),
        "predicted_at_risk": predicted_at_risk,
        "predicted_retained": predicted_retained,
        "predicted_counts": predicted_counts,
        "data_quality_score": calculate_data_quality_score(
            validation_results
        ),
        "clean_archive_path": clean_archive_path,
        "rfm_archive_path": rfm_archive_path,
        "cv_archive_path": cv_archive_path,
        "temporal_archive_path": temporal_archive_path,
        "latest_clean_path": latest_clean_path,
        "latest_rfm_path": latest_rfm_path,
        "latest_cv_path": latest_cv_path,
        "latest_temporal_path": latest_temporal_path,
        "power_bi_rfm_path": power_bi_rfm_path,
        "power_bi_cv_path": power_bi_cv_path,
        "power_bi_temporal_path": power_bi_temporal_path,
        "power_bi_customer_summary_path": power_bi_customer_summary_path,
        "power_bi_clean_transactions_path": power_bi_clean_transactions_path,
        "power_bi_invoice_summary_path": power_bi_invoice_summary_path,
        "team_paths": team_paths,
        "team_archive_paths": team_archive_paths,
        "manifest_path": manifest_path,
    }

    return reporting_df, publication_summary
    # ============================================================
# 14. Technical workspace
# ============================================================

# Branded header switches descriptions by workspace without changing navigation.
if user_role == TECHNICAL_ROLE:
    _workspace_label = "TECHNICAL WORKSPACE"
    _workspace_summary = "Controlled ingestion, validation, RFM modelling and publication to Power BI."
else:
    _workspace_label = "BUSINESS WORKSPACE"
    _workspace_summary = "Read-only customer retention insights and approved Power BI reporting."

st.markdown(
    '<div class="rni-identity">'
    f'<div class="rni-eyebrow">{_workspace_label}</div>'
    '<div class="rni-identity-title">RNI Customer Retention System</div>'
    f'<div class="rni-identity-subtitle">{_workspace_summary}</div>'
    '</div>',
    unsafe_allow_html=True,
)


if user_role == TECHNICAL_ROLE:

    # --------------------------------------------------------
    # 14a. Pipeline Overview
    # --------------------------------------------------------
    if navigation == "Pipeline Overview":
        render_pipeline_breadcrumb()

        st.header("Pipeline Overview")
        st.write(
            "This workspace is used by authorised Technical users to "
            "ingest, validate, clean and prepare customer data before "
            "publication to the Power BI reporting layer."
        )

        top1, top2, top3 = st.columns(3)
        top1.metric(
            "Dataset",
            "Loaded" if st.session_state.ingestion_complete else "Not Loaded",
        )
        top2.metric(
            "Validation",
            "Completed" if st.session_state.validation_complete else "Not Run",
        )
        top3.metric(
            "Cleaning",
            "Completed" if st.session_state.cleaning_complete else "Not Run",
        )

        bottom1, bottom2 = st.columns(2)
        bottom1.metric(
            "RFM",
            "Completed" if st.session_state.rfm_complete else "Not Run",
        )
        bottom2.metric(
            "Power BI Handoff",
            "Published" if st.session_state.publication_complete else "Not Published",
        )

    # --------------------------------------------------------
    # 14b. Dataset Ingestion
    # --------------------------------------------------------
    elif navigation == "Dataset Ingestion":
        render_pipeline_breadcrumb()

        st.header("Dataset Ingestion")
        st.write(
            "Upload the retail transaction dataset that will enter the "
            "controlled customer-retention preparation pipeline."
        )
        st.caption(
            "Supported formats: CSV and Excel (.xlsx). No data cleaning "
            "is performed during ingestion."
        )

        uploaded_file = st.file_uploader(
            "Upload retail dataset",
            type=["csv", "xlsx"],
        )

        selected_sheets: Optional[list[str]] = None

        if uploaded_file is not None:
            st.subheader("File Information")
            file_col1, file_col2, file_col3 = st.columns(3)
            file_col1.metric("File Name", uploaded_file.name)

            file_size_mb = uploaded_file.size / (1024 * 1024)
            file_col2.metric("File Size", f"{file_size_mb:.2f} MB")

            file_extension = uploaded_file.name.split(".")[-1].upper()
            file_col3.metric("File Type", file_extension)

            is_excel = uploaded_file.name.lower().endswith(".xlsx")

            if is_excel:
                try:
                    sheet_names = get_excel_sheet_names(uploaded_file)
                    st.subheader("Excel Sheets")
                    st.write(
                        f"Workbook contains **{len(sheet_names)}** sheet(s)."
                    )

                    selected_sheets = st.multiselect(
                        "Select the sheet(s) to ingest",
                        options=sheet_names,
                        default=(
                            sheet_names if len(sheet_names) == 1 else []
                        ),
                        help=(
                            "For multi-sheet workbooks, select only the "
                            "sheets that belong to the same transaction "
                            "structure."
                        ),
                    )
                    st.session_state["selected_sheets"] = selected_sheets

                except (ValueError, IOError) as sheet_error:
                    st.error(
                        f"Unable to inspect Excel workbook: {sheet_error}"
                    )

            st.divider()

            combining_multiple_sheets = bool(
                is_excel and selected_sheets and len(selected_sheets) > 1
            )

            sheet_combination_approved = True
            if combining_multiple_sheets:
                st.warning(
                    "Combining multiple sheets merges them into a single "
                    "transaction stream. Confirm you have verified that "
                    "the selected sheets share the same schema."
                )
                sheet_combination_approved = st.checkbox(
                    "I have verified that the selected sheets share the "
                    "same schema and should be combined.",
                    value=False,
                )

            if is_excel and selected_sheets:
                load_label = (
                    "Combine Selected Sheets and Continue"
                    if combining_multiple_sheets
                    else "Load Sheet and Continue"
                )
            else:
                load_label = "Load Dataset"

            load_disabled = bool(is_excel and not selected_sheets) or (
                combining_multiple_sheets and not sheet_combination_approved
            )

            if st.button(load_label, type="primary", disabled=load_disabled):
                try:
                    with loading_overlay(
                        "Reading the selected source data and preparing "
                        "the ingestion preview."
                    ):
                        raw_df = load_uploaded_data(
                            uploaded_file, selected_sheets
                        )

                    st.session_state.raw_data = raw_df
                    st.session_state.uploaded_filename = uploaded_file.name
                    st.session_state.ingestion_complete = True

                    reset_downstream_from_ingestion()

                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="Dataset loaded",
                        stage="Dataset Ingestion",
                        status="SUCCESS",
                        source_file=uploaded_file.name,
                        details=(
                            f"Loaded {len(raw_df):,} rows and "
                            f"{len(raw_df.columns)} columns."
                        ),
                    )

                    st.success("Dataset loaded successfully.")

                except (ValueError, IOError) as load_error:
                    st.session_state.raw_data = None
                    st.session_state.ingestion_complete = False
                    reset_downstream_from_ingestion()

                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="Dataset load attempted",
                        stage="Dataset Ingestion",
                        status="FAILED",
                        source_file=(
                            uploaded_file.name if uploaded_file else ""
                        ),
                        details=str(load_error),
                    )

                    st.error(f"Dataset could not be loaded: {load_error}")

        if (
            st.session_state.ingestion_complete
            and st.session_state.raw_data is not None
        ):
            raw_df = st.session_state.raw_data
            st.divider()

            st.subheader("Ingestion Summary")
            summary_col1, summary_col2, summary_col3 = st.columns(3)
            summary_col1.metric("Rows Loaded", f"{len(raw_df):,}")
            summary_col2.metric("Columns", len(raw_df.columns))
            summary_col3.metric(
                "Source File", st.session_state.uploaded_filename
            )

            st.subheader("Detected Columns")
            column_profile_df = pd.DataFrame(
                {
                    "Column": raw_df.columns,
                    "Data Type": raw_df.dtypes.astype(str).values,
                    "Non-Null Count": raw_df.notna().sum().values,
                    "Unique Values": [
                        raw_df[c].nunique() for c in raw_df.columns
                    ],
                }
            )
            st.dataframe(
                column_profile_df, width="stretch", hide_index=True
            )

            st.subheader("Raw Data Preview")
            st.caption(
                "Rows highlighted in pink are cancellation invoices. "
                "Rows highlighted in amber have missing Customer IDs."
            )

            def _highlight_preview_rows(row: pd.Series) -> list[str]:
                invoice_value = str(row.get("Invoice", ""))
                if invoice_value.startswith("C"):
                    return ["background-color: #fdecea"] * len(row)
                if pd.isna(row.get("Customer ID")):
                    return ["background-color: #fef6e0"] * len(row)
                return [""] * len(row)

            preview_df = raw_df.head(20).copy()
            try:
                styled_preview = preview_df.style.apply(
                    _highlight_preview_rows, axis=1
                )
                st.dataframe(styled_preview, width="stretch")
            except Exception:
                st.dataframe(preview_df, width="stretch")

            render_proceed_button(
                "Proceed to Data Validation",
                "Data Validation",
                "proceed_ingestion_to_validation",
            )

    # --------------------------------------------------------
    # 14c. Data Validation
    # --------------------------------------------------------
    elif navigation == "Data Validation":
        render_pipeline_breadcrumb()

        st.header("Data Validation")
        st.write(
            "Assess the uploaded source data before cleaning or "
            "analytical transformation."
        )

        if (
            not st.session_state.ingestion_complete
            or st.session_state.raw_data is None
        ):
            st.warning("Load a dataset in Dataset Ingestion first.")

        else:
            if st.button("Run Data Validation", type="primary"):
                try:
                    with loading_overlay(
                        "Checking schema, missing values, duplicates, "
                        "cancellations and field validity."
                    ):
                        validation_results = validate_dataset(
                            st.session_state.raw_data
                        )

                    st.session_state.validation_score = (
                        calculate_data_quality_score(validation_results)
                    )
                    st.session_state.validation_results = validation_results
                    st.session_state.validation_complete = True

                    st.session_state.cleaned_data = None
                    st.session_state.cleaning_steps = None
                    st.session_state.cleaning_summary = None
                    st.session_state.cleaning_complete = False

                    st.session_state.rfm_data = None
                    st.session_state.rfm_summary = None
                    st.session_state.rfm_complete = False

                    st.session_state.model_reviewed = False

                    reset_publication_state()

                    failed_checks = int(
                        validation_results["Status"].eq("FAIL").sum()
                    )
                    warning_checks = int(
                        validation_results["Status"].eq("WARNING").sum()
                    )

                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="Data validation completed",
                        stage="Data Validation",
                        status="SUCCESS",
                        source_file=(
                            st.session_state.uploaded_filename or ""
                        ),
                        details=(
                            f"Validation completed with {failed_checks} "
                            f"failed checks and {warning_checks} warnings."
                        ),
                    )

                    st.success("Data validation completed.")

                except (ValueError, KeyError) as validation_error:
                    st.session_state.validation_results = None
                    st.session_state.validation_complete = False

                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="Data validation attempted",
                        stage="Data Validation",
                        status="FAILED",
                        source_file=(
                            st.session_state.uploaded_filename or ""
                        ),
                        details=str(validation_error),
                    )

                    st.error(
                        f"Validation failed: {validation_error}"
                    )

            if st.session_state.validation_results is not None:
                validation_results = st.session_state.validation_results
                st.divider()

                st.subheader("Validation Results")

                passed = int(
                    validation_results["Status"].eq("PASS").sum()
                )
                warnings = int(
                    validation_results["Status"].eq("WARNING").sum()
                )
                failed = int(
                    validation_results["Status"].eq("FAIL").sum()
                )
                quality_score = calculate_data_quality_score(
                    validation_results
                )

                score_col1, score_col2, score_col3, score_col4 = st.columns(4)
                score_col1.metric(
                    "Data Quality Score", f"{quality_score:.1f}%"
                )
                score_col2.metric("Passed", passed)
                score_col3.metric("Warnings", warnings)
                score_col4.metric("Failed", failed)

                st.dataframe(
                    validation_results,
                    width="stretch",
                    hide_index=True,
                )

                country_validation = validation_results.loc[
                    validation_results["Check"].isin(
                        [
                            "Recognised Country Labels",
                            "Excluded Aggregate Country Labels",
                            "Unresolved Country Labels",
                        ]
                    )
                ].copy()

                if not country_validation.empty:
                    with st.expander(
                        "Country Mapping Status", expanded=True
                    ):
                        country_lookup = country_validation.set_index(
                            "Check"
                        )

                        recognised_count = (
                            int(
                                country_lookup.loc[
                                    "Recognised Country Labels", "Count"
                                ]
                            )
                            if "Recognised Country Labels"
                            in country_lookup.index
                            else 0
                        )
                        excluded_count = (
                            int(
                                country_lookup.loc[
                                    "Excluded Aggregate Country Labels",
                                    "Count",
                                ]
                            )
                            if "Excluded Aggregate Country Labels"
                            in country_lookup.index
                            else 0
                        )
                        unresolved_count = (
                            int(
                                country_lookup.loc[
                                    "Unresolved Country Labels", "Count"
                                ]
                            )
                            if "Unresolved Country Labels"
                            in country_lookup.index
                            else 0
                        )

                        country_col1, country_col2, country_col3 = (
                            st.columns(3)
                        )
                        country_col1.metric("Recognised", recognised_count)
                        country_col2.metric(
                            "Excluded / Aggregate", excluded_count
                        )
                        country_col3.metric(
                            "Unresolved", unresolved_count
                        )

                        unresolved_row = country_validation.loc[
                            country_validation["Check"].eq(
                                "Unresolved Country Labels"
                            )
                        ]
                        if unresolved_count > 0 and not unresolved_row.empty:
                            st.warning(
                                str(unresolved_row.iloc[0]["Details"])
                            )
                        else:
                            st.success(
                                "All geography labels are ready for "
                                "governed reporting or explicitly "
                                "excluded from country-level mapping."
                            )

                if failed > 0:
                    st.error(
                        "One or more critical validation checks failed."
                    )
                elif warnings > 0:
                    st.warning(
                        "Validation completed with warnings. Review the "
                        "findings before cleaning."
                    )
                else:
                    st.success("All validation checks passed.")

                if st.session_state.validation_complete and failed == 0:
                    render_proceed_button(
                        "Proceed to Data Cleaning",
                        "Data Cleaning",
                        "proceed_validation_to_cleaning",
                    )

    # --------------------------------------------------------
    # 14d. Data Cleaning
    # --------------------------------------------------------
    elif navigation == "Data Cleaning":
        render_pipeline_breadcrumb()

        st.header("Data Cleaning")
        st.write(
            "Apply the verified transaction preparation rules used by "
            "the customer-retention analysis."
        )

        if (
            not st.session_state.validation_complete
            or st.session_state.raw_data is None
        ):
            st.warning("Complete Data Validation before cleaning.")

        else:
            validation_results = st.session_state.validation_results
            critical_failures = int(
                validation_results["Status"].eq("FAIL").sum()
            )

            if critical_failures > 0:
                st.error(
                    "Cleaning cannot continue while critical validation "
                    "failures remain."
                )

            elif st.button("Run Data Cleaning", type="primary"):
                try:
                    with loading_overlay(
                        "Standardising transactions, preserving "
                        "cancellations and assigning analysis flags."
                    ):
                        (
                            cleaned_df,
                            cleaning_steps,
                            cleaning_summary,
                        ) = clean_dataset(st.session_state.raw_data)

                    st.session_state.cleaned_data = cleaned_df
                    st.session_state.cleaning_steps = cleaning_steps
                    st.session_state.cleaning_summary = cleaning_summary
                    st.session_state.cleaning_complete = True

                    st.session_state.rfm_data = None
                    st.session_state.rfm_summary = None
                    st.session_state.rfm_complete = False

                    st.session_state.model_reviewed = False

                    reset_publication_state()

                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="Data cleaning completed",
                        stage="Data Cleaning",
                        status="SUCCESS",
                        source_file=(
                            st.session_state.uploaded_filename or ""
                        ),
                        details=(
                            f"Cleaned dataset contains "
                            f"{len(cleaned_df):,} qualifying rows."
                        ),
                    )

                    st.success("Data cleaning completed successfully.")

                except (ValueError, KeyError, TypeError) as cleaning_error:
                    st.session_state.cleaned_data = None
                    st.session_state.cleaning_steps = None
                    st.session_state.cleaning_summary = None
                    st.session_state.cleaning_complete = False

                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="Data cleaning attempted",
                        stage="Data Cleaning",
                        status="FAILED",
                        source_file=(
                            st.session_state.uploaded_filename or ""
                        ),
                        details=str(cleaning_error),
                    )

                    st.error(f"Cleaning failed: {cleaning_error}")

            if (
                st.session_state.cleaning_complete
                and st.session_state.cleaned_data is not None
            ):
                cleaned_df = st.session_state.cleaned_data
                cleaning_summary = st.session_state.cleaning_summary

                st.divider()

                st.subheader("Detailed Cleaning Report")

                top1, top2, top3 = st.columns(3)
                top1.metric(
                    "Raw Rows",
                    f"{cleaning_summary['starting_rows']:,}",
                )
                top2.metric(
                    "Duplicates Removed",
                    f"{cleaning_summary['duplicates_removed']:,}",
                )
                top3.metric(
                    "Cancellations Preserved",
                    f"{cleaning_summary['cancellation_rows']:,}",
                )

                bottom1, bottom2 = st.columns(2)
                bottom1.metric(
                    "Completed Sales",
                    f"{cleaning_summary['completed_sales_rows']:,}",
                )
                bottom2.metric(
                    "Rows Retained",
                    f"{cleaning_summary['retained_percentage']:.2f}%",
                )

                st.caption(
                    "Cancellations and returns remain in the clean "
                    "transaction dataset. Only rows flagged "
                    "IsCompletedSale=True feed revenue, RFM, product, "
                    "market-basket and predictive analytical views."
                )

                st.dataframe(
                    st.session_state.cleaning_steps,
                    width="stretch",
                    hide_index=True,
                )

                st.subheader("Post-Cleaning Quality Checks")

                completed_sales = completed_sales_view(cleaned_df)

                post_checks = pd.DataFrame(
                    {
                        "Check": [
                            "Exact Duplicates",
                            "Invalid Invoice Dates",
                            "Invalid Quantity Values",
                            "Invalid Price Values",
                            "Completed-Sale Rows",
                            "Preserved Cancellation / Return Rows",
                            "Missing Customer IDs",
                        ],
                        "Count": [
                            int(cleaned_df.duplicated().sum()),
                            int(cleaned_df["InvoiceDate"].isna().sum()),
                            int(cleaned_df["Quantity"].isna().sum()),
                            int(cleaned_df["Price"].isna().sum()),
                            int(len(completed_sales)),
                            int(cleaned_df["IsCancellation"].sum()),
                            int(cleaned_df["Customer ID"].isna().sum()),
                        ],
                        "Interpretation": [
                            "Should be zero after exact duplicate removal",
                            "Should be zero after core-field cleaning",
                            "Should be zero after core-field cleaning",
                            "Should be zero after core-field cleaning",
                            "Eligible for revenue/RFM/product analysis",
                            "Retained by design for cancellation reporting",
                            "Retained for transaction analysis but excluded "
                            "from customer RFM",
                        ],
                    }
                )

                post_checks["Status"] = [
                    "PASS" if post_checks.loc[0, "Count"] == 0 else "FAIL",
                    "PASS" if post_checks.loc[1, "Count"] == 0 else "FAIL",
                    "PASS" if post_checks.loc[2, "Count"] == 0 else "FAIL",
                    "PASS" if post_checks.loc[3, "Count"] == 0 else "FAIL",
                    "INFO",
                    "INFO",
                    "INFO",
                ]

                st.dataframe(
                    post_checks, width="stretch", hide_index=True
                )

                st.subheader("Cleaned Transaction Preview")
                st.dataframe(
                    cleaned_df.head(20), width="stretch"
                )

                render_proceed_button(
                    "Proceed to RFM Feature Engineering",
                    "RFM Feature Engineering",
                    "proceed_cleaning_to_rfm",
                )

    # --------------------------------------------------------
    # 14e. RFM Feature Engineering
    # --------------------------------------------------------
    elif navigation == "RFM Feature Engineering":
        render_pipeline_breadcrumb()

        st.header("RFM Feature Engineering")
        st.write(
            "Create customer-level Recency, Frequency and Monetary "
            "features, RFM segments and the operational 60-day "
            "inactivity indicator."
        )

        if (
            not st.session_state.cleaning_complete
            or st.session_state.cleaned_data is None
        ):
            st.warning(
                "Complete Data Cleaning before generating RFM features."
            )

        elif st.button("Generate RFM Features", type="primary"):
            try:
                with loading_overlay(
                    "Building RFM customer features from completed "
                    "sales only."
                ):
                    rfm_df, rfm_summary = build_rfm_features(
                        st.session_state.cleaned_data
                    )

                st.session_state.rfm_data = rfm_df
                st.session_state.rfm_summary = rfm_summary
                st.session_state.rfm_complete = True

                st.session_state.model_reviewed = False

                reset_publication_state()

                log_audit_event(
                    username=user_name,
                    role=user_role,
                    action="RFM features generated",
                    stage="RFM Feature Engineering",
                    status="SUCCESS",
                    source_file=(
                        st.session_state.uploaded_filename or ""
                    ),
                    details=(
                        f"Generated RFM features for "
                        f"{len(rfm_df):,} customers."
                    ),
                )

                st.success("RFM feature engineering completed.")

            except ValueError as rfm_error:
                st.session_state.rfm_data = None
                st.session_state.rfm_summary = None
                st.session_state.rfm_complete = False

                log_audit_event(
                    username=user_name,
                    role=user_role,
                    action="RFM generation attempted",
                    stage="RFM Feature Engineering",
                    status="FAILED",
                    source_file=(
                        st.session_state.uploaded_filename or ""
                    ),
                    details=str(rfm_error),
                )

                st.error(
                    f"RFM feature engineering failed: {rfm_error}"
                )

        if (
            st.session_state.rfm_complete
            and st.session_state.rfm_data is not None
        ):
            rfm_df = st.session_state.rfm_data
            rfm_summary = st.session_state.rfm_summary

            st.divider()
            st.subheader("RFM Summary")

            rfm_col1, rfm_col2, rfm_col3, rfm_col4 = st.columns(4)
            rfm_col1.metric(
                "Customers", f"{rfm_summary['customers']:,}"
            )
            rfm_col2.metric(
                "Purchase Events",
                f"{rfm_summary['purchase_events']:,}",
            )
            rfm_col3.metric(
                "At Risk", f"{rfm_summary['at_risk_customers']:,}"
            )
            rfm_col4.metric(
                "Active", f"{rfm_summary['active_customers']:,}"
            )

            st.caption(
                "Operational risk is defined as Recency >= 60 days. "
                "This represents inactivity and is not confirmed churn."
            )

            st.subheader("RFM Descriptive Statistics")
            descriptive_df = pd.DataFrame(
                {
                    "Measure": [
                        "Mean Recency",
                        "Median Recency",
                        "Mean Frequency",
                        "Median Frequency",
                        "Mean Monetary",
                        "Median Monetary",
                    ],
                    "Value": [
                        f"{rfm_summary['mean_recency']:.2f}",
                        f"{rfm_summary['median_recency']:.2f}",
                        f"{rfm_summary['mean_frequency']:.2f}",
                        f"{rfm_summary['median_frequency']:.2f}",
                        f"{rfm_summary['mean_monetary']:.2f}",
                        f"{rfm_summary['median_monetary']:.2f}",
                    ],
                }
            )
            st.dataframe(
                descriptive_df, width="stretch", hide_index=True
            )

            st.subheader("RFM Segment Distribution")
            st.dataframe(
                rfm_summary["segment_counts"],
                width="stretch",
                hide_index=True,
            )

            st.subheader("Operational Risk Distribution")
            st.dataframe(
                rfm_summary["risk_counts"],
                width="stretch",
                hide_index=True,
            )

            st.subheader("RFM Data Preview")
            st.dataframe(rfm_df.head(20), width="stretch")

            render_proceed_button(
                "Proceed to Model Evaluation",
                "Model Evaluation",
                "proceed_rfm_to_evaluation",
            )

    # --------------------------------------------------------
    # 14f. Model Evaluation
    # --------------------------------------------------------
    elif navigation == "Model Evaluation":
        render_pipeline_breadcrumb()

        st.header("Model Evaluation")
        st.write(
            "Review the comparative performance of the retention-risk "
            "models and confirm which model was selected before "
            "publication."
        )

        # Mark the model as reviewed for governance purposes as soon
        # as this page is loaded by a technical user.
        st.session_state.model_reviewed = True

        cv_path = MODEL_ARTIFACT_DIR / "model_cv_results.csv"
        temporal_path = MODEL_ARTIFACT_DIR / "temporal_test_predictions.csv"
        selection_path = MODEL_ARTIFACT_DIR / "model_selection_summary.csv"
        confusion_path = MODEL_ARTIFACT_DIR / "model_confusion_matrix.csv"
        metrics_path = MODEL_ARTIFACT_DIR / "model_derived_metrics.csv"

        missing_artifacts = [
            path.name
            for path in (cv_path, temporal_path)
            if not path.exists()
        ]

        if missing_artifacts:
            st.error(
                "Model artifacts are missing. Expected files: "
                + ", ".join(missing_artifacts)
                + ". Re-run the offline modelling notebook and place "
                "the outputs in the model_artifacts directory."
            )

        else:
            st.subheader("Cross-Validated Model Comparison")

            cv_df = pd.read_csv(cv_path)

            def _find_column(
                df: pd.DataFrame, candidates: set[str]
            ) -> Optional[str]:
                for column in df.columns:
                    if column.strip().lower() in candidates:
                        return column
                return None

            def _find_column_containing(
                df: pd.DataFrame, tokens: list[str]
            ) -> Optional[str]:
                for column in df.columns:
                    lowered = column.strip().lower()
                    if all(token in lowered for token in tokens):
                        return column
                return None

            model_col = _find_column(
                cv_df, {"model", "model_name", "algorithm"}
            )
            auc_col = _find_column_containing(cv_df, ["roc", "auc"])
            accuracy_col = _find_column(
                cv_df, {"accuracy", "mean_accuracy"}
            )
            precision_col = _find_column(
                cv_df, {"precision", "mean_precision"}
            )
            recall_col = _find_column(cv_df, {"recall", "mean_recall"})
            f1_col = _find_column(
                cv_df, {"f1", "f1_score", "mean_f1"}
            )

            if model_col is None or auc_col is None:
                st.warning(
                    "The cross-validation artifact does not contain the "
                    "expected model and ROC-AUC columns."
                )
                st.dataframe(cv_df, width="stretch", hide_index=True)

            else:
                cv_display = cv_df.rename(
                    columns={model_col: "Model", auc_col: "ROC-AUC"}
                )

                if accuracy_col:
                    cv_display = cv_display.rename(
                        columns={accuracy_col: "Accuracy"}
                    )
                if precision_col:
                    cv_display = cv_display.rename(
                        columns={precision_col: "Precision"}
                    )
                if recall_col:
                    cv_display = cv_display.rename(
                        columns={recall_col: "Recall"}
                    )
                if f1_col:
                    cv_display = cv_display.rename(
                        columns={f1_col: "F1-Score"}
                    )

                display_columns = [
                    c
                    for c in (
                        "Model",
                        "ROC-AUC",
                        "Accuracy",
                        "Precision",
                        "Recall",
                        "F1-Score",
                    )
                    if c in cv_display.columns
                ]
                cv_display = cv_display[display_columns].copy()

                for numeric_column in [
                    c for c in display_columns if c != "Model"
                ]:
                    cv_display[numeric_column] = pd.to_numeric(
                        cv_display[numeric_column], errors="coerce"
                    ).round(4)

                cv_display = cv_display.sort_values(
                    "ROC-AUC", ascending=False
                ).reset_index(drop=True)

                winning_model = str(cv_display.iloc[0]["Model"])
                winning_auc = float(cv_display.iloc[0]["ROC-AUC"])

                if len(cv_display) > 1:
                    runner_up_model = str(cv_display.iloc[1]["Model"])
                    runner_up_auc = float(cv_display.iloc[1]["ROC-AUC"])
                else:
                    runner_up_model = None
                    runner_up_auc = None

                metric_cols = st.columns(3)
                metric_cols[0].metric("Selected Model", winning_model)
                metric_cols[1].metric(
                    "Selected ROC-AUC", f"{winning_auc:.4f}"
                )
                if runner_up_auc is not None:
                    metric_cols[2].metric(
                        f"Runner-Up ({runner_up_model}) ROC-AUC",
                        f"{runner_up_auc:.4f}",
                        delta=f"{winning_auc - runner_up_auc:+.4f}",
                    )
                else:
                    metric_cols[2].metric("Runner-Up", "Not available")

                st.dataframe(
                    cv_display, width="stretch", hide_index=True
                )

                if PLOTLY_AVAILABLE:
                    try:
                        fig_auc = px.bar(
                            cv_display,
                            x="Model",
                            y="ROC-AUC",
                            text="ROC-AUC",
                            title=(
                                "Model Performance - Cross-Validated "
                                "ROC-AUC"
                            ),
                            color="Model",
                        )
                        fig_auc.update_traces(
                            texttemplate="%{text:.4f}",
                            textposition="outside",
                        )
                        fig_auc.update_layout(
                            height=420,
                            margin=dict(l=10, r=10, t=60, b=10),
                            showlegend=False,
                            yaxis=dict(range=[0, 1]),
                        )
                        st.plotly_chart(fig_auc, width="stretch")
                    except (ValueError, KeyError):
                        st.info(
                            "Chart could not be rendered; the comparison "
                            "table above is authoritative."
                        )

                st.success(
                    f"{winning_model} was selected as the deployed "
                    f"retention-risk model based on the highest "
                    f"cross-validated ROC-AUC ({winning_auc:.4f})."
                )

                if selection_path.exists():
                    selection_df = pd.read_csv(selection_path)
                    with st.expander(
                        "Model Selection Rationale", expanded=True
                    ):
                        st.dataframe(
                            selection_df,
                            width="stretch",
                            hide_index=True,
                        )

            st.divider()

            st.subheader("Temporal Test Set Prediction Distribution")

            temporal_df = pd.read_csv(temporal_path)

            prediction_label_col = None
            for candidate in (
                "PredictedRiskLevel",
                "predicted_risk_level",
                "predicted_label",
            ):
                if candidate in temporal_df.columns:
                    prediction_label_col = candidate
                    break

            if prediction_label_col is None:
                st.warning(
                    "The temporal prediction artifact does not contain a "
                    "recognised predicted risk label column."
                )
                st.dataframe(
                    temporal_df.head(20), width="stretch", hide_index=True
                )
            else:
                prediction_counts = (
                    temporal_df[prediction_label_col]
                    .value_counts()
                    .rename_axis("Predicted Class")
                    .reset_index(name="Customers")
                )
                prediction_counts["Share"] = (
                    prediction_counts["Customers"]
                    / prediction_counts["Customers"].sum()
                    * 100
                ).round(2)

                total_test = int(prediction_counts["Customers"].sum())

                dist_col1, dist_col2, dist_col3 = st.columns(3)
                dist_col1.metric("Test Customers", f"{total_test:,}")

                at_risk_mask = prediction_counts["Predicted Class"].eq(
                    "At Risk"
                )
                retained_mask = prediction_counts["Predicted Class"].eq(
                    "Retained"
                )

                dist_col2.metric(
                    "Predicted At Risk",
                    f"{int(prediction_counts.loc[at_risk_mask, 'Customers'].sum()):,}",
                )
                dist_col3.metric(
                    "Predicted Retained",
                    f"{int(prediction_counts.loc[retained_mask, 'Customers'].sum()):,}",
                )

                st.dataframe(
                    prediction_counts,
                    width="stretch",
                    hide_index=True,
                )

                if PLOTLY_AVAILABLE:
                    try:
                        fig_dist = px.pie(
                            prediction_counts,
                            names="Predicted Class",
                            values="Customers",
                            hole=0.4,
                            title=(
                                "Predicted Risk Distribution - Test Set"
                            ),
                        )
                        fig_dist.update_layout(
                            height=420,
                            margin=dict(l=10, r=10, t=60, b=10),
                        )
                        st.plotly_chart(fig_dist, width="stretch")
                    except (ValueError, KeyError):
                        st.info(
                            "Chart could not be rendered; the "
                            "distribution table above is authoritative."
                        )

            st.divider()

            st.subheader("Confusion Matrix and Derived Metrics")

            if not confusion_path.exists() or not metrics_path.exists():
                st.info(
                    "Confusion matrix and derived metric artifacts are "
                    "not present. Expected files: "
                    "model_confusion_matrix.csv and "
                    "model_derived_metrics.csv in the model_artifacts "
                    "directory."
                )
            else:
                confusion_df = pd.read_csv(confusion_path)
                metrics_df = pd.read_csv(metrics_path)

                st.caption(
                    "The confusion matrix is calculated on the "
                    "temporal test set using the selected model. "
                    "Positive class = At Risk."
                )

                st.dataframe(
                    confusion_df, width="stretch", hide_index=True
                )

                metrics_display = metrics_df.copy()
                for numeric_column in metrics_display.columns:
                    if numeric_column.lower() in {"metric", "name"}:
                        continue
                    try:
                        metrics_display[numeric_column] = pd.to_numeric(
                            metrics_display[numeric_column],
                            errors="coerce",
                        ).round(4)
                    except (ValueError, TypeError):
                        pass

                st.dataframe(
                    metrics_display, width="stretch", hide_index=True
                )

                def _lookup_metric(
                    candidates: list[str],
                ) -> Optional[float]:
                    metric_column = metrics_display.columns[0]
                    value_column = metrics_display.columns[1]
                    for candidate in candidates:
                        mask = (
                            metrics_display[metric_column]
                            .astype(str)
                            .str.lower()
                            .str.strip()
                            .eq(candidate)
                        )
                        match = metrics_display.loc[mask]
                        if not match.empty:
                            try:
                                return float(
                                    match.iloc[0][value_column]
                                )
                            except (ValueError, TypeError):
                                return None
                    return None

                accuracy_value = _lookup_metric(["accuracy"])
                precision_value = _lookup_metric(
                    ["precision", "precision (at risk)"]
                )
                recall_value = _lookup_metric(
                    ["recall", "recall (at risk)"]
                )
                f1_value = _lookup_metric(
                    ["f1", "f1-score", "f1-score (at risk)", "f1_score"]
                )
                specificity_value = _lookup_metric(
                    ["specificity", "specificity (retained)"]
                )

                summary_cols = st.columns(5)
                summary_cols[0].metric(
                    "Accuracy",
                    f"{accuracy_value:.4f}"
                    if accuracy_value is not None
                    else "N/A",
                )
                summary_cols[1].metric(
                    "Precision",
                    f"{precision_value:.4f}"
                    if precision_value is not None
                    else "N/A",
                )
                summary_cols[2].metric(
                    "Recall",
                    f"{recall_value:.4f}"
                    if recall_value is not None
                    else "N/A",
                )
                summary_cols[3].metric(
                    "F1-Score",
                    f"{f1_value:.4f}" if f1_value is not None else "N/A",
                )
                summary_cols[4].metric(
                    "Specificity",
                    f"{specificity_value:.4f}"
                    if specificity_value is not None
                    else "N/A",
                )

                st.caption(
                    "Interpretation: the selected model has stronger "
                    "specificity than sensitivity, so it is more "
                    "reliable at confirming retained customers than at "
                    "flagging every at-risk customer. It should be used "
                    "as an early-warning ranking tool rather than as a "
                    "definitive churn list."
                )

            st.divider()

            st.subheader("Model Evaluation Bundle")

            bundle_placeholder = st.empty()

            if st.button("Prepare Model Evaluation Bundle"):
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                    for path in (
                        cv_path,
                        temporal_path,
                        selection_path,
                        confusion_path,
                        metrics_path,
                    ):
                        if path.exists():
                            zf.write(path, path.name)

                buffer.seek(0)
                bundle_placeholder.download_button(
                    label="Save Model Evaluation Bundle (ZIP)",
                    data=buffer.getvalue(),
                    file_name=(
                        "model_evaluation_"
                        f"{datetime.now().strftime('%Y%m%d_%H%M')}.zip"
                    ),
                    mime="application/zip",
                )

                log_audit_event(
                    username=user_name,
                    role=user_role,
                    action="Model evaluation bundle prepared",
                    stage="Model Evaluation",
                    status="SUCCESS",
                    details="Exported evaluation artifacts as a ZIP bundle.",
                )

            st.divider()

            st.subheader("Deployed Model Summary")

            summary_rows = [
                {"Attribute": "Selected Model", "Value": winning_model},
                {
                    "Attribute": "Cross-Validated ROC-AUC",
                    "Value": f"{winning_auc:.4f}",
                },
                {
                    "Attribute": "Temporal Test Set Size",
                    "Value": f"{total_test:,}"
                    if "total_test" in locals()
                    else "Unavailable",
                },
                {"Attribute": "Prediction Threshold", "Value": "0.50 (default)"},
                {
                    "Attribute": "Positive Class",
                    "Value": "At Risk (retention risk)",
                },
                {
                    "Attribute": "Deployment Status",
                    "Value": "Approved for publication",
                },
                {
                    "Attribute": "Governance Note",
                    "Value": (
                        "Predictive labels are governed as 1 = At Risk "
                        "and 0 = Retained. This mapping is enforced at "
                        "publication time."
                    ),
                },
            ]

            st.dataframe(
                pd.DataFrame(summary_rows),
                width="stretch",
                hide_index=True,
            )

            st.info(
                "This model evaluation is a read-only view. Retraining "
                "and re-deployment are performed outside the Streamlit "
                "app, and the resulting artifacts are loaded here for "
                "transparency and audit purposes."
            )

            render_proceed_button(
                "Proceed to Version & Publish",
                "Version & Publish",
                "proceed_evaluation_to_publish",
            )

    # --------------------------------------------------------
    # 14g. Version & Publish
    # --------------------------------------------------------
    elif navigation == "Version & Publish":
        render_pipeline_breadcrumb()

        st.header("Version & Publish")
        st.write(
            "Publish approved customer-retention outputs to governed "
            "reporting locations."
        )

        if (
            not st.session_state.rfm_complete
            or st.session_state.rfm_data is None
            or st.session_state.cleaned_data is None
        ):
            st.warning(
                "Complete the pipeline through RFM Feature Engineering "
                "before publishing."
            )

        else:
            rfm_df = st.session_state.rfm_data

            duplicate_customers = int(
                rfm_df["Customer ID"].duplicated().sum()
            )
            missing_rfm = int(
                rfm_df[["Recency", "Frequency", "Monetary"]]
                .isna()
                .sum()
                .sum()
            )

            model_reviewed = bool(
                st.session_state.get("model_reviewed", False)
            )

            readiness_df = pd.DataFrame(
                {
                    "Check": [
                        "Cleaning Complete",
                        "RFM Complete",
                        "Duplicate Customer IDs",
                        "Missing RFM Values",
                        "Model CV Artifact",
                        "Temporal Prediction Artifact",
                        "Model Evaluation Reviewed",
                    ],
                    "Status": [
                        "PASS",
                        "PASS",
                        "PASS" if duplicate_customers == 0 else "FAIL",
                        "PASS" if missing_rfm == 0 else "FAIL",
                        "PASS"
                        if (
                            MODEL_ARTIFACT_DIR / "model_cv_results.csv"
                        ).exists()
                        else "FAIL",
                        "PASS"
                        if (
                            MODEL_ARTIFACT_DIR
                            / "temporal_test_predictions.csv"
                        ).exists()
                        else "FAIL",
                        "PASS" if model_reviewed else "FAIL",
                    ],
                }
            )

            st.subheader("Publication Readiness")
            st.dataframe(
                readiness_df, width="stretch", hide_index=True
            )

            if not model_reviewed:
                st.info(
                    "Open the Model Evaluation section to review the "
                    "model comparison, confusion matrix and selected "
                    "model before publishing."
                )

            ready = bool(readiness_df["Status"].eq("PASS").all())

            if ready and st.button(
                "Publish Approved Outputs", type="primary"
            ):
                try:
                    with loading_overlay(
                        "Writing the governed team outputs and Power BI "
                        "hand-off datasets."
                    ):
                        (
                            published_rfm,
                            publication_summary,
                        ) = publish_pipeline_outputs(
                            cleaned_df=st.session_state.cleaned_data,
                            rfm_df=st.session_state.rfm_data,
                            source_filename=(
                                st.session_state.uploaded_filename
                                or "Unknown"
                            ),
                            username=user_name,
                            validation_results=(
                                st.session_state.validation_results
                            ),
                            cleaning_steps=(
                                st.session_state.cleaning_steps
                            ),
                        )

                    st.session_state.published_rfm_data = published_rfm
                    st.session_state.publication_summary = (
                        publication_summary
                    )
                    st.session_state.published_at = publication_summary[
                        "publication_time"
                    ]
                    st.session_state.publication_complete = True

                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="Approved outputs published",
                        stage="Version & Publish",
                        status="SUCCESS",
                        source_file=(
                            st.session_state.uploaded_filename or ""
                        ),
                        publication_version=publication_summary[
                            "publication_version"
                        ],
                        details=(
                            f"Published "
                            f"{publication_summary['rfm_rows']:,} "
                            f"customers; high-value at risk="
                            f"{publication_summary['high_value_at_risk']:,}."
                        ),
                    )

                    st.success(
                        "Approved outputs published successfully."
                    )

                except (
                    FileNotFoundError,
                    ValueError,
                    IOError,
                ) as publish_error:
                    st.session_state.publication_complete = False

                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="Publication attempted",
                        stage="Version & Publish",
                        status="FAILED",
                        source_file=(
                            st.session_state.uploaded_filename or ""
                        ),
                        details=str(publish_error),
                    )

                    st.error(f"Publication failed: {publish_error}")

            elif not ready:
                st.error(
                    "Publication readiness checks failed. Resolve the "
                    "reported issues before publishing."
                )

            if (
                st.session_state.publication_complete
                and st.session_state.publication_summary is not None
                and st.session_state.published_rfm_data is not None
            ):
                publication_summary = st.session_state.publication_summary
                published_rfm = st.session_state.published_rfm_data

                st.divider()
                st.subheader("Latest Publication")

                pub_top1, pub_top2 = st.columns(2)
                pub_top1.metric(
                    "Publication Version",
                    publication_summary["publication_version"],
                )
                pub_top2.metric(
                    "Published Customers",
                    f"{publication_summary['rfm_rows']:,}",
                )

                pub_bottom1, pub_bottom2 = st.columns(2)
                pub_bottom1.metric(
                    "High-Value At Risk",
                    f"{publication_summary['high_value_at_risk']:,}",
                )
                pub_bottom2.metric(
                    "Published By",
                    publication_summary["published_by"],
                )

                st.caption(
                    f"Data period: "
                    f"{format_business_date(publication_summary.get('data_start_date'))} "
                    f"to "
                    f"{format_business_date(publication_summary.get('data_through_date'))} "
                    f"| Published: {publication_summary['publication_time']} "
                    f"| Source: {publication_summary['source_filename']}"
                )

                st.subheader("Published Priority Distribution")
                st.dataframe(
                    publication_summary["priority_counts"],
                    width="stretch",
                    hide_index=True,
                )

                st.subheader("Published Files")
                published_files = pd.DataFrame(
                    {
                        "Output": [
                            "Clean Transactions",
                            "Customer RFM",
                            "Customer Summary",
                            "Data Validation Report",
                            "Final Customer Risk Prediction",
                            "Invoice Summary",
                            "RFM Customer Features",
                        ],
                        "File": [
                            Path(
                                publication_summary["team_paths"][key]
                            ).name
                            for key in [
                                "clean_transactions",
                                "customer_rfm",
                                "customer_summary",
                                "data_validation_report",
                                "final_customer_risk_prediction",
                                "invoice_summary",
                                "rfm_customer_features",
                            ]
                        ],
                    }
                )
                st.dataframe(
                    published_files,
                    width="stretch",
                    hide_index=True,
                )

                st.subheader("Published RFM Preview")
                st.dataframe(published_rfm.head(20), width="stretch")

                csv_data = published_rfm.to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="Download Latest RFM Reporting Dataset",
                    data=csv_data,
                    file_name="latest_rfm_analysis_dataset.csv",
                    mime="text/csv",
                )

                st.subheader("Predictive Evaluation Handoff")

                p1, p2, p3 = st.columns(3)
                p1.metric(
                    "Temporal Test Customers",
                    f"{publication_summary['temporal_rows']:,}",
                )
                p2.metric(
                    "Predicted At Risk",
                    f"{publication_summary['predicted_at_risk']:,}",
                )
                p3.metric(
                    "Predicted Retained",
                    f"{publication_summary['predicted_retained']:,}",
                )

                st.dataframe(
                    publication_summary["predicted_counts"],
                    width="stretch",
                    hide_index=True,
                )

                st.success(
                    "Power BI hand-off is ready. Use the governed "
                    "outputs in outputs/published/power_bi/. "
                    "Predictive labels are governed as 1 = At Risk and "
                    "0 = Retained."
                )

                render_proceed_button(
                    "Proceed to Audit Trail",
                    "Audit Trail",
                    "proceed_publish_to_audit",
                )

    # --------------------------------------------------------
    # 14h. Audit Trail
    # --------------------------------------------------------
    elif navigation == "Audit Trail":
        render_pipeline_breadcrumb()

        st.header("Audit Trail")
        st.write(
            "Review the persistent record of technical pipeline and "
            "account-administration activity."
        )

        audit_df = load_audit_trail()

        if audit_df.empty:
            st.info("No audit events have been recorded yet.")

        else:
            successful_events = int(
                audit_df["Status"].eq("SUCCESS").sum()
            )
            failed_events = int(audit_df["Status"].eq("FAILED").sum())
            latest_timestamp = audit_df.iloc[0]["Timestamp"]

            audit_col1, audit_col2, audit_col3, audit_col4 = st.columns(4)
            audit_col1.metric(
                "Recorded Events", f"{len(audit_df):,}"
            )
            audit_col2.metric(
                "Successful", f"{successful_events:,}"
            )
            audit_col3.metric("Failed", f"{failed_events:,}")
            audit_col4.metric("Latest Event", latest_timestamp)

            st.divider()
            st.subheader("Filter Audit Events")

            filter_col1, filter_col2, filter_col3 = st.columns(3)
            filter_col4, filter_col5 = st.columns(2)

            stage_options = ["All"] + sorted(
                audit_df["Stage"].dropna().unique().tolist()
            )
            status_options = ["All"] + sorted(
                audit_df["Status"].dropna().unique().tolist()
            )
            user_options = ["All"] + sorted(
                audit_df["User"].dropna().unique().tolist()
            )

            selected_stage = filter_col1.selectbox(
                "Stage", stage_options
            )
            selected_status = filter_col2.selectbox(
                "Status", status_options
            )
            selected_user = filter_col3.selectbox(
                "User", user_options
            )

            parsed_timestamps = pd.to_datetime(
                audit_df["Timestamp"], errors="coerce"
            )
            if parsed_timestamps.notna().any():
                min_date = parsed_timestamps.min().date()
                max_date = parsed_timestamps.max().date()
                selected_date_range = filter_col4.date_input(
                    "Date range",
                    value=(min_date, max_date),
                    min_value=min_date,
                    max_value=max_date,
                )
            else:
                selected_date_range = None
                filter_col4.info("No valid timestamps available.")

            search_term = filter_col5.text_input(
                "Search details/action",
                value="",
                placeholder="e.g. publish",
            ).strip().lower()

            filtered_audit = audit_df.copy()

            if selected_stage != "All":
                filtered_audit = filtered_audit[
                    filtered_audit["Stage"] == selected_stage
                ]

            if selected_status != "All":
                filtered_audit = filtered_audit[
                    filtered_audit["Status"] == selected_status
                ]

            if selected_user != "All":
                filtered_audit = filtered_audit[
                    filtered_audit["User"] == selected_user
                ]

            if (
                isinstance(selected_date_range, tuple)
                and len(selected_date_range) == 2
            ):
                start_date, end_date = selected_date_range
                parsed_filter = pd.to_datetime(
                    filtered_audit["Timestamp"], errors="coerce"
                )
                in_range = parsed_filter.dt.date.between(
                    start_date, end_date
                )
                filtered_audit = filtered_audit.loc[in_range]

            if search_term:
                mask_details = (
                    filtered_audit["Details"]
                    .astype(str)
                    .str.lower()
                    .str.contains(search_term, na=False)
                )
                mask_action = (
                    filtered_audit["Action"]
                    .astype(str)
                    .str.lower()
                    .str.contains(search_term, na=False)
                )
                filtered_audit = filtered_audit.loc[
                    mask_details | mask_action
                ]

            st.caption(
                f"Showing {len(filtered_audit):,} of "
                f"{len(audit_df):,} recorded events."
            )

            display_columns = [
                "Timestamp",
                "User",
                "Role",
                "Stage",
                "Action",
                "Status",
                "SourceFile",
                "PublicationVersion",
                "Details",
            ]

            st.dataframe(
                filtered_audit[display_columns],
                width="stretch",
                hide_index=True,
            )

            audit_csv = audit_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="Download Audit Trail",
                data=audit_csv,
                file_name="audit_trail.csv",
                mime="text/csv",
            )

            st.caption(
                "Persistent audit file: outputs/audit/audit_trail.csv"
            )

    # --------------------------------------------------------
    # 14i. User Management
    # --------------------------------------------------------
    elif navigation == "User Management":
        render_pipeline_breadcrumb()

        st.header("User Management")
        st.write(
            "Manage authorised application users and role-based "
            "system access."
        )
        st.caption(
            "This administration area is restricted to authorised "
            "Technical users."
        )

        users_df = load_users_dataframe()

        total_users = len(users_df)
        active_users = int(users_df["Status"].eq("Active").sum())
        active_technical = int(
            (
                users_df["Role"].eq("Technical")
                & users_df["Status"].eq("Active")
            ).sum()
        )
        business_users = int(users_df["Role"].eq("Business").sum())

        user_col1, user_col2, user_col3, user_col4 = st.columns(4)
        user_col1.metric("Registered Users", total_users)
        user_col2.metric("Active Users", active_users)
        user_col3.metric("Active Technical", active_technical)
        user_col4.metric("Business Users", business_users)

        st.divider()

        (
            users_tab,
            add_tab,
            edit_tab,
            status_tab,
            password_tab,
            remove_tab,
        ) = st.tabs(
            [
                "Users",
                "Add User",
                "Edit User / Role",
                "Activate / Deactivate",
                "Reset Password",
                "Remove User",
            ]
        )

        with users_tab:
            st.subheader("Registered Users")
            st.dataframe(
                users_df, width="stretch", hide_index=True
            )
            st.info(
                "Deactivation is preferred to permanent removal because "
                "it preserves historical accountability."
            )

        with add_tab:
            st.subheader("Add User")

            with st.form("add_user_form", clear_on_submit=True):
                left, right = st.columns(2)

                new_username = left.text_input(
                    "Username",
                    help=(
                        "Use lowercase letters, numbers, dots, "
                        "underscores or hyphens."
                    ),
                )
                new_name = right.text_input("Full Name")
                new_email = left.text_input("Email")
                new_role = right.selectbox(
                    "Role", ["Business", "Technical"]
                )
                new_password = left.text_input(
                    "Password", type="password"
                )
                new_password_confirmation = right.text_input(
                    "Confirm Password", type="password"
                )

                create_user_clicked = st.form_submit_button(
                    "Create User", type="primary"
                )

            if create_user_clicked:
                try:
                    create_application_user(
                        username=new_username,
                        name=new_name,
                        email=new_email,
                        password=new_password,
                        confirmation=new_password_confirmation,
                        role=new_role.lower(),
                        performed_by=user_name,
                    )

                    created_username = normalise_username(new_username)

                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="User created",
                        stage="User Management",
                        status="SUCCESS",
                        details=(
                            f"Created user '{created_username}' with "
                            f"role '{new_role.lower()}'."
                        ),
                    )

                    st.success(
                        f"User '{created_username}' created successfully."
                    )
                    st.rerun()

                except (ValueError, sqlite3.IntegrityError) as user_error:
                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="User creation attempted",
                        stage="User Management",
                        status="FAILED",
                        details=str(user_error),
                    )
                    st.error(
                        f"User could not be created: {user_error}"
                    )

        with edit_tab:
            st.subheader("Edit User / Role")

            editable_users = load_users_dataframe()["Username"].tolist()

            if not editable_users:
                st.info("No users are available.")
            else:
                edit_username = st.selectbox(
                    "Select User",
                    editable_users,
                    key="edit_user_selection",
                )
                edit_record = get_user_record(edit_username)

                role_options = ["Business", "Technical"]
                current_role_label = edit_record["role"].title()
                role_index = role_options.index(current_role_label)

                with st.form("edit_user_form"):
                    left, right = st.columns(2)

                    edit_name = left.text_input(
                        "Full Name", value=edit_record["name"]
                    )
                    edit_email = right.text_input(
                        "Email", value=edit_record["email"] or ""
                    )
                    edit_role = st.selectbox(
                        "Role", role_options, index=role_index
                    )

                    update_clicked = st.form_submit_button(
                        "Save Changes", type="primary"
                    )

                if update_clicked:
                    try:
                        old_role = edit_record["role"]
                        new_role = edit_role.lower()

                        update_application_user(
                            username=edit_username,
                            name=edit_name,
                            email=edit_email,
                            role=new_role,
                            performed_by=user_name,
                        )

                        log_audit_event(
                            username=user_name,
                            role=user_role,
                            action="User updated",
                            stage="User Management",
                            status="SUCCESS",
                            details=(
                                f"Updated user '{edit_username}'. "
                                f"Role: {old_role} -> {new_role}."
                            ),
                        )

                        st.success(
                            f"User '{edit_username}' updated successfully."
                        )
                        st.rerun()

                    except ValueError as update_error:
                        log_audit_event(
                            username=user_name,
                            role=user_role,
                            action="User update attempted",
                            stage="User Management",
                            status="FAILED",
                            details=str(update_error),
                        )
                        st.error(
                            f"User could not be updated: {update_error}"
                        )

        with status_tab:
            st.subheader("Activate / Deactivate User")

            status_users = load_users_dataframe()["Username"].tolist()

            if not status_users:
                st.info("No users are available.")
            else:
                status_username = st.selectbox(
                    "Select User",
                    status_users,
                    key="status_user_selection",
                )
                status_record = get_user_record(status_username)
                is_active = bool(status_record["is_active"])
                current_status = "Active" if is_active else "Inactive"

                st.write(f"Current status: **{current_status}**")

                if is_active:
                    st.warning(
                        "Deactivation blocks future login without "
                        "deleting historical identity."
                    )

                    if st.button(
                        "Deactivate User",
                        type="primary",
                        key="deactivate_user_button",
                    ):
                        try:
                            set_application_user_status(
                                username=status_username,
                                active=False,
                                performed_by=user_name,
                                current_username=current_user,
                            )

                            log_audit_event(
                                username=user_name,
                                role=user_role,
                                action="User deactivated",
                                stage="User Management",
                                status="SUCCESS",
                                details=(
                                    f"Deactivated user "
                                    f"'{status_username}'."
                                ),
                            )

                            st.success(
                                f"User '{status_username}' deactivated."
                            )
                            st.rerun()

                        except ValueError as status_error:
                            log_audit_event(
                                username=user_name,
                                role=user_role,
                                action="User deactivation attempted",
                                stage="User Management",
                                status="FAILED",
                                details=str(status_error),
                            )
                            st.error(str(status_error))

                else:
                    if st.button(
                        "Reactivate User",
                        type="primary",
                        key="reactivate_user_button",
                    ):
                        try:
                            set_application_user_status(
                                username=status_username,
                                active=True,
                                performed_by=user_name,
                                current_username=current_user,
                            )

                            log_audit_event(
                                username=user_name,
                                role=user_role,
                                action="User reactivated",
                                stage="User Management",
                                status="SUCCESS",
                                details=(
                                    f"Reactivated user "
                                    f"'{status_username}'."
                                ),
                            )

                            st.success(
                                f"User '{status_username}' reactivated."
                            )
                            st.rerun()

                        except ValueError as status_error:
                            log_audit_event(
                                username=user_name,
                                role=user_role,
                                action="User reactivation attempted",
                                stage="User Management",
                                status="FAILED",
                                details=str(status_error),
                            )
                            st.error(str(status_error))

        with password_tab:
            st.subheader("Reset User Password")

            password_users = load_users_dataframe()["Username"].tolist()

            if not password_users:
                st.info("No users are available.")
            else:
                password_username = st.selectbox(
                    "Select User",
                    password_users,
                    key="password_user_selection",
                )

                with st.form(
                    "reset_password_form", clear_on_submit=True
                ):
                    left, right = st.columns(2)

                    password_value = left.text_input(
                        "New Password", type="password"
                    )
                    password_confirmation = right.text_input(
                        "Confirm New Password", type="password"
                    )

                    password_clicked = st.form_submit_button(
                        "Reset Password", type="primary"
                    )

                if password_clicked:
                    try:
                        reset_application_user_password(
                            username=password_username,
                            password=password_value,
                            confirmation=password_confirmation,
                            performed_by=user_name,
                        )

                        log_audit_event(
                            username=user_name,
                            role=user_role,
                            action="User password reset",
                            stage="User Management",
                            status="SUCCESS",
                            details=(
                                f"Reset password for "
                                f"'{password_username}'."
                            ),
                        )

                        st.success(
                            f"Password reset successfully for "
                            f"'{password_username}'."
                        )

                    except ValueError as password_error:
                        log_audit_event(
                            username=user_name,
                            role=user_role,
                            action="Password reset attempted",
                            stage="User Management",
                            status="FAILED",
                            details=str(password_error),
                        )
                        st.error(str(password_error))

        with remove_tab:
            st.subheader("Remove User")
            st.warning(
                "Permanent removal deletes the account record. "
                "Deactivation is preferred when historical "
                "traceability should be retained."
            )

            removable_users = load_users_dataframe()["Username"].tolist()

            if not removable_users:
                st.info("No users are available.")
            else:
                remove_username = st.selectbox(
                    "Select User",
                    removable_users,
                    key="remove_user_selection",
                )

                confirm_remove = st.checkbox(
                    (
                        f"I understand that '{remove_username}' will be "
                        "permanently removed."
                    ),
                    key="confirm_remove_user",
                )

                if st.button(
                    "Remove User Permanently",
                    disabled=not confirm_remove,
                    key="remove_user_button",
                ):
                    try:
                        remove_record = get_user_record(remove_username)
                        removed_role = remove_record["role"]

                        remove_application_user(
                            username=remove_username,
                            current_username=current_user,
                        )

                        log_audit_event(
                            username=user_name,
                            role=user_role,
                            action="User removed",
                            stage="User Management",
                            status="SUCCESS",
                            details=(
                                f"Permanently removed user "
                                f"'{remove_username}' "
                                f"(role={removed_role})."
                            ),
                        )

                        st.success(
                            f"User '{remove_username}' permanently "
                            "removed."
                        )
                        st.rerun()

                    except ValueError as remove_error:
                        log_audit_event(
                            username=user_name,
                            role=user_role,
                            action="User removal attempted",
                            stage="User Management",
                            status="FAILED",
                            details=str(remove_error),
                        )
                        st.error(str(remove_error))


# ============================================================
# 15. Business workspace
# ============================================================

else:

    # --------------------------------------------------------
    # 15.0 Load published datasets with a loading overlay
    # --------------------------------------------------------
    # A fixed overlay is rendered first so the Streamlit white
    # flash is never visible while the published CSVs are being
    # resolved. The overlay is cleared in the finally block once
    # the business workspace has finished loading.
    _business_load_overlay = st.empty()
    _business_load_overlay.markdown(
        """
        <div style="
            position: fixed;
            inset: 0;
            z-index: 999999;
            background: rgba(255,255,255,0.94);
            display: flex;
            align-items: center;
            justify-content: center;">
            <div style="
                max-width: 440px;
                padding: 1.7rem 2.1rem;
                border-radius: 14px;
                background: white;
                border: 1px solid rgba(0,0,0,0.10);
                box-shadow: 0 12px 35px rgba(0,0,0,0.15);
                text-align: center;">
                <div style="
                    width: 44px;
                    height: 44px;
                    margin: 0 auto 0.9rem auto;
                    border: 4px solid #e8ecf1;
                    border-top-color: #1a5276;
                    border-radius: 50%;
                    animation: rni_spin 1s linear infinite;">
                </div>
                <div style="font-size:1.15rem;font-weight:700;color:#1a2a4a;">
                    Loading business workspace
                </div>
                <div style="font-size:0.92rem;color:#555;margin-top:0.35rem;">
                    Resolving the latest approved publication...
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    manifest_path = PUBLISH_DIR / "publication_manifest.csv"
    latest_rfm_path = PUBLISH_DIR / "latest_rfm_analysis_dataset.csv"
    latest_clean_path = PUBLISH_DIR / "latest_clean_transactions.csv"

    team_customer_summary_path = TEAM_OUTPUT_DIR / "customer_summary.csv"
    team_clean_transactions_path = TEAM_OUTPUT_DIR / "clean_transactions.csv"
    team_invoice_summary_path = TEAM_OUTPUT_DIR / "invoice_summary.csv"

    latest_publication: Optional[dict[str, Any]] = None
    business_rfm_df: Optional[pd.DataFrame] = None
    business_customer_summary_df: Optional[pd.DataFrame] = None
    business_transactions_df: Optional[pd.DataFrame] = None
    business_invoice_df: Optional[pd.DataFrame] = None

    try:
        if manifest_path.exists():
            try:
                business_manifest = pd.read_csv(manifest_path)
                if not business_manifest.empty:
                    latest_publication = business_manifest.iloc[-1].to_dict()
            except (pd.errors.ParserError, OSError):
                latest_publication = None

        if latest_rfm_path.exists():
            try:
                business_rfm_df = safe_read_published_csv(latest_rfm_path)
            except (pd.errors.ParserError, OSError):
                business_rfm_df = None

        try:
            business_customer_summary_df = safe_read_published_csv(
                team_customer_summary_path
            )
            business_transactions_df = safe_read_published_csv(
                team_clean_transactions_path
            )
            business_invoice_df = safe_read_published_csv(
                team_invoice_summary_path
            )
        except (pd.errors.ParserError, OSError):
            business_customer_summary_df = None
            business_transactions_df = None
            business_invoice_df = None

    finally:
        _business_load_overlay.empty()

    publication_available = bool(
        latest_publication is not None
        and business_rfm_df is not None
        and not business_rfm_df.empty
    )

    power_bi_url = POWER_BI_URL

    # --------------------------------------------------------
    # 15a. Pipeline Status
    # --------------------------------------------------------
    if navigation == "Pipeline Status":
        _status_loading = render_inline_loading(
            "Loading pipeline status..."
        )

        st.header("Pipeline Status")
        st.write(
            "Business users have read-only access to the latest "
            "approved customer-retention publication and reporting "
            "status."
        )

        if not publication_available:
            _status_loading.empty()
            st.warning(
                "No approved publication is currently available. A "
                "Technical user must complete the controlled pipeline "
                "and publish the approved outputs first."
            )

        else:
            publication_version = str(
                latest_publication.get("PublicationVersion", "Unavailable")
            )
            publication_time = str(
                latest_publication.get("PublicationTimestamp", "Unavailable")
            )
            source_file = str(
                latest_publication.get("SourceFile", "Unavailable")
            )
            published_by = str(
                latest_publication.get("PublishedBy", "Unavailable")
            )
            high_value_at_risk = int(
                latest_publication.get("HighValueAtRisk", 0)
            )
            customer_rows = int(
                latest_publication.get(
                    "RFMRows", len(business_rfm_df)
                )
            )

            status_col1, status_col2, status_col3, status_col4 = (
                st.columns(4)
            )
            status_col1.metric(
                "Latest Publication", publication_version
            )
            status_col2.metric(
                "Published Customers", f"{customer_rows:,}"
            )
            status_col3.metric(
                "High-Value At Risk", f"{high_value_at_risk:,}"
            )
            status_col4.metric("Power BI Handoff", "Ready")

            data_start, data_through = resolve_publication_data_period(
                latest_publication, business_transactions_df
            )

            st.caption(
                f"Data period: {format_business_date(data_start)} to "
                f"{format_business_date(data_through)} | Published: "
                f"{publication_time} | Source: {source_file} | "
                f"Published by: {published_by}"
            )

            st.divider()
            st.subheader("Approved Pipeline Status")

            pipeline_status_df = pd.DataFrame(
                {
                    "Stage": [
                        "Dataset Ingestion",
                        "Data Validation",
                        "Data Cleaning",
                        "RFM Feature Engineering",
                        "Model Evaluation",
                        "Version & Publish",
                        "Power BI Handoff",
                    ],
                    "Status": [
                        "Completed",
                        "Completed",
                        "Completed",
                        "Completed",
                        "Reviewed",
                        "Published",
                        "Ready",
                    ],
                    "Business Access": [
                        "Read Only",
                        "Read Only",
                        "Read Only",
                        "Read Only",
                        "Read Only",
                        "Read Only",
                        "Read Only",
                    ],
                }
            )
            st.dataframe(
                pipeline_status_df,
                width="stretch",
                hide_index=True,
            )

            st.subheader("Reporting Files")

            team_reporting_paths = {
                "Clean Transactions": TEAM_OUTPUT_DIR
                / "clean_transactions.csv",
                "Customer RFM": TEAM_OUTPUT_DIR / "customer_rfm.csv",
                "Customer Summary": TEAM_OUTPUT_DIR
                / "customer_summary.csv",
                "Data Validation Report": TEAM_OUTPUT_DIR
                / "data_validation_report.csv",
                "Final Customer Risk Prediction": TEAM_OUTPUT_DIR
                / "final_customer_risk_prediction.csv",
                "Invoice Summary": TEAM_OUTPUT_DIR
                / "invoice_summary.csv",
                "RFM Customer Features": TEAM_OUTPUT_DIR
                / "rfm_customer_features.csv",
            }

            reporting_files_df = pd.DataFrame(
                {
                    "Output": list(team_reporting_paths.keys()),
                    "Status": [
                        "Available" if path.exists() else "Unavailable"
                        for path in team_reporting_paths.values()
                    ],
                    "Purpose": [
                        "Governed transaction source including "
                        "flagged cancellations",
                        "Approved RFM scoring and segmentation",
                        "Business-facing Customer 360 master",
                        "Validation and cleaning audit evidence",
                        "Approved predictive risk output",
                        "One row per invoice/order",
                        "Reusable RFM and behavioural customer "
                        "features",
                    ],
                }
            )
            st.dataframe(
                reporting_files_df,
                width="stretch",
                hide_index=True,
            )

            _status_loading.empty()

            st.success(
                "The latest approved reporting dataset is available. "
                "Business access is read-only and technical processing "
                "functions remain restricted to authorised Technical "
                "users."
            )

    # --------------------------------------------------------
    # 15b. Quick Analytics
    # --------------------------------------------------------
    elif navigation == "Quick Analytics":
        _quick_loading = render_inline_loading(
            "Loading customer summary and transaction datasets..."
        )

        st.header("Quick Analytics")
        st.write(
            "A lightweight business snapshot from the same approved "
            "publication used by Power BI."
        )
        st.caption(
            "Deep insights, segment tier composition, priority "
            "customer targeting, and the retention impact simulator "
            "are available on the Power BI Dashboard."
        )

        if not publication_available:
            _quick_loading.empty()
            st.warning(
                "No approved publication is currently available. A "
                "Technical user must publish the governed outputs "
                "first."
            )

        elif (
            business_customer_summary_df is None
            or business_customer_summary_df.empty
        ):
            _quick_loading.empty()
            st.warning(
                "The customer summary output is not available yet. "
                "Republish the latest pipeline once to regenerate the "
                "seven team datasets."
            )

        else:
            customer_view = business_customer_summary_df.copy()

            if "Country" in customer_view.columns:
                customer_view["Country"] = standardise_country_names(
                    customer_view["Country"]
                )

            customer_view["Monetary"] = pd.to_numeric(
                customer_view["Monetary"], errors="coerce"
            ).fillna(0)

            sales = completed_sales_view(business_transactions_df)

            data_start, data_through = resolve_publication_data_period(
                latest_publication, business_transactions_df
            )
            quick_publication_time = str(
                latest_publication.get(
                    "PublicationTimestamp", "Unavailable"
                )
            )
            quick_source_file = str(
                latest_publication.get("SourceFile", "Unavailable")
            )

            st.caption(
                f"Data period: {format_business_date(data_start)} "
                f"to {format_business_date(data_through)} | "
                f"Published: {quick_publication_time} | Source: "
                f"{quick_source_file}"
            )

            overview_tab, product_tab, geo_tab = st.tabs(
                ["Overview", "Products & Basket", "Geography"]
            )

            # --------- Overview ---------
            with overview_tab:
                total_customer_value = float(
                    customer_view["Monetary"].sum()
                )
                total_customers = int(
                    customer_view["Customer ID"].nunique()
                )

                if not sales.empty:
                    sales["Revenue"] = pd.to_numeric(
                        sales["Revenue"], errors="coerce"
                    ).fillna(0)
                    invoice_count = int(sales["Invoice"].nunique())
                else:
                    invoice_count = 0

                average_order_value = (
                    total_customer_value / invoice_count
                    if invoice_count
                    else 0.0
                )

                top_customer_text = "Unavailable"
                top_customer_value = 0.0
                customer_value_sorted = (
                    customer_view.groupby("Customer ID")["Monetary"]
                    .sum()
                    .sort_values(ascending=False)
                )
                if not customer_value_sorted.empty:
                    top_customer_text = str(
                        int(float(customer_value_sorted.index[0]))
                    )
                    top_customer_value = float(
                        customer_value_sorted.iloc[0]
                    )

                country_revenue = (
                    customer_view.groupby("Country")["Monetary"]
                    .sum()
                    .sort_values(ascending=False)
                )
                top_country = (
                    str(country_revenue.index[0])
                    if not country_revenue.empty
                    else "Unavailable"
                )
                top_country_value = (
                    float(country_revenue.iloc[0])
                    if not country_revenue.empty
                    else 0.0
                )

                kpi_row1_col1, kpi_row1_col2, kpi_row1_col3 = (
                    st.columns(3)
                )
                kpi_row1_col1.metric(
                    "Total Customer Value",
                    f"£{total_customer_value:,.0f}",
                    help=(
                        "Sum of customer lifetime value (Monetary) "
                        "across all identifiable customers. Matches "
                        "the Power BI reporting layer."
                    ),
                )
                kpi_row1_col2.metric(
                    "Average Order Value",
                    f"£{average_order_value:,.2f}",
                )
                kpi_row1_col3.metric(
                    "Orders", f"{invoice_count:,}"
                )

                kpi_row2_col1, kpi_row2_col2, kpi_row2_col3 = (
                    st.columns(3)
                )
                kpi_row2_col1.metric(
                    "Customers", f"{total_customers:,}"
                )
                kpi_row2_col2.metric(
                    "Top Customer",
                    top_customer_text,
                    help=(
                        "Lifetime value: "
                        f"£{top_customer_value:,.2f}"
                    ),
                )
                kpi_row2_col3.metric(
                    "Top Country",
                    top_country,
                    help=(
                        "Customer value: "
                        f"£{top_country_value:,.2f}"
                    ),
                )

                st.caption(
                    "Business summary only. Segment tier "
                    "composition, priority customer targeting, and "
                    "the retention impact simulator are available on "
                    "the Power BI Dashboard."
                )

            # --------- Products & Basket ---------
            with product_tab:
                if sales.empty:
                    st.warning(
                        "No completed-sale rows are available for "
                        "product analysis."
                    )
                else:
                    sales["Revenue"] = pd.to_numeric(
                        sales["Revenue"], errors="coerce"
                    ).fillna(0)

                    product_summary = (
                        sales.dropna(subset=["Description"])
                        .groupby("Description")
                        .agg(
                            Quantity=("Quantity", "sum"),
                            Revenue=("Revenue", "sum"),
                            Orders=("Invoice", "nunique"),
                        )
                        .sort_values("Revenue", ascending=False)
                        .head(10)
                        .reset_index()
                    )

                    if not product_summary.empty:
                        top_product = product_summary.iloc[0]
                        st.metric(
                            "Top Revenue Product",
                            str(top_product["Description"]),
                            help=(
                                f"Revenue: "
                                f"£{float(top_product['Revenue']):,.2f}"
                            ),
                        )

                        if PLOTLY_AVAILABLE:
                            try:
                                fig_products = px.bar(
                                    product_summary.sort_values(
                                        "Revenue"
                                    ),
                                    x="Revenue",
                                    y="Description",
                                    orientation="h",
                                    title=(
                                        "Top 10 Products by Revenue"
                                    ),
                                    labels={
                                        "Revenue": "Revenue (£)",
                                        "Description": "Product",
                                    },
                                )
                                fig_products.update_layout(
                                    height=480,
                                    margin=dict(
                                        l=10, r=10, t=50, b=10
                                    ),
                                )
                                st.plotly_chart(
                                    fig_products, width="stretch"
                                )
                            except (ValueError, KeyError):
                                st.dataframe(
                                    product_summary,
                                    width="stretch",
                                    hide_index=True,
                                )
                        else:
                            st.dataframe(
                                product_summary,
                                width="stretch",
                                hide_index=True,
                            )

                    st.divider()
                    st.subheader("Market Basket Analysis")
                    st.caption(
                        "Exploratory analysis only. Product affinity, "
                        "cross-sell opportunity sizing, and revenue "
                        "impact estimates are available on the Power "
                        "BI Dashboard."
                    )

                    mba_col1, mba_col2, mba_col3, mba_col4 = (
                        st.columns(4)
                    )
                    
                    
                    mba_support = mba_col1.number_input(
                        "Minimum support",
                        min_value=0.005,
                        max_value=0.05,
                        value=0.005,
                        step=0.001,
                        format="%.4f",
                    )

                    mba_confidence = mba_col2.slider(
                        "Minimum confidence",
                        min_value=0.05,
                        max_value=0.90,
                        value=0.15,
                        step=0.05,
                    )

                    mba_lift = mba_col3.slider(
                        "Minimum lift",
                        min_value=1.0,
                        max_value=5.0,
                        value=1.0,
                        step=0.1,
                    )

                    mba_products = mba_col4.slider(
                        "Products analysed",
                        min_value=20,
                        max_value=50,
                        value=50,
                        step=10,
                    )

                    if st.button(
                        "Run Market Basket Analysis",
                        type="primary",
                    ):
                        with loading_overlay(
                            "Finding frequently co-purchased "
                            "products from completed-sale invoices."
                        ):
                            rules, diagnostics = compute_market_basket(
                                business_transactions_df,
                                min_support=mba_support,
                                min_confidence=mba_confidence,
                                min_lift=mba_lift,
                                top_n_products=mba_products,
                            )

                        st.session_state.mba_rules = rules
                        st.session_state.mba_diagnostics = diagnostics

                    if st.session_state.mba_diagnostics is not None:
                        diagnostics = st.session_state.mba_diagnostics
                        diag_col1, diag_col2, diag_col3, diag_col4 = (
                            st.columns(4)
                        )
                        diag_col1.metric(
                            "Eligible Invoices",
                            f"{diagnostics['eligible_invoices']:,}",
                        )
                        diag_col2.metric(
                            "Products Analysed",
                            f"{diagnostics['products_analysed']:,}",
                        )
                        diag_col3.metric(
                            "Frequent Itemsets",
                            f"{diagnostics['frequent_itemsets']:,}",
                        )
                        diag_col4.metric(
                            "Rules Returned",
                            f"{diagnostics['rules_after_lift']:,}",
                        )
                        st.caption(
                            f"MBA status: {diagnostics['status']}"
                        )

                    if st.session_state.mba_rules is not None:
                        if st.session_state.mba_rules.empty:
                            st.info(
                                "No association rules met the "
                                "selected thresholds. Try lower "
                                "support/confidence or analyse more "
                                "products."
                            )
                        else:
                            st.dataframe(
                                st.session_state.mba_rules.head(50),
                                width="stretch",
                                hide_index=True,
                            )

            # --------- Geography ---------
            with geo_tab:
                st.subheader("Customer Value by Country")
                st.caption(
                    "Geography summary — where customers are "
                    "concentrated. For geographic drill-down, "
                    "priority targeting, and retention scenarios, "
                    "use the Power BI Dashboard."
                )

                country_source = customer_view.dropna(
                    subset=["Country"]
                ).copy()

                country_summary = (
                    country_source.groupby("Country")
                    .agg(
                        Revenue=("Monetary", "sum"),
                        Customers=("Customer ID", "nunique"),
                        AvgCustomerValue=("Monetary", "mean"),
                        Frequency=("Frequency", "sum"),
                    )
                    .reset_index()
                    .sort_values("Revenue", ascending=False)
                    .reset_index(drop=True)
                )

                map_country_summary = country_summary.loc[
                    ~country_summary["Country"].isin(
                        _COUNTRY_MAP_EXCLUSIONS
                    )
                ].copy()

                if country_summary.empty:
                    st.info(
                        "No country information is available in the "
                        "approved customer summary."
                    )
                else:
                    geo_left, geo_right = st.columns([2, 1])

                    with geo_left:
                        if PLOTLY_AVAILABLE:
                            try:
                                map_fig = px.choropleth(
                                    map_country_summary,
                                    locations="Country",
                                    locationmode="country names",
                                    color="Revenue",
                                    hover_name="Country",
                                    hover_data={
                                        "Revenue": ":,.2f",
                                        "Customers": ":,",
                                        "AvgCustomerValue": ":,.2f",
                                    },
                                    color_continuous_scale="Blues",
                                    title=(
                                        "Customer Value Concentration"
                                    ),
                                )
                                map_fig.update_layout(
                                    height=560,
                                    margin=dict(
                                        l=0, r=0, t=50, b=0
                                    ),
                                    geo=dict(
                                        showframe=False,
                                        showcoastlines=True,
                                        coastlinecolor=(
                                            "rgba(120,120,120,0.35)"
                                        ),
                                        showcountries=True,
                                        countrycolor=(
                                            "rgba(120,120,120,0.25)"
                                        ),
                                        landcolor="#f7f9fc",
                                        bgcolor="rgba(0,0,0,0)",
                                    ),
                                )
                                st.plotly_chart(
                                    map_fig, width="stretch"
                                )
                            except (ValueError, KeyError):
                                st.dataframe(
                                    country_summary,
                                    width="stretch",
                                    hide_index=True,
                                )
                        else:
                            st.dataframe(
                                country_summary,
                                width="stretch",
                                hide_index=True,
                            )

                    with geo_right:
                        st.caption("Top Countries")
                        st.dataframe(
                            country_summary.head(10),
                            width="stretch",
                            hide_index=True,
                        )

                    st.caption(
                        "Colour intensity reflects total customer "
                        "value per country. The table on the right "
                        "shows the same figures numerically. Deeper "
                        "geographic analysis, including priority "
                        "customer drill-down by country, is available "
                        "on the Power BI Dashboard."
                    )

            st.divider()
            st.info(
                "Quick Analytics is intentionally lightweight. Use "
                "the Power BI Dashboard for the full executive, "
                "retention and scenario-analysis experience."
            )

            _quick_loading.empty()

    # --------------------------------------------------------
    # 15c. Power BI Dashboard
    # --------------------------------------------------------
    elif navigation == "Power BI Dashboard":
        _pbi_loading = render_inline_loading(
            "Loading Power BI access..."
        )

        st.header("Power BI Dashboard")
        st.write(
            "Access the approved customer-retention reporting layer. "
            "This workspace is read-only for Business users."
        )

        if not publication_available:
            _pbi_loading.empty()
            st.warning(
                "The reporting layer is not ready because no approved "
                "publication is currently available."
            )
        else:
            publication_version = str(
                latest_publication.get("PublicationVersion", "Unavailable")
            )
            publication_time = str(
                latest_publication.get("PublicationTimestamp", "Unavailable")
            )
            high_value_at_risk = int(
                latest_publication.get("HighValueAtRisk", 0)
            )

            pbi_col1, pbi_col2, pbi_col3, pbi_col4 = st.columns(4)
            pbi_col1.metric(
                "Approved Version", publication_version
            )
            pbi_col2.metric(
                "Customers", f"{len(business_rfm_df):,}"
            )

            at_risk_count = (
                int(business_rfm_df["AtRisk60"].sum())
                if "AtRisk60" in business_rfm_df.columns
                else 0
            )
            pbi_col3.metric("At Risk", f"{at_risk_count:,}")
            pbi_col4.metric(
                "High-Value At Risk", f"{high_value_at_risk:,}"
            )

            data_start, data_through = resolve_publication_data_period(
                latest_publication, business_transactions_df
            )
            source_file = str(
                latest_publication.get("SourceFile", "Unavailable")
            )

            st.caption(
                f"Data period: {format_business_date(data_start)} to "
                f"{format_business_date(data_through)} | Published: "
                f"{publication_time} | Source: {source_file}"
            )

            st.divider()

            if "Priority" in business_rfm_df.columns:
                st.subheader("Retention Priority Distribution")

                business_priority_counts = (
                    business_rfm_df["Priority"]
                    .value_counts()
                    .rename_axis("Priority")
                    .reset_index(name="Customers")
                )
                st.dataframe(
                    business_priority_counts,
                    width="stretch",
                    hide_index=True,
                )

            st.subheader("Approved Reporting Dataset Preview")

            preview_columns = [
                column
                for column in [
                    "Customer ID",
                    "Recency",
                    "Frequency",
                    "Monetary",
                    "RFM_Segment",
                    "RiskLevel",
                    "HighValue",
                    "Priority",
                ]
                if column in business_rfm_df.columns
            ]

            st.dataframe(
                business_rfm_df[preview_columns].head(20),
                width="stretch",
            )

            st.divider()
            st.subheader("Power BI Access")

            if power_bi_url:
                st.link_button(
                    "Open Power BI Dashboard",
                    power_bi_url,
                    type="primary",
                )
                st.success(
                    "The dashboard link is connected to the approved "
                    "business reporting workspace."
                )
            else:
                st.info(
                    "The approved Power BI hand-off dataset is ready. "
                    "The Power BI dashboard URL has not yet been "
                    "configured in Streamlit Secrets."
                )

            reporting_csv = business_rfm_df.to_csv(
                index=False
            ).encode("utf-8")

            st.download_button(
                label="Download Approved RFM Reporting Dataset",
                data=reporting_csv,
                file_name="latest_rfm_analysis_dataset.csv",
                mime="text/csv",
            )

            st.caption(
                "Reporting source: "
                "outputs/published/latest_rfm_analysis_dataset.csv"
            )

            _pbi_loading.empty()
