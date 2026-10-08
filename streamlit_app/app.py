# ============================================================
# RNI CUSTOMER RETENTION SYSTEM
# Features:
# - Authentication
# - Streamlit Secrets
# - Persistent prototype RBAC using SQLite
# - Technical / Business roles
# - User Management
# - Dataset Ingestion
# - Data Validation
# - Data Cleaning
# - RFM Feature Engineering
# - Version & Publish
# - Power BI Hand-off
# - Persistent Audit Trail
# - Excel multi-sheet approval workflow
# - Cancellation-preserving clean transaction layer
# - Data quality scoring and detailed cleaning audit
# - Seven governed team CSV outputs
# - Lightweight business Quick Analytics with map, products and MBA
# - Business-facing data-period / data-through metadata
# - Case-insensitive country standardisation and unresolved-label validation
# - Modern stretch-width Streamlit tables and charts
# ============================================================
# IMPORTS
# ============================================================

import io
import re
import sqlite3
from contextlib import contextmanager

from datetime import datetime
from pathlib import Path

import bcrypt
import pandas as pd
import streamlit as st
import streamlit_authenticator as stauth
import yaml

# Optional visual/association-analysis dependencies.
# The application still runs if these are unavailable; only the related
# business visual or Market Basket Analysis feature is disabled.
try:
    import plotly.express as px
    PLOTLY_AVAILABLE = True
except Exception:
    px = None
    PLOTLY_AVAILABLE = False

try:
    from mlxtend.frequent_patterns import apriori, association_rules
    MLXTEND_AVAILABLE = True
except Exception:
    apriori = None
    association_rules = None
    MLXTEND_AVAILABLE = False


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="RNI Customer Retention System",
    page_icon="CRS",
    layout="wide"
)


# ============================================================
# APPLICATION STYLING
# ============================================================
# wrap after three tabs so navigation never disappears off-screen.
st.markdown(
    """
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
    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# PATHS
# ============================================================

APP_DIR = Path(__file__).parent

CONFIG_PATH = APP_DIR / "config.yaml"

PUBLISH_DIR = (
    APP_DIR
    / "outputs"
    / "published"
)

ARCHIVE_DIR = (
    PUBLISH_DIR
    / "archive"
)

POWER_BI_DIR = (
    PUBLISH_DIR
    / "power_bi"
)

TEAM_OUTPUT_DIR = (
    PUBLISH_DIR
    / "team_outputs"
)

MODEL_ARTIFACT_DIR = (
    APP_DIR
    / "model_artifacts"
)

AUDIT_DIR = (
    APP_DIR
    / "outputs"
    / "audit"
)

AUDIT_LOG_PATH = (
    AUDIT_DIR
    / "audit_trail.csv"
)

USER_DATA_DIR = (
    APP_DIR
    / "data"
)

USER_DB_PATH = (
    USER_DATA_DIR
    / "users.db"
)


# ============================================================
# CREATE REQUIRED DIRECTORIES
# ============================================================

for directory in [
    PUBLISH_DIR,
    ARCHIVE_DIR,
    POWER_BI_DIR,
    TEAM_OUTPUT_DIR,
    AUDIT_DIR,
    USER_DATA_DIR
]:
    directory.mkdir(
        parents=True,
        exist_ok=True
    )


# ============================================================
# LOAD NON-SENSITIVE CONFIGURATION
# ============================================================

def load_config():

    with open(
        CONFIG_PATH,
        "r",
        encoding="utf-8"
    ) as file:

        return yaml.safe_load(file)


config = load_config()


# ============================================================
# DEPLOYMENT SECRETS
# ============================================================

try:

    COOKIE_NAME = (
        st.secrets[
            "cookie"
        ][
            "name"
        ]
    )

    COOKIE_KEY = (
        st.secrets[
            "cookie"
        ][
            "key"
        ]
    )

    COOKIE_EXPIRY_DAYS = int(
        st.secrets[
            "cookie"
        ][
            "expiry_days"
        ]
    )

    POWER_BI_URL = (
        st.secrets[
            "power_bi"
        ][
            "dashboard_url"
        ]
    )

    BOOTSTRAP_USERS = {

        username: {

            "email":
                user_data.get(
                    "email",
                    ""
                ),

            "name":
                user_data.get(
                    "name",
                    username
                ),

            "password":
                user_data[
                    "password"
                ],

            "role":
                user_data.get(
                    "role",
                    "business"
                )

        }

        for (
            username,
            user_data
        )
        in st.secrets[
            "bootstrap_users"
        ].items()
    }


except Exception as e:

    st.error(
        "Application secrets could not be loaded."
    )

    st.info(
        "Check .streamlit/secrets.toml locally, "
        "or the Secrets section in Streamlit Community Cloud."
    )

    st.code(
        str(e)
    )

    st.stop()


# ============================================================
# APPLICATION ROLE CONSTANTS
# ============================================================

TECHNICAL_ROLE = (
    config
    .get(
        "roles",
        {}
    )
    .get(
        "technical",
        "technical"
    )
)

BUSINESS_ROLE = (
    config
    .get(
        "roles",
        {}
    )
    .get(
        "business",
        "business"
    )
)


# ============================================================
# USER DATABASE / RBAC
# ============================================================

def get_user_db_connection():

    connection = sqlite3.connect(
        USER_DB_PATH
    )

    connection.row_factory = (
        sqlite3.Row
    )

    return connection


def initialise_user_database():
    """
    Create the persistent prototype user database.

    Bootstrap accounts from Streamlit Secrets are inserted
    only when the users table is empty.
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
                    CHECK (
                        role IN (
                            'technical',
                            'business'
                        )
                    ),

                is_active INTEGER NOT NULL
                    DEFAULT 1,

                created_at TEXT NOT NULL,

                created_by TEXT NOT NULL,

                updated_at TEXT NOT NULL,

                updated_by TEXT NOT NULL
            )
            """
        )

        existing_count = (
            connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM users
                """
            )
            .fetchone()[
                "total"
            ]
        )

        if existing_count == 0:

            usernames = (
                BOOTSTRAP_USERS
            )

            now = (
                datetime.now()
                .strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            for (
                username,
                user
            ) in usernames.items():

                clean_username = (
                    str(username)
                    .strip()
                    .lower()
                )

                role = (
                    str(
                        user.get(
                            "role",
                            BUSINESS_ROLE
                        )
                    )
                    .strip()
                    .lower()
                )

                if role not in {
                    TECHNICAL_ROLE,
                    BUSINESS_ROLE
                }:
                    role = BUSINESS_ROLE

                connection.execute(
                    """
                    INSERT INTO users (

                        username,
                        name,
                        email,
                        password_hash,
                        role,
                        is_active,

                        created_at,
                        created_by,

                        updated_at,
                        updated_by
                    )

                    VALUES (
                        ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?
                    )
                    """,
                    (
                        clean_username,

                        str(
                            user.get(
                                "name",
                                clean_username
                            )
                        ).strip(),

                        str(
                            user.get(
                                "email",
                                ""
                            )
                            or ""
                        ).strip(),

                        str(
                            user[
                                "password"
                            ]
                        ),

                        role,

                        1,

                        now,
                        "Streamlit Secrets bootstrap",

                        now,
                        "Streamlit Secrets bootstrap"
                    )
                )

        connection.commit()


def normalise_username(
    username
):

    return (
        str(
            username
            or ""
        )
        .strip()
        .lower()
    )


def get_user_record(
    username
):

    username = (
        normalise_username(
            username
        )
    )

    if not username:
        return None

    with get_user_db_connection() as connection:

        row = (
            connection.execute(
                """
                SELECT
                    username,
                    name,
                    email,
                    password_hash,
                    role,
                    is_active,
                    created_at,
                    created_by,
                    updated_at,
                    updated_by

                FROM users

                WHERE username = ?
                """,
                (
                    username,
                )
            )
            .fetchone()
        )

    if row is None:
        return None

    return dict(
        row
    )


def load_users_dataframe():

    with get_user_db_connection() as connection:

        users_df = pd.read_sql_query(
            """
            SELECT

                username AS Username,

                name AS Name,

                email AS Email,

                CASE
                    WHEN role = 'technical'
                    THEN 'Technical'
                    ELSE 'Business'
                END AS Role,

                CASE
                    WHEN is_active = 1
                    THEN 'Active'
                    ELSE 'Inactive'
                END AS Status,

                created_at AS Created,

                created_by AS CreatedBy,

                updated_at AS LastModified,

                updated_by AS ModifiedBy

            FROM users

            ORDER BY
                role DESC,
                username
            """,
            connection
        )

    return users_df


def load_authentication_credentials():
    """
    Only active users are supplied to Streamlit Authenticator.
    """

    credentials = {
        "usernames": {}
    }

    with get_user_db_connection() as connection:

        rows = (
            connection.execute(
                """
                SELECT
                    username,
                    name,
                    email,
                    password_hash,
                    role

                FROM users

                WHERE is_active = 1

                ORDER BY username
                """
            )
            .fetchall()
        )

    for row in rows:

        credentials[
            "usernames"
        ][
            row[
                "username"
            ]
        ] = {

            "name":
                row[
                    "name"
                ],

            "email":
                row[
                    "email"
                ]
                or "",

            "password":
                row[
                    "password_hash"
                ],

            "role":
                row[
                    "role"
                ],

            "logged_in":
                False
        }

    return credentials


# ============================================================
# PASSWORD MANAGEMENT
# ============================================================

def validate_password(
    password,
    confirmation
):

    password = str(
        password
        or ""
    )

    confirmation = str(
        confirmation
        or ""
    )

    if password != confirmation:

        raise ValueError(
            "Password confirmation does not match."
        )

    if len(
        password
    ) < 8:

        raise ValueError(
            "Password must contain at least 8 characters."
        )

    if password.isspace():

        raise ValueError(
            "Password cannot contain only spaces."
        )


def hash_password(
    password
):

    return (
        bcrypt.hashpw(
            password.encode(
                "utf-8"
            ),
            bcrypt.gensalt(
                rounds=12
            )
        )
        .decode(
            "utf-8"
        )
    )


# ============================================================
# TECHNICAL ADMIN SAFEGUARDS
# ============================================================

def count_active_technical_users():

    with get_user_db_connection() as connection:

        total = (
            connection.execute(
                """
                SELECT COUNT(*) AS total

                FROM users

                WHERE
                    role = 'technical'
                    AND
                    is_active = 1
                """
            )
            .fetchone()[
                "total"
            ]
        )

    return int(
        total
    )


# ============================================================
# CREATE USER
# ============================================================

def create_application_user(
    username,
    name,
    email,
    password,
    confirmation,
    role,
    performed_by
):

    username = (
        normalise_username(
            username
        )
    )

    name = str(
        name
        or ""
    ).strip()

    email = str(
        email
        or ""
    ).strip()

    role = str(
        role
        or ""
    ).strip().lower()

    if not username:

        raise ValueError(
            "Username is required."
        )

    if not re.fullmatch(
        r"[a-z0-9._-]+",
        username
    ):

        raise ValueError(
            "Username may contain only lowercase letters, "
            "numbers, dots, underscores and hyphens."
        )

    if not name:

        raise ValueError(
            "Full name is required."
        )

    if role not in {
        TECHNICAL_ROLE,
        BUSINESS_ROLE
    }:

        raise ValueError(
            "Role must be Technical or Business."
        )

    validate_password(
        password,
        confirmation
    )

    password_hash = (
        hash_password(
            password
        )
    )

    now = (
        datetime.now()
        .strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    try:

        with get_user_db_connection() as connection:

            connection.execute(
                """
                INSERT INTO users (

                    username,
                    name,
                    email,
                    password_hash,
                    role,
                    is_active,

                    created_at,
                    created_by,

                    updated_at,
                    updated_by
                )

                VALUES (
                    ?, ?, ?, ?, ?, 1,
                    ?, ?, ?, ?
                )
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
                    performed_by
                )
            )

            connection.commit()

    except sqlite3.IntegrityError as exc:

        raise ValueError(
            f"The username '{username}' already exists."
        ) from exc


# ============================================================
# UPDATE USER
# ============================================================

def update_application_user(
    username,
    name,
    email,
    role,
    performed_by
):

    username = (
        normalise_username(
            username
        )
    )

    existing = (
        get_user_record(
            username
        )
    )

    if existing is None:

        raise ValueError(
            "The selected user does not exist."
        )

    name = str(
        name
        or ""
    ).strip()

    email = str(
        email
        or ""
    ).strip()

    role = str(
        role
        or ""
    ).strip().lower()

    if not name:

        raise ValueError(
            "Full name is required."
        )

    if role not in {
        TECHNICAL_ROLE,
        BUSINESS_ROLE
    }:

        raise ValueError(
            "Role must be Technical or Business."
        )

    if (
        existing[
            "role"
        ]
        == TECHNICAL_ROLE

        and
        bool(
            existing[
                "is_active"
            ]
        )

        and
        role != TECHNICAL_ROLE

        and
        count_active_technical_users()
        <= 1
    ):

        raise ValueError(
            "The final active Technical administrator "
            "cannot be changed to Business."
        )

    now = (
        datetime.now()
        .strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    with get_user_db_connection() as connection:

        connection.execute(
            """
            UPDATE users

            SET
                name = ?,
                email = ?,
                role = ?,
                updated_at = ?,
                updated_by = ?

            WHERE username = ?
            """,
            (
                name,
                email,
                role,
                now,
                performed_by,
                username
            )
        )

        connection.commit()


# ============================================================
# ACTIVATE / DEACTIVATE USER
# ============================================================

def set_application_user_status(
    username,
    active,
    performed_by,
    current_username
):

    username = (
        normalise_username(
            username
        )
    )

    current_username = (
        normalise_username(
            current_username
        )
    )

    existing = (
        get_user_record(
            username
        )
    )

    if existing is None:

        raise ValueError(
            "The selected user does not exist."
        )

    active = bool(
        active
    )

    if (
        username
        == current_username

        and
        not active
    ):

        raise ValueError(
            "You cannot deactivate your own signed-in account."
        )

    if (
        existing[
            "role"
        ]
        == TECHNICAL_ROLE

        and
        bool(
            existing[
                "is_active"
            ]
        )

        and
        not active

        and
        count_active_technical_users()
        <= 1
    ):

        raise ValueError(
            "The final active Technical administrator "
            "cannot be deactivated."
        )

    now = (
        datetime.now()
        .strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    with get_user_db_connection() as connection:

        connection.execute(
            """
            UPDATE users

            SET
                is_active = ?,
                updated_at = ?,
                updated_by = ?

            WHERE username = ?
            """,
            (
                (
                    1
                    if active
                    else 0
                ),
                now,
                performed_by,
                username
            )
        )

        connection.commit()


# ============================================================
# RESET USER PASSWORD
# ============================================================

def reset_application_user_password(
    username,
    password,
    confirmation,
    performed_by
):

    username = (
        normalise_username(
            username
        )
    )

    if (
        get_user_record(
            username
        )
        is None
    ):

        raise ValueError(
            "The selected user does not exist."
        )

    validate_password(
        password,
        confirmation
    )

    password_hash = (
        hash_password(
            password
        )
    )

    now = (
        datetime.now()
        .strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    with get_user_db_connection() as connection:

        connection.execute(
            """
            UPDATE users

            SET
                password_hash = ?,
                updated_at = ?,
                updated_by = ?

            WHERE username = ?
            """,
            (
                password_hash,
                now,
                performed_by,
                username
            )
        )

        connection.commit()


# ============================================================
# REMOVE USER
# ============================================================

def remove_application_user(
    username,
    current_username
):

    username = (
        normalise_username(
            username
        )
    )

    current_username = (
        normalise_username(
            current_username
        )
    )

    existing = (
        get_user_record(
            username
        )
    )

    if existing is None:

        raise ValueError(
            "The selected user does not exist."
        )

    if (
        username
        == current_username
    ):

        raise ValueError(
            "You cannot permanently remove "
            "your own signed-in account."
        )

    if (
        existing[
            "role"
        ]
        == TECHNICAL_ROLE

        and
        bool(
            existing[
                "is_active"
            ]
        )

        and
        count_active_technical_users()
        <= 1
    ):

        raise ValueError(
            "The final active Technical administrator "
            "cannot be removed."
        )

    with get_user_db_connection() as connection:

        connection.execute(
            """
            DELETE FROM users
            WHERE username = ?
            """,
            (
                username,
            )
        )

        connection.commit()


# ============================================================
# INITIALISE USER DATABASE
# ============================================================

initialise_user_database()


# ============================================================
# AUTHENTICATION
# ============================================================

authentication_credentials = (
    load_authentication_credentials()
)


authenticator = stauth.Authenticate(
    authentication_credentials,
    COOKIE_NAME,
    COOKIE_KEY,
    COOKIE_EXPIRY_DAYS,
)


authenticator.login()


# ============================================================
# LOGIN STATUS
# ============================================================

authentication_status = (
    st.session_state.get(
        "authentication_status"
    )
)


if authentication_status is False:

    st.error(
        "Username or password is incorrect, "
        "or the account is inactive."
    )

    st.stop()


elif authentication_status is None:

    st.info(
        "Please log in to continue."
    )

    st.stop()


# ============================================================
# CURRENT USER / ROLE
# ============================================================

current_user = (
    normalise_username(
        st.session_state.get(
            "username"
        )
    )
)


user_data = (
    get_user_record(
        current_user
    )
)


if user_data is None:

    st.error(
        "Your account could not be found "
        "in the authorised user store."
    )

    st.stop()


if not bool(
    user_data[
        "is_active"
    ]
):

    st.error(
        "This account has been deactivated."
    )

    st.stop()


user_role = (
    str(
        user_data[
            "role"
        ]
    )
    .lower()
)


user_name = (
    user_data[
        "name"
    ]
)


# ============================================================
# SIDEBAR USER INFO
# ============================================================

st.sidebar.write(
    f"Logged in as **{user_name}**"
)


st.sidebar.caption(
    f"Role: {user_role.title()}"
)


authenticator.logout(
    "Logout",
    "sidebar"
)


st.sidebar.divider()


# ============================================================
# ROLE-BASED NAVIGATION
# ============================================================

if user_role == TECHNICAL_ROLE:

    navigation = (
        st.sidebar.radio(
            "Technical Workspace",
            [
                "Pipeline Overview",
                "Dataset Ingestion",
                "Data Validation",
                "Data Cleaning",
                "RFM Feature Engineering",
                "Version & Publish",
                "Audit Trail",
                "User Management",
            ],
            key="technical_navigation"
        )
    )


elif user_role == BUSINESS_ROLE:

    navigation = (
        st.sidebar.radio(
            "Business Workspace",
            [
                "Pipeline Status",
                "Quick Analytics",
                "Power BI Dashboard",
            ],
            key="business_navigation"
        )
    )


else:

    st.error(
        "Your account has an unsupported role."
    )

    st.stop()


# ============================================================
# SESSION STATE
# ============================================================

session_defaults = {

    "raw_data":
        None,

    "uploaded_filename":
        None,

    "selected_sheets":
        [],

    "ingestion_complete":
        False,

    "validation_results":
        None,

    "validation_complete":
        False,

    "validation_score":
        None,

    "mba_rules":
        None,

    "mba_diagnostics":
        None,

    "cleaned_data":
        None,

    "cleaning_steps":
        None,

    "cleaning_summary":
        None,

    "cleaning_complete":
        False,

    "rfm_data":
        None,

    "rfm_summary":
        None,

    "rfm_complete":
        False,

    "publication_complete":
        False,

    "publication_summary":
        None,

    "published_rfm_data":
        None,

    "published_at":
        None,
}


for (
    key,
    value
) in session_defaults.items():

    if key not in st.session_state:

        st.session_state[
            key
        ] = value


# ============================================================
# AUDIT TRAIL
# ============================================================

def log_audit_event(
    username,
    role,
    action,
    stage,
    status,
    details="",
    source_file=None,
    publication_version=None
):

    event_time = (
        datetime.now()
    )

    event_id = (
        "EVT_"
        +
        event_time.strftime(
            "%Y%m%d_%H%M%S_%f"
        )
    )

    audit_record = pd.DataFrame({

        "EventID": [
            event_id
        ],

        "Timestamp": [
            event_time.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        ],

        "User": [
            username
        ],

        "Role": [
            role
        ],

        "Stage": [
            stage
        ],

        "Action": [
            action
        ],

        "Status": [
            status
        ],

        "SourceFile": [
            (
                source_file
                if source_file
                else ""
            )
        ],

        "PublicationVersion": [
            (
                publication_version
                if publication_version
                else ""
            )
        ],

        "Details": [
            details
        ]
    })

    audit_record.to_csv(
        AUDIT_LOG_PATH,
        mode="a",
        header=(
            not AUDIT_LOG_PATH.exists()
        ),
        index=False
    )


def load_audit_trail():

    columns = [
        "EventID",
        "Timestamp",
        "User",
        "Role",
        "Stage",
        "Action",
        "Status",
        "SourceFile",
        "PublicationVersion",
        "Details"
    ]

    if not AUDIT_LOG_PATH.exists():

        return pd.DataFrame(
            columns=columns
        )

    audit_df = pd.read_csv(
        AUDIT_LOG_PATH,
        dtype=str,
        keep_default_na=False
    )

    if (
        "Timestamp"
        in audit_df.columns
    ):

        audit_df = (
            audit_df
            .sort_values(
                by="Timestamp",
                ascending=False,
                kind="stable"
            )
            .reset_index(
                drop=True
            )
        )

    return audit_df


# ============================================================
# PIPELINE RESET HELPERS
# ============================================================

def reset_publication_state():

    st.session_state.publication_complete = False
    st.session_state.publication_summary = None
    st.session_state.published_rfm_data = None
    st.session_state.published_at = None


def reset_downstream_from_ingestion():

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

    reset_publication_state()


# ============================================================
# SHARED UI / ANALYTICS HELPERS
# ============================================================

@contextmanager
def loading_overlay(message="Please wait while the application processes your request..."):
    """Display a fixed, centred loading message during heavier operations."""

    overlay = st.empty()
    overlay.markdown(
        f"""
        <div style="
            position: fixed;
            inset: 0;
            z-index: 999999;
            background: rgba(255,255,255,0.82);
            backdrop-filter: blur(2px);
            display: flex;
            align-items: center;
            justify-content: center;">
            <div style="
                max-width: 460px;
                padding: 1.4rem 1.8rem;
                border-radius: 14px;
                background: white;
                border: 1px solid rgba(0,0,0,0.12);
                box-shadow: 0 12px 35px rgba(0,0,0,0.15);
                text-align: center;">
                <div style="font-size:1.15rem;font-weight:700;margin-bottom:0.35rem;">
                    Loading, please wait...
                </div>
                <div style="font-size:0.92rem;color:#555;">
                    {message}
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    try:
        yield
    finally:
        overlay.empty()


def go_to_technical_page(page_name):
    """Move the Technical Workspace radio to the requested next pipeline stage."""

    st.session_state["technical_navigation"] = page_name


def render_proceed_button(label, target_page, key):
    """Render a consistent next-step button after a completed technical stage."""

    st.write("")
    st.button(
        label,
        type="primary",
        key=key,
        on_click=go_to_technical_page,
        args=(target_page,)
    )


# ============================================================
# COUNTRY STANDARDISATION / GEOGRAPHIC VALIDATION
# ============================================================
# Country names are normalised once at the governed cleaning stage so that
# Streamlit, the seven team outputs and Power BI all use the same labels.
# Matching is deliberately case-insensitive and punctuation-insensitive.

COUNTRY_RENAME_MAP = {
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

# Canonical names expected in the Online Retail II geography plus common
# reporting countries.  Unknown labels are never silently changed; they remain
# available for audit and are surfaced as a validation warning.
KNOWN_REPORTING_COUNTRIES = {
    "Australia", "Austria", "Bahrain", "Belgium", "Bermuda", "Botswana",
    "Brazil", "Canada", "Cyprus", "Czech Republic", "Denmark", "Finland",
    "Hong Kong",
    "France", "Germany", "Greece", "Iceland", "Ireland", "Israel", "Italy",
    "Japan", "Lebanon", "Lithuania", "Malta", "Netherlands", "Nigeria",
    "Norway", "Poland", "Portugal", "Saudi Arabia", "Singapore",
    "South Africa", "South Korea", "Spain", "Sweden", "Switzerland",
    "Thailand", "United Arab Emirates", "United Kingdom", "United States",
}

# These labels may appear in the source and are retained for audit, but they are
# not individual countries and should not be sent to a country-name choropleth.
COUNTRY_MAP_EXCLUSIONS = {
    "Unspecified",
    "European Community",
    "West Indies",
    "Channel Islands",
}


def normalise_country_key(value):
    """Return a case/punctuation-insensitive key for comparing country labels."""

    if pd.isna(value):
        return ""

    text = re.sub(r"\s+", " ", str(value).strip())
    text = re.sub(r"[^a-z0-9]+", " ", text.casefold())
    return re.sub(r"\s+", " ", text).strip()


_CANONICAL_COUNTRY_BY_KEY = {
    normalise_country_key(country): country
    for country in KNOWN_REPORTING_COUNTRIES
}

_COUNTRY_EXCLUSION_BY_KEY = {
    normalise_country_key(country): country
    for country in COUNTRY_MAP_EXCLUSIONS
}


def standardise_country_value(value):
    """Standardise one country label without inventing a replacement for unknowns."""

    if pd.isna(value):
        return pd.NA

    cleaned = re.sub(r"\s+", " ", str(value).strip())
    if not cleaned:
        return pd.NA

    key = normalise_country_key(cleaned)

    if key in COUNTRY_RENAME_MAP:
        return COUNTRY_RENAME_MAP[key]

    if key in _CANONICAL_COUNTRY_BY_KEY:
        return _CANONICAL_COUNTRY_BY_KEY[key]

    if key in _COUNTRY_EXCLUSION_BY_KEY:
        return _COUNTRY_EXCLUSION_BY_KEY[key]

    # Preserve unresolved source text for audit instead of silently guessing.
    return cleaned


def standardise_country_names(series):
    """Return reporting-ready country labels with case-insensitive alias handling."""

    return series.astype("string").map(standardise_country_value)


def assess_country_labels(series):
    """Classify unique source country labels as recognised, excluded or unresolved."""

    source = (
        series.astype("string")
        .str.strip()
        .str.replace(r"\s+", " ", regex=True)
        .dropna()
    )
    source = source[source.ne("")]

    unique_source = list(dict.fromkeys(source.tolist()))
    recognised = []
    excluded = []
    unresolved = []

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


# ============================================================
# DATA PERIOD HELPERS
# ============================================================

def get_data_period(df):
    """Return the first and last valid completed-sale dates in a transaction dataset."""

    if df is None or df.empty or "InvoiceDate" not in df.columns:
        return None, None

    working = completed_sales_view(df)
    if working.empty:
        working = df.copy()

    dates = pd.to_datetime(working["InvoiceDate"], errors="coerce").dropna()
    if dates.empty:
        return None, None

    return dates.min(), dates.max()


def format_business_date(value):
    """Format a date for compact business-facing captions."""

    if value is None or pd.isna(value):
        return "Unavailable"

    parsed = pd.to_datetime(value, errors="coerce")
    if pd.isna(parsed):
        return str(value)

    # Cross-platform day formatting without relying on %-d.
    return f"{parsed.day} {parsed.strftime('%b %Y')}"


def resolve_publication_data_period(publication_record=None, transactions_df=None):
    """Read the governed data period from the manifest, with transaction fallback."""

    start_value = None
    through_value = None

    if publication_record is not None:
        try:
            start_value = publication_record.get("DataStartDate")
            through_value = publication_record.get("DataThroughDate")
        except Exception:
            pass

    start_parsed = pd.to_datetime(start_value, errors="coerce")
    through_parsed = pd.to_datetime(through_value, errors="coerce")

    if pd.isna(start_parsed) or pd.isna(through_parsed):
        fallback_start, fallback_through = get_data_period(transactions_df)
        if pd.isna(start_parsed):
            start_parsed = fallback_start
        if pd.isna(through_parsed):
            through_parsed = fallback_through

    return start_parsed, through_parsed


def completed_sales_view(df):
    """Return the analytical sales view while preserving flagged cancellations."""

    if df is None or df.empty:
        return pd.DataFrame()

    working = df.copy()

    if "IsCompletedSale" in working.columns:
        return working.loc[
            working["IsCompletedSale"].fillna(False)
        ].copy()

    mask = pd.Series(True, index=working.index)

    if "IsCancellation" in working.columns:
        mask &= ~working["IsCancellation"].fillna(False)

    if "Quantity" in working.columns:
        mask &= pd.to_numeric(working["Quantity"], errors="coerce").gt(0)

    if "Price" in working.columns:
        mask &= pd.to_numeric(working["Price"], errors="coerce").gt(0)

    return working.loc[mask].copy()


def calculate_data_quality_score(validation_results):
    """Convert PASS/WARNING/FAIL checks into a simple transparent 0-100 score."""

    if validation_results is None or validation_results.empty:
        return 0.0

    weights = {
        "PASS": 1.0,
        "WARNING": 0.5,
        "FAIL": 0.0,
    }

    values = (
        validation_results["Status"]
        .astype(str)
        .str.upper()
        .map(weights)
        .fillna(0.0)
    )

    return float(values.mean() * 100)


@st.cache_data(show_spinner=False)
def read_csv_cached(path_text, modified_time):
    """Cache published CSV reads while automatically invalidating on file changes."""
    del modified_time
    return pd.read_csv(path_text)


def safe_read_published_csv(path):
    """Read a published CSV using a modification-aware Streamlit cache."""

    path = Path(path)
    if not path.exists():
        return None

    return read_csv_cached(
        str(path),
        path.stat().st_mtime_ns
    )


def build_invoice_summary(cleaned_df):
    """Create one governed row per invoice, including cancellation invoices."""

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
        .rename(columns={
            "Quantity": "TotalQuantity",
            "Revenue": "InvoiceValue",
        })
    )

    if "Description" in df.columns:
        unique_products = (
            df.groupby("Invoice", dropna=False)["Description"]
            .nunique(dropna=True)
            .rename("UniqueProducts")
            .reset_index()
        )
        invoice_summary = invoice_summary.merge(
            unique_products,
            on="Invoice",
            how="left"
        )

    invoice_summary["IsCompletedSale"] = (
        ~invoice_summary["IsCancellation"].fillna(False)
        & invoice_summary["TotalQuantity"].gt(0)
        & invoice_summary["InvoiceValue"].gt(0)
    )

    return invoice_summary


def build_rfm_customer_features(cleaned_df, rfm_df):
    """Build reusable customer features from completed sales only."""

    sales = completed_sales_view(cleaned_df)

    if sales.empty or rfm_df is None or rfm_df.empty:
        return rfm_df.copy() if rfm_df is not None else pd.DataFrame()

    sales = sales.dropna(subset=["Customer ID", "InvoiceDate"]).copy()
    sales["Customer ID"] = pd.to_numeric(
        sales["Customer ID"],
        errors="coerce"
    )
    sales = sales.dropna(subset=["Customer ID"]).copy()
    sales["Customer ID"] = sales["Customer ID"].astype(int)

    invoice_level = (
        sales[["Customer ID", "Invoice", "InvoiceDate", "Revenue"]]
        .groupby(["Customer ID", "Invoice"], as_index=False)
        .agg(
            InvoiceDate=("InvoiceDate", "min"),
            InvoiceValue=("Revenue", "sum")
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
        order_features,
        on="Customer ID",
        how="left"
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
        gaps,
        on="Customer ID",
        how="left"
    )

    customer_features = customer_features.merge(
        pd.concat([recent_counts, prior_counts], axis=1)
        .fillna(0)
        .reset_index(),
        on="Customer ID",
        how="left"
    )

    for column in ["Recent60dOrders", "Prior60dOrders"]:
        customer_features[column] = (
            customer_features[column]
            .fillna(0)
            .astype(int)
        )

    customer_features["OrderFrequencyTrend"] = (
        customer_features["Recent60dOrders"]
        - customer_features["Prior60dOrders"]
    )

    return (
        rfm_df.merge(
            customer_features,
            on="Customer ID",
            how="left"
        )
    )


def build_customer_summary(reporting_df, rfm_features_df, risk_df):
    """Create the business-facing Customer 360 master dataset."""

    customer_summary = reporting_df.copy()

    if rfm_features_df is not None and not rfm_features_df.empty:
        extra_columns = [
            column for column in rfm_features_df.columns
            if column == "Customer ID"
            or column not in customer_summary.columns
        ]
        customer_summary = customer_summary.merge(
            rfm_features_df[extra_columns],
            on="Customer ID",
            how="left"
        )

    if risk_df is not None and not risk_df.empty:
        risk_customer_column = None
        for candidate in [
            "Customer ID",
            "CustomerID",
            "customer_id",
            "Customer_ID",
        ]:
            if candidate in risk_df.columns:
                risk_customer_column = candidate
                break

        if risk_customer_column is not None:
            risk_copy = risk_df.copy()
            risk_copy[risk_customer_column] = pd.to_numeric(
                risk_copy[risk_customer_column],
                errors="coerce"
            )
            risk_copy = risk_copy.dropna(subset=[risk_customer_column]).copy()
            risk_copy[risk_customer_column] = risk_copy[risk_customer_column].astype(int)

            if risk_customer_column != "Customer ID":
                risk_copy = risk_copy.rename(
                    columns={risk_customer_column: "Customer ID"}
                )

            risk_columns = [
                column for column in risk_copy.columns
                if column == "Customer ID"
                or column not in customer_summary.columns
            ]

            customer_summary = customer_summary.merge(
                risk_copy[risk_columns].drop_duplicates(subset=["Customer ID"]),
                on="Customer ID",
                how="left"
            )

    return customer_summary


def build_data_validation_report(validation_results, cleaning_steps=None):
    """Create one auditable validation report for the team outputs."""

    validation = (
        validation_results.copy()
        if validation_results is not None
        else pd.DataFrame(columns=["Check", "Status", "Count", "Details"])
    )

    validation["Stage"] = "Pre-Cleaning Validation"
    validation["QualityScore"] = calculate_data_quality_score(validation)

    if cleaning_steps is None or cleaning_steps.empty:
        return validation

    cleaning = cleaning_steps.copy()
    cleaning_report = pd.DataFrame({
        "Check": cleaning["Step"].astype(str),
        "Status": "INFO",
        "Count": cleaning["Rows Removed"],
        "Details": cleaning["Action"].astype(str),
        "Stage": "Cleaning Audit",
        "QualityScore": calculate_data_quality_score(validation),
    })

    return pd.concat(
        [validation, cleaning_report],
        ignore_index=True
    )


def compute_market_basket(
    cleaned_df,
    min_support=0.002,
    min_confidence=0.15,
    min_lift=1.0,
    top_n_products=150,
):
    """Calculate association rules at invoice level with useful diagnostics."""

    diagnostics = {
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

    sales = completed_sales_view(cleaned_df)
    diagnostics["input_rows"] = 0 if cleaned_df is None else len(cleaned_df)

    if sales.empty:
        diagnostics["status"] = "No completed sales available"
        return pd.DataFrame(), diagnostics

    required = {"Invoice", "Description", "Quantity"}
    if not required.issubset(sales.columns):
        diagnostics["status"] = "Required product fields are missing"
        return pd.DataFrame(), diagnostics

    sales = sales.dropna(subset=["Invoice", "Description"]).copy()
    sales["Description"] = sales["Description"].astype(str).str.strip()

    # Remove common non-merchandise / administrative stock codes when present.
    if "StockCode" in sales.columns:
        stock = sales["StockCode"].astype(str).str.upper().str.strip()
        admin_mask = stock.str.match(
            r"^(POST|DOT|M|D|BANK CHARGES|AMAZONFEE|S|CRUK)$",
            na=False
        )
        sales = sales.loc[~admin_mask].copy()

    diagnostics["eligible_rows"] = len(sales)
    diagnostics["eligible_invoices"] = int(sales["Invoice"].nunique())

    if diagnostics["eligible_invoices"] < 2:
        diagnostics["status"] = "Too few invoices for association analysis"
        return pd.DataFrame(), diagnostics

    top_products = (
        sales.groupby("Description")["Quantity"]
        .sum()
        .sort_values(ascending=False)
        .head(int(top_n_products))
        .index
    )
    sales = sales.loc[sales["Description"].isin(top_products)].copy()
    diagnostics["products_analysed"] = int(sales["Description"].nunique())

    try:
        basket = (
            sales.groupby(["Invoice", "Description"])["Quantity"]
            .sum()
            .unstack(fill_value=0)
            .gt(0)
        )

        frequent_itemsets = apriori(
            basket,
            min_support=float(min_support),
            use_colnames=True
        )
        diagnostics["frequent_itemsets"] = len(frequent_itemsets)

        if frequent_itemsets.empty:
            diagnostics["status"] = "No frequent itemsets at the selected support"
            return pd.DataFrame(), diagnostics

        rules = association_rules(
            frequent_itemsets,
            metric="confidence",
            min_threshold=float(min_confidence)
        )
        diagnostics["rules_before_lift"] = len(rules)

        rules = rules.loc[rules["lift"] >= float(min_lift)].copy()
        diagnostics["rules_after_lift"] = len(rules)

        if rules.empty:
            diagnostics["status"] = "No rules meet the selected confidence/lift thresholds"
            return pd.DataFrame(), diagnostics

        rules["Antecedents"] = rules["antecedents"].apply(
            lambda items: ", ".join(sorted(map(str, items)))
        )
        rules["Consequents"] = rules["consequents"].apply(
            lambda items: ", ".join(sorted(map(str, items)))
        )

        output = (
            rules[[
                "Antecedents",
                "Consequents",
                "support",
                "confidence",
                "lift",
            ]]
            .sort_values(
                ["lift", "confidence", "support"],
                ascending=False
            )
            .reset_index(drop=True)
        )
        diagnostics["status"] = "Success"
        return output, diagnostics

    except Exception as exc:
        diagnostics["status"] = f"Analysis error: {exc}"
        return pd.DataFrame(), diagnostics


# ============================================================
# DATA INGESTION HELPERS
# ============================================================

def get_excel_sheet_names(
    uploaded_file
):

    workbook_bytes = (
        uploaded_file.getvalue()
    )

    with pd.ExcelFile(
        io.BytesIO(
            workbook_bytes
        )
    ) as workbook:

        return workbook.sheet_names


def load_uploaded_data(
    uploaded_file,
    selected_sheets=None
):

    filename = (
        uploaded_file.name
        .lower()
    )

    if filename.endswith(
        ".csv"
    ):

        return pd.read_csv(
            io.BytesIO(
                uploaded_file.getvalue()
            )
        )

    elif filename.endswith(
        ".xlsx"
    ):

        if not selected_sheets:

            raise ValueError(
                "Select at least one Excel sheet "
                "before loading the dataset."
            )

        sheets = pd.read_excel(
            io.BytesIO(
                uploaded_file.getvalue()
            ),
            sheet_name=list(
                selected_sheets
            )
        )

        if len(
            sheets
        ) == 0:

            raise ValueError(
                "No Excel sheets were loaded."
            )

        first_sheet_name = (
            list(
                sheets.keys()
            )[0]
        )

        reference_columns = list(
            sheets[
                first_sheet_name
            ].columns
        )

        incompatible_sheets = []

        for (
            sheet_name,
            sheet_df
        ) in sheets.items():

            if (
                list(
                    sheet_df.columns
                )
                != reference_columns
            ):

                incompatible_sheets.append(
                    sheet_name
                )

        if incompatible_sheets:

            raise ValueError(
                "Selected Excel sheets do not have matching structures. "
                "Incompatible sheet(s): "
                +
                ", ".join(
                    incompatible_sheets
                )
            )

        return pd.concat(
            sheets.values(),
            ignore_index=True
        )

    raise ValueError(
        "Unsupported file type. "
        "Upload a CSV or XLSX file."
    )


# ============================================================
# DATA VALIDATION
# ============================================================

def validate_dataset(
    df
):

    validation_results = []

    required_columns = [
        "Invoice",
        "StockCode",
        "Description",
        "Quantity",
        "InvoiceDate",
        "Price",
        "Customer ID",
        "Country"
    ]

    missing_columns = [

        column

        for column
        in required_columns

        if column
        not in df.columns
    ]

    if missing_columns:

        validation_results.append({

            "Check":
                "Required Schema",

            "Status":
                "FAIL",

            "Count":
                len(
                    missing_columns
                ),

            "Details":
                (
                    "Missing required columns: "
                    +
                    ", ".join(
                        missing_columns
                    )
                )
        })

        return pd.DataFrame(
            validation_results
        )

    validation_results.append({

        "Check":
            "Required Schema",

        "Status":
            "PASS",

        "Count":
            0,

        "Details":
            "All required columns are present."
    })

    validation_df = (
        df.copy()
    )

    # Country-label governance.  Known aliases are assessed case-insensitively
    # before cleaning so the Technical user can see whether any geography will
    # fail to resolve cleanly in Streamlit or Power BI maps.
    country_assessment = assess_country_labels(
        validation_df["Country"]
    )

    recognised_countries = country_assessment["recognised"]
    excluded_country_labels = country_assessment["excluded"]
    unresolved_country_labels = country_assessment["unresolved"]

    validation_results.append({
        "Check": "Recognised Country Labels",
        "Status": "PASS",
        "Count": len(recognised_countries),
        "Details": (
            f"{len(recognised_countries)} unique country label(s) are recognised "
            "after case-insensitive standardisation."
        )
    })

    validation_results.append({
        "Check": "Excluded Aggregate Country Labels",
        # These labels are explicitly governed and excluded from maps, so their
        # presence is informative rather than a data-quality penalty.
        "Status": "PASS",
        "Count": len(excluded_country_labels),
        "Details": (
            "Retained for audit but excluded from the world map: "
            + ", ".join(excluded_country_labels)
            if excluded_country_labels
            else "No aggregate/non-country geography labels detected."
        )
    })

    validation_results.append({
        "Check": "Unresolved Country Labels",
        "Status": (
            "WARNING"
            if unresolved_country_labels
            else "PASS"
        ),
        "Count": len(unresolved_country_labels),
        "Details": (
            "Review these labels before reporting: "
            + ", ".join(unresolved_country_labels)
            if unresolved_country_labels
            else "All country labels are recognised or explicitly excluded from mapping."
        )
    })

    # Missing Customer IDs
    missing_customer_ids = int(
        validation_df[
            "Customer ID"
        ]
        .isna()
        .sum()
    )

    validation_results.append({

        "Check":
            "Missing Customer IDs",

        "Status":
            (
                "WARNING"
                if missing_customer_ids > 0
                else "PASS"
            ),

        "Count":
            missing_customer_ids,

        "Details":
            (
                "Missing Customer IDs detected. "
                "These records may remain available for transaction-level "
                "analysis but cannot be used for customer-level RFM analysis."
                if missing_customer_ids > 0
                else
                "No missing Customer IDs detected."
            )
    })

    # Missing Descriptions
    missing_descriptions = int(
        validation_df[
            "Description"
        ]
        .isna()
        .sum()
    )

    validation_results.append({

        "Check":
            "Missing Descriptions",

        "Status":
            (
                "WARNING"
                if missing_descriptions > 0
                else "PASS"
            ),

        "Count":
            missing_descriptions,

        "Details":
            (
                "Some product descriptions are missing."
                if missing_descriptions > 0
                else
                "No missing product descriptions detected."
            )
    })

    # Exact duplicates
    duplicate_rows = int(
        validation_df
        .duplicated()
        .sum()
    )

    validation_results.append({

        "Check":
            "Exact Duplicate Rows",

        "Status":
            (
                "WARNING"
                if duplicate_rows > 0
                else "PASS"
            ),

        "Count":
            duplicate_rows,

        "Details":
            (
                "Exact duplicate records were detected."
                if duplicate_rows > 0
                else
                "No exact duplicate records detected."
            )
    })

    # Cancellation transactions
    invoice_text = (
        validation_df[
            "Invoice"
        ]
        .astype(
            str
        )
        .str.strip()
        .str.upper()
    )

    cancellation_count = int(
        invoice_text
        .str.startswith(
            "C"
        )
        .sum()
    )

    validation_results.append({

        "Check":
            "Cancellation Transactions",

        "Status":
            (
                "WARNING"
                if cancellation_count > 0
                else "PASS"
            ),

        "Count":
            cancellation_count,

        "Details":
            (
                "Invoices beginning with C were detected."
                if cancellation_count > 0
                else
                "No cancellation invoices detected."
            )
    })

    # Quantity checks
    quantity_numeric = pd.to_numeric(
        validation_df[
            "Quantity"
        ],
        errors="coerce"
    )

    invalid_quantity = int(
        quantity_numeric
        .isna()
        .sum()
    )

    validation_results.append({

        "Check":
            "Invalid Quantity Values",

        "Status":
            (
                "FAIL"
                if invalid_quantity > 0
                else "PASS"
            ),

        "Count":
            invalid_quantity,

        "Details":
            (
                "Some Quantity values could not be interpreted as numbers."
                if invalid_quantity > 0
                else
                "Quantity values are numeric."
            )
    })

    negative_quantity = int(
        (
            quantity_numeric
            < 0
        )
        .sum()
    )

    validation_results.append({

        "Check":
            "Negative Quantities",

        "Status":
            (
                "WARNING"
                if negative_quantity > 0
                else "PASS"
            ),

        "Count":
            negative_quantity,

        "Details":
            (
                "Negative quantities may represent returns or adjustments."
                if negative_quantity > 0
                else
                "No negative quantities detected."
            )
    })

    zero_quantity = int(
        (
            quantity_numeric
            == 0
        )
        .sum()
    )

    validation_results.append({

        "Check":
            "Zero Quantities",

        "Status":
            (
                "WARNING"
                if zero_quantity > 0
                else "PASS"
            ),

        "Count":
            zero_quantity,

        "Details":
            (
                "Zero quantity transactions were detected."
                if zero_quantity > 0
                else
                "No zero quantities detected."
            )
    })

    # Price checks
    price_numeric = pd.to_numeric(
        validation_df[
            "Price"
        ],
        errors="coerce"
    )

    invalid_price = int(
        price_numeric
        .isna()
        .sum()
    )

    validation_results.append({

        "Check":
            "Invalid Price Values",

        "Status":
            (
                "FAIL"
                if invalid_price > 0
                else "PASS"
            ),

        "Count":
            invalid_price,

        "Details":
            (
                "Some Price values could not be interpreted as numbers."
                if invalid_price > 0
                else
                "Price values are numeric."
            )
    })

    negative_price = int(
        (
            price_numeric
            < 0
        )
        .sum()
    )

    validation_results.append({

        "Check":
            "Negative Prices",

        "Status":
            (
                "WARNING"
                if negative_price > 0
                else "PASS"
            ),

        "Count":
            negative_price,

        "Details":
            (
                "Negative prices were detected and require review."
                if negative_price > 0
                else
                "No negative prices detected."
            )
    })

    zero_price = int(
        (
            price_numeric
            == 0
        )
        .sum()
    )

    validation_results.append({

        "Check":
            "Zero Prices",

        "Status":
            (
                "WARNING"
                if zero_price > 0
                else "PASS"
            ),

        "Count":
            zero_price,

        "Details":
            (
                "Zero-price transactions were detected."
                if zero_price > 0
                else
                "No zero prices detected."
            )
    })

    # Invoice date
    parsed_dates = pd.to_datetime(
        validation_df[
            "InvoiceDate"
        ],
        errors="coerce"
    )

    invalid_dates = int(
        parsed_dates
        .isna()
        .sum()
    )

    validation_results.append({

        "Check":
            "Invalid Invoice Dates",

        "Status":
            (
                "FAIL"
                if invalid_dates > 0
                else "PASS"
            ),

        "Count":
            invalid_dates,

        "Details":
            (
                "Some InvoiceDate values could not be converted to valid dates."
                if invalid_dates > 0
                else
                "All InvoiceDate values are valid."
            )
    })

    return pd.DataFrame(
        validation_results
    )


# ============================================================
# DATA CLEANING
# ============================================================

def clean_dataset(
    df
):
    """
    Clean and standardise transaction data while preserving cancellations.

    The returned clean transaction dataset keeps cancellation/return records
    for audit and cancellation reporting.  The IsCompletedSale flag identifies
    rows that are eligible for revenue, RFM, product, MBA and model analytics.
    """

    raw_df = df.copy()
    summary_rows = []
    starting_rows = len(raw_df)

    summary_rows.append({
        "Step": "Raw dataset",
        "Rows Before": starting_rows,
        "Rows Removed": 0,
        "Rows After": starting_rows,
        "Action": "Preserved source data before cleaning."
    })

    # 1. Remove only exact duplicate records.
    before_duplicates = len(raw_df)
    prepared_df = raw_df.drop_duplicates().copy()
    after_duplicates = len(prepared_df)
    duplicates_removed = before_duplicates - after_duplicates

    summary_rows.append({
        "Step": "Exact duplicate removal",
        "Rows Before": before_duplicates,
        "Rows Removed": duplicates_removed,
        "Rows After": after_duplicates,
        "Action": "Removed only completely identical transaction rows."
    })

    # 2. Standardise text fields without changing business meaning.
    for column in ["Invoice", "StockCode"]:
        prepared_df[column] = prepared_df[column].astype(str).str.strip()

    # Standardise known country aliases at the governed cleaning stage so all
    # downstream team CSVs, Streamlit visuals and Power BI use one country name.
    prepared_df["Country"] = standardise_country_names(
        prepared_df["Country"]
    )

    prepared_df["Description"] = (
        prepared_df["Description"]
        .astype("string")
        .str.strip()
    )

    # 3. Convert analytical fields to consistent data types.
    prepared_df["InvoiceDate"] = pd.to_datetime(
        prepared_df["InvoiceDate"],
        errors="coerce"
    )
    prepared_df["Quantity"] = pd.to_numeric(
        prepared_df["Quantity"],
        errors="coerce"
    )
    prepared_df["Price"] = pd.to_numeric(
        prepared_df["Price"],
        errors="coerce"
    )
    prepared_df["Customer ID"] = pd.to_numeric(
        prepared_df["Customer ID"],
        errors="coerce"
    )

    summary_rows.append({
        "Step": "Type and format standardisation",
        "Rows Before": len(prepared_df),
        "Rows Removed": 0,
        "Rows After": len(prepared_df),
        "Action": "Standardised identifiers/text and converted date/numeric fields."
    })

    # 4. Preserve cancellations/returns as explicit governed records.
    prepared_df["IsCancellation"] = (
        prepared_df["Invoice"]
        .str.upper()
        .str.startswith("C")
    )
    cancellation_count = int(prepared_df["IsCancellation"].sum())

    summary_rows.append({
        "Step": "Cancellation identification",
        "Rows Before": len(prepared_df),
        "Rows Removed": 0,
        "Rows After": len(prepared_df),
        "Action": (
            f"Flagged and preserved {cancellation_count:,} cancellation/return rows; "
            "they remain available for cancellation reporting."
        )
    })

    # 5. Remove only records that cannot be interpreted as transactions at all.
    before_invalid = len(prepared_df)
    valid_core_mask = (
        prepared_df["InvoiceDate"].notna()
        & prepared_df["Quantity"].notna()
        & prepared_df["Price"].notna()
    )
    cleaned_df = prepared_df.loc[valid_core_mask].copy()
    invalid_removed = before_invalid - len(cleaned_df)

    summary_rows.append({
        "Step": "Invalid core field removal",
        "Rows Before": before_invalid,
        "Rows Removed": invalid_removed,
        "Rows After": len(cleaned_df),
        "Action": (
            "Removed only rows with unusable InvoiceDate, Quantity or Price values. "
            "Valid cancellations and returns were retained."
        )
    })

    # 6. Add line value and analytical eligibility flags.
    cleaned_df["Revenue"] = (
        cleaned_df["Quantity"]
        * cleaned_df["Price"]
    )

    cleaned_df["IsCompletedSale"] = (
        ~cleaned_df["IsCancellation"]
        & cleaned_df["Quantity"].gt(0)
        & cleaned_df["Price"].gt(0)
    )

    cleaned_df["TransactionType"] = "Other / Adjustment"
    cleaned_df.loc[
        cleaned_df["IsCancellation"],
        "TransactionType"
    ] = "Cancellation / Return"
    cleaned_df.loc[
        cleaned_df["IsCompletedSale"],
        "TransactionType"
    ] = "Completed Sale"

    # Calendar fields support Power BI and Streamlit reporting.
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

    summary_rows.append({
        "Step": "Analytical eligibility",
        "Rows Before": len(cleaned_df),
        "Rows Removed": 0,
        "Rows After": len(cleaned_df),
        "Action": (
            f"Flagged {completed_sales_rows:,} completed-sale rows for revenue/RFM/product "
            f"analysis while preserving {non_analytical_rows:,} non-sale rows."
        )
    })

    final_rows = len(cleaned_df)
    total_removed = starting_rows - final_rows
    retained_percentage = (
        (final_rows / starting_rows) * 100
        if starting_rows > 0
        else 0
    )
    missing_customer_ids = int(cleaned_df["Customer ID"].isna().sum())

    final_summary = {
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

    return (
        cleaned_df,
        pd.DataFrame(summary_rows),
        final_summary
    )


# ============================================================
# RFM FEATURE ENGINEERING
# ============================================================

def assign_rfm_segment(
    score
):

    if score >= 13:
        return "Champions"

    elif score >= 10:
        return "Loyal Customers"

    elif score >= 7:
        return "Potential Loyalists"

    elif score >= 5:
        return "At Risk"

    else:
        return "Lost / Low Value"


def build_rfm_features(
    cleaned_df
):

    required_columns = [
        "Customer ID",
        "Invoice",
        "InvoiceDate",
        "Revenue"
    ]

    missing_columns = [

        column

        for column
        in required_columns

        if column
        not in cleaned_df.columns
    ]

    if missing_columns:

        raise ValueError(
            "RFM feature engineering cannot continue. "
            "Missing required fields: "
            +
            ", ".join(
                missing_columns
            )
        )

    # RFM must use completed positive sales only.  Cancellation rows remain
    # available in the clean transaction layer but are deliberately excluded here.
    analytical_sales = completed_sales_view(
        cleaned_df
    )

    rfm_df = (
        analytical_sales
        .dropna(
            subset=[
                "Customer ID"
            ]
        )
        .copy()
    )

    if rfm_df.empty:

        raise ValueError(
            "No identifiable customer records "
            "are available for RFM analysis."
        )

    rfm_df[
        "Customer ID"
    ] = pd.to_numeric(
        rfm_df[
            "Customer ID"
        ],
        errors="coerce"
    )

    rfm_df = (
        rfm_df
        .dropna(
            subset=[
                "Customer ID"
            ]
        )
        .copy()
    )

    rfm_df[
        "Customer ID"
    ] = (
        rfm_df[
            "Customer ID"
        ]
        .astype(
            int
        )
    )

    unique_customers = int(
        rfm_df[
            "Customer ID"
        ]
        .nunique()
    )

    if unique_customers < 5:

        raise ValueError(
            "At least 5 identifiable customers "
            "are required for quintile-based RFM scoring."
        )

    observation_date = (
        rfm_df[
            "InvoiceDate"
        ]
        .max()
    )

    if pd.isna(
        observation_date
    ):

        raise ValueError(
            "A valid observation date could not be determined."
        )

    customer_invoices = (
        rfm_df[
            [
                "Customer ID",
                "Invoice",
                "InvoiceDate"
            ]
        ]
        .drop_duplicates()
    )

    customer_recency = (
        customer_invoices
        .groupby(
            "Customer ID"
        )[
            "InvoiceDate"
        ]
        .max()
        .reset_index()
        .rename(
            columns={
                "InvoiceDate":
                    "LastPurchase"
            }
        )
    )

    customer_recency[
        "Recency"
    ] = (

        (
            observation_date
            -
            customer_recency[
                "LastPurchase"
            ]
        )
        .dt.total_seconds()

        /
        (
            24
            *
            60
            *
            60
        )
    )

    customer_frequency = (
        customer_invoices
        .groupby(
            "Customer ID"
        )[
            "Invoice"
        ]
        .nunique()
        .reset_index()
        .rename(
            columns={
                "Invoice":
                    "Frequency"
            }
        )
    )

    customer_monetary = (
        rfm_df
        .groupby(
            "Customer ID"
        )[
            "Revenue"
        ]
        .sum()
        .reset_index()
        .rename(
            columns={
                "Revenue":
                    "Monetary"
            }
        )
    )

    rfm = (
        customer_recency
        .merge(
            customer_frequency,
            on="Customer ID",
            how="inner"
        )
        .merge(
            customer_monetary,
            on="Customer ID",
            how="inner"
        )
    )

    rfm[
        "R_Score"
    ] = pd.qcut(
        rfm[
            "Recency"
        ],
        q=5,
        labels=[
            5,
            4,
            3,
            2,
            1
        ],
        duplicates="drop"
    ).astype(
        int
    )

    rfm[
        "F_Score"
    ] = pd.qcut(
        rfm[
            "Frequency"
        ]
        .rank(
            method="first"
        ),
        q=5,
        labels=[
            1,
            2,
            3,
            4,
            5
        ]
    ).astype(
        int
    )

    rfm[
        "M_Score"
    ] = pd.qcut(
        rfm[
            "Monetary"
        ]
        .rank(
            method="first"
        ),
        q=5,
        labels=[
            1,
            2,
            3,
            4,
            5
        ]
    ).astype(
        int
    )

    rfm[
        "RFM_Score"
    ] = (
        rfm[
            "R_Score"
        ]
        +
        rfm[
            "F_Score"
        ]
        +
        rfm[
            "M_Score"
        ]
    )

    rfm[
        "RFM_Segment"
    ] = (
        rfm[
            "RFM_Score"
        ]
        .apply(
            assign_rfm_segment
        )
    )

    # Operational inactivity rule
    rfm[
        "AtRisk60"
    ] = (
        rfm[
            "Recency"
        ]
        >= 60
    )

    rfm[
        "RiskLevel"
    ] = (
        rfm[
            "AtRisk60"
        ]
        .map(
            {
                True:
                    "At Risk",

                False:
                    "Active"
            }
        )
    )

    rfm = (
        rfm[
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
                "RiskLevel"
            ]
        ]
        .copy()
    )

    segment_counts = (
        rfm[
            "RFM_Segment"
        ]
        .value_counts()
        .rename_axis(
            "RFM Segment"
        )
        .reset_index(
            name="Customers"
        )
    )

    segment_counts[
        "Percentage"
    ] = (
        segment_counts[
            "Customers"
        ]
        /
        len(
            rfm
        )
        *
        100
    )

    risk_counts = (
        rfm[
            "RiskLevel"
        ]
        .value_counts()
        .rename_axis(
            "Risk Level"
        )
        .reset_index(
            name="Customers"
        )
    )

    risk_counts[
        "Percentage"
    ] = (
        risk_counts[
            "Customers"
        ]
        /
        len(
            rfm
        )
        *
        100
    )

    summary = {

        "clean_transaction_rows":
            len(
                cleaned_df
            ),

        "identifiable_transaction_rows":
            len(
                rfm_df
            ),

        "customers":
            len(
                rfm
            ),

        "observation_date":
            observation_date,

        "purchase_events":
            len(
                customer_invoices
            ),

        "columns":
            len(
                rfm.columns
            ),

        "mean_recency":
            rfm[
                "Recency"
            ].mean(),

        "mean_frequency":
            rfm[
                "Frequency"
            ].mean(),

        "mean_monetary":
            rfm[
                "Monetary"
            ].mean(),

        "median_recency":
            rfm[
                "Recency"
            ].median(),

        "median_frequency":
            rfm[
                "Frequency"
            ].median(),

        "median_monetary":
            rfm[
                "Monetary"
            ].median(),

        "at_risk_customers":
            int(
                rfm[
                    "AtRisk60"
                ]
                .sum()
            ),

        "active_customers":
            int(
                (
                    ~rfm[
                        "AtRisk60"
                    ]
                )
                .sum()
            ),

        "duplicate_customers":
            int(
                rfm[
                    "Customer ID"
                ]
                .duplicated()
                .sum()
            ),

        "missing_rfm_values":
            int(
                rfm[
                    [
                        "Recency",
                        "Frequency",
                        "Monetary"
                    ]
                ]
                .isna()
                .sum()
                .sum()
            ),

        "segment_counts":
            segment_counts,

        "risk_counts":
            risk_counts
    }

    return (
        rfm,
        summary
    )


# ============================================================
# PUBLICATION
# ============================================================

def reset_publication_state():

    st.session_state.publication_complete = False
    st.session_state.publication_summary = None
    st.session_state.published_rfm_data = None
    st.session_state.published_at = None


def build_reporting_dataset(
    rfm_df
):

    reporting_df = (
        rfm_df.copy()
    )

    high_value_threshold = (
        reporting_df[
            "Monetary"
        ]
        .quantile(
            0.75
        )
    )

    reporting_df[
        "HighValue"
    ] = (
        reporting_df[
            "Monetary"
        ]
        >= high_value_threshold
    )

    reporting_df[
        "Priority"
    ] = "Standard"

    reporting_df.loc[

        (
            reporting_df[
                "AtRisk60"
            ]

            &

            reporting_df[
                "HighValue"
            ]
        ),

        "Priority"

    ] = "High Priority"

    reporting_df.loc[

        (
            reporting_df[
                "AtRisk60"
            ]

            &

            ~reporting_df[
                "HighValue"
            ]
        ),

        "Priority"

    ] = "Retention Opportunity"

    return (
        reporting_df,
        high_value_threshold
    )


def publish_pipeline_outputs(
    cleaned_df,
    rfm_df,
    source_filename,
    username,
    validation_results=None,
    cleaning_steps=None,
):
    """
    Publish the governed application outputs.

    Existing RFM/model files remain available for backwards compatibility,
    while the seven team deliverables are also written from one controlled
    publication event so Streamlit and Power BI can use the same definitions.
    """

    publication_time = datetime.now()
    timestamp = publication_time.strftime("%Y%m%d_%H%M%S_%f")
    publication_version = f"PUB_{timestamp}"
    publication_display_time = publication_time.strftime("%Y-%m-%d %H:%M:%S")

    # Keep the source data period separate from the publication timestamp.
    # This prevents historical retail data from being mistaken for current data.
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

    # Verify predictive label polarity before anything is published.
    required_prediction_columns = {
        "PredictedRetentionRisk",
        "PredictedRiskLevel"
    }

    if required_prediction_columns.issubset(temporal_df.columns):
        invalid_mapping = temporal_df.loc[
            (
                temporal_df["PredictedRetentionRisk"].eq(1)
                & temporal_df["PredictedRiskLevel"].ne("At Risk")
            )
            |
            (
                temporal_df["PredictedRetentionRisk"].eq(0)
                & temporal_df["PredictedRiskLevel"].ne("Retained")
            )
        ]

        if not invalid_mapping.empty:
            raise ValueError(
                "Predictive label mapping failed: "
                "1 must mean At Risk and 0 must mean Retained."
            )

    # Build the seven team deliverables from the same approved publication.
    invoice_summary_df = build_invoice_summary(cleaned_df)
    rfm_customer_features_df = build_rfm_customer_features(
        cleaned_df,
        rfm_df
    )
    final_customer_risk_prediction_df = temporal_df.copy()
    customer_summary_df = build_customer_summary(
        reporting_df,
        rfm_customer_features_df,
        final_customer_risk_prediction_df
    )
    validation_report_df = build_data_validation_report(
        validation_results,
        cleaning_steps
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

    team_paths = {}
    team_archive_paths = {}

    for output_name, output_df in team_outputs.items():
        latest_path = TEAM_OUTPUT_DIR / f"{output_name}.csv"
        archive_path = ARCHIVE_DIR / f"{output_name}_{timestamp}.csv"
        output_df.to_csv(latest_path, index=False)
        output_df.to_csv(archive_path, index=False)
        team_paths[output_name] = latest_path
        team_archive_paths[output_name] = archive_path

    # Existing stable / archive outputs retained for backwards compatibility.
    clean_archive_path = ARCHIVE_DIR / f"clean_transactions_{timestamp}.csv"
    rfm_archive_path = ARCHIVE_DIR / f"rfm_analysis_dataset_{timestamp}.csv"
    cv_archive_path = ARCHIVE_DIR / f"model_cv_results_{timestamp}.csv"
    temporal_archive_path = ARCHIVE_DIR / f"temporal_test_predictions_{timestamp}.csv"

    latest_clean_path = PUBLISH_DIR / "latest_clean_transactions.csv"
    latest_rfm_path = PUBLISH_DIR / "latest_rfm_analysis_dataset.csv"
    latest_cv_path = PUBLISH_DIR / "latest_model_cv_results.csv"
    latest_temporal_path = PUBLISH_DIR / "latest_temporal_test_predictions.csv"

    power_bi_rfm_path = POWER_BI_DIR / "rfm_analysis_dataset.csv"
    power_bi_cv_path = POWER_BI_DIR / "model_cv_results.csv"
    power_bi_temporal_path = POWER_BI_DIR / "temporal_test_predictions.csv"

    # Recommended Power BI business contract: customer, transaction and invoice grain.
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

    predicted_counts = (
        temporal_df["PredictedRiskLevel"]
        .value_counts()
        .rename_axis("PredictedRiskLevel")
        .reset_index(name="Customers")
        if "PredictedRiskLevel" in temporal_df.columns
        else pd.DataFrame(columns=["PredictedRiskLevel", "Customers"])
    )

    predicted_at_risk = int(
        temporal_df["PredictedRiskLevel"].eq("At Risk").sum()
    ) if "PredictedRiskLevel" in temporal_df.columns else 0

    predicted_retained = int(
        temporal_df["PredictedRiskLevel"].eq("Retained").sum()
    ) if "PredictedRiskLevel" in temporal_df.columns else 0

    manifest_record = pd.DataFrame({
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
        "DataQualityScore": [calculate_data_quality_score(validation_results)],
        "PowerBIRFMFile": [power_bi_rfm_path.name],
        "PowerBICVFile": [power_bi_cv_path.name],
        "PowerBITemporalFile": [power_bi_temporal_path.name],
        "PowerBICustomerSummaryFile": [power_bi_customer_summary_path.name],
        "PowerBICleanTransactionsFile": [power_bi_clean_transactions_path.name],
        "PowerBIInvoiceSummaryFile": [power_bi_invoice_summary_path.name],
    })

    if manifest_path.exists():
        existing_manifest = pd.read_csv(manifest_path)
        publication_manifest = pd.concat(
            [existing_manifest, manifest_record],
            ignore_index=True
        )
    else:
        publication_manifest = manifest_record.copy()

    publication_manifest.to_csv(manifest_path, index=False)

    publication_summary = {
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
        "data_quality_score": calculate_data_quality_score(validation_results),
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
# MAIN HEADER
# ============================================================

st.title(
    "RNI Customer Retention System"
)

st.caption(
    "Controlled data preparation, customer feature engineering "
    "and Power BI hand-off."
)


# ============================================================
# TECHNICAL WORKSPACE
# ============================================================

if user_role == TECHNICAL_ROLE:


    # ========================================================
    # PIPELINE OVERVIEW
    # ========================================================

    if navigation == "Pipeline Overview":

        st.header(
            "Pipeline Overview"
        )

        st.write(
            "This workspace is used by authorised Technical users "
            "to ingest, validate, clean and prepare customer data "
            "before publication to the Power BI reporting layer."
        )

        # Keep status cards readable: three on the first row and two below.
        top1, top2, top3 = st.columns(3)

        top1.metric(
            "Dataset",
            (
                "Loaded"
                if st.session_state.ingestion_complete
                else "Not Loaded"
            )
        )

        top2.metric(
            "Validation",
            (
                "Completed"
                if st.session_state.validation_complete
                else "Not Run"
            )
        )

        top3.metric(
            "Cleaning",
            (
                "Completed"
                if st.session_state.cleaning_complete
                else "Not Run"
            )
        )

        bottom1, bottom2 = st.columns(2)

        bottom1.metric(
            "RFM",
            (
                "Completed"
                if st.session_state.rfm_complete
                else "Not Run"
            )
        )

        bottom2.metric(
            "Power BI Handoff",
            (
                "Published"
                if st.session_state.publication_complete
                else "Not Published"
            )
        )

        # The status cards already communicate pipeline progress, so the
        # previous full-width information banner was removed to keep this
        # overview compact and uncluttered.


    # ========================================================
    # DATASET INGESTION
    # ========================================================

    elif navigation == "Dataset Ingestion":

        st.header(
            "Dataset Ingestion"
        )

        st.write(
            "Upload the retail transaction dataset that will enter "
            "the controlled customer-retention preparation pipeline."
        )

        st.caption(
            "Supported formats: CSV and Excel (.xlsx). "
            "No data cleaning is performed during ingestion."
        )

        uploaded_file = (
            st.file_uploader(
                "Upload retail dataset",
                type=[
                    "csv",
                    "xlsx"
                ]
            )
        )

        selected_sheets = None

        if uploaded_file is not None:

            st.subheader(
                "File Information"
            )

            col1, col2, col3 = (
                st.columns(
                    3
                )
            )

            col1.metric(
                "File Name",
                uploaded_file.name
            )

            file_size_mb = (
                uploaded_file.size
                /
                (
                    1024
                    *
                    1024
                )
            )

            col2.metric(
                "File Size",
                f"{file_size_mb:.2f} MB"
            )

            file_extension = (
                uploaded_file.name
                .split(
                    "."
                )[-1]
                .upper()
            )

            col3.metric(
                "File Type",
                file_extension
            )

            if (
                uploaded_file.name
                .lower()
                .endswith(
                    ".xlsx"
                )
            ):

                try:

                    sheet_names = (
                        get_excel_sheet_names(
                            uploaded_file
                        )
                    )

                    st.subheader(
                        "Excel Sheets"
                    )

                    st.write(
                        f"Workbook contains "
                        f"**{len(sheet_names)}** sheet(s)."
                    )

                    selected_sheets = (
                        st.multiselect(
                            "Select the sheet(s) to ingest",
                            options=sheet_names,
                            default=(
                                sheet_names
                                if len(sheet_names) == 1
                                else []
                            ),
                            help=(
                                "For multi-sheet workbooks, select only the sheets that "
                                "belong to the same transaction structure. They will not "
                                "be combined until you explicitly approve the load."
                            )
                        )
                    )

                    st.session_state[
                        "selected_sheets"
                    ] = selected_sheets

                    if len(sheet_names) > 1:
                        if len(selected_sheets) > 1:
                            st.info(
                                f"{len(selected_sheets)} sheets selected. They will be "
                                "combined only after you approve the action below."
                            )
                        elif len(selected_sheets) == 1:
                            st.info(
                                "One sheet selected. Only that sheet will be loaded."
                            )
                        else:
                            st.warning(
                                "Select at least one sheet before continuing."
                            )

                except Exception as e:

                    st.error(
                        f"Unable to inspect Excel workbook: {e}"
                    )

            st.divider()

            is_excel_upload = uploaded_file.name.lower().endswith(".xlsx")
            if is_excel_upload and selected_sheets:
                load_label = (
                    "Combine Selected Sheets and Continue"
                    if len(selected_sheets) > 1
                    else "Load Sheet and Continue"
                )
            else:
                load_label = "Load Dataset"

            load_disabled = bool(
                is_excel_upload
                and not selected_sheets
            )

            if st.button(
                load_label,
                type="primary",
                disabled=load_disabled
            ):

                try:

                    with loading_overlay(
                        "Reading the selected source data and preparing the ingestion preview."
                    ):
                        raw_df = (
                            load_uploaded_data(
                                uploaded_file,
                                selected_sheets
                            )
                        )

                    st.session_state.raw_data = (
                        raw_df
                    )

                    st.session_state.uploaded_filename = (
                        uploaded_file.name
                    )

                    st.session_state.ingestion_complete = (
                        True
                    )

                    # Reset downstream stages
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

                    reset_publication_state()

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
                        )
                    )

                    st.success(
                        "Dataset loaded successfully."
                    )

                except Exception as e:

                    st.session_state.raw_data = None
                    st.session_state.ingestion_complete = False

                    st.session_state.validation_results = None
                    st.session_state.validation_complete = False

                    st.session_state.cleaned_data = None
                    st.session_state.cleaning_steps = None
                    st.session_state.cleaning_summary = None
                    st.session_state.cleaning_complete = False

                    st.session_state.rfm_data = None
                    st.session_state.rfm_summary = None
                    st.session_state.rfm_complete = False

                    reset_publication_state()

                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="Dataset load attempted",
                        stage="Dataset Ingestion",
                        status="FAILED",
                        source_file=(
                            uploaded_file.name
                            if uploaded_file is not None
                            else ""
                        ),
                        details=str(
                            e
                        )
                    )

                    st.error(
                        f"Dataset could not be loaded: {e}"
                    )

        if (
            st.session_state.ingestion_complete
            and
            st.session_state.raw_data
            is not None
        ):

            raw_df = (
                st.session_state.raw_data
            )

            st.divider()

            st.subheader(
                "Ingestion Summary"
            )

            col1, col2, col3 = (
                st.columns(
                    3
                )
            )

            col1.metric(
                "Rows Loaded",
                f"{len(raw_df):,}"
            )

            col2.metric(
                "Columns",
                len(
                    raw_df.columns
                )
            )

            col3.metric(
                "Source File",
                st.session_state.uploaded_filename
            )

            st.subheader(
                "Detected Columns"
            )

            column_info = pd.DataFrame({

                "Column":
                    raw_df.columns,

                "Data Type":
                    raw_df
                    .dtypes
                    .astype(
                        str
                    )
                    .values
            })

            st.dataframe(
                column_info,
                width="stretch",
                hide_index=True
            )

            st.subheader(
                "Raw Data Preview"
            )

            st.dataframe(
                raw_df.head(
                    20
                ),
                width="stretch"
            )

            render_proceed_button(
                "Proceed to Data Validation",
                "Data Validation",
                "proceed_ingestion_to_validation"
            )


    # ========================================================
    # DATA VALIDATION
    # ========================================================

    elif navigation == "Data Validation":

        st.header(
            "Data Validation"
        )

        st.write(
            "Assess the uploaded source data before cleaning "
            "or analytical transformation."
        )

        if (
            not st.session_state.ingestion_complete
            or
            st.session_state.raw_data
            is None
        ):

            st.warning(
                "Load a dataset in Dataset Ingestion first."
            )

        else:

            if st.button(
                "Run Data Validation",
                type="primary"
            ):

                try:

                    with loading_overlay(
                        "Checking schema, missing values, duplicates, cancellations and field validity."
                    ):
                        validation_results = (
                            validate_dataset(
                                st.session_state.raw_data
                            )
                        )

                    st.session_state.validation_score = (
                        calculate_data_quality_score(
                            validation_results
                        )
                    )

                    st.session_state.validation_results = (
                        validation_results
                    )

                    st.session_state.validation_complete = (
                        True
                    )

                    st.session_state.cleaned_data = None
                    st.session_state.cleaning_steps = None
                    st.session_state.cleaning_summary = None
                    st.session_state.cleaning_complete = False

                    st.session_state.rfm_data = None
                    st.session_state.rfm_summary = None
                    st.session_state.rfm_complete = False

                    reset_publication_state()

                    failed_checks = int(
                        validation_results[
                            "Status"
                        ]
                        .eq(
                            "FAIL"
                        )
                        .sum()
                    )

                    warning_checks = int(
                        validation_results[
                            "Status"
                        ]
                        .eq(
                            "WARNING"
                        )
                        .sum()
                    )

                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="Data validation completed",
                        stage="Data Validation",
                        status="SUCCESS",
                        source_file=(
                            st.session_state.uploaded_filename
                            or ""
                        ),
                        details=(
                            f"Validation completed with "
                            f"{failed_checks} failed checks and "
                            f"{warning_checks} warnings."
                        )
                    )

                    st.success(
                        "Data validation completed."
                    )

                except Exception as e:

                    st.session_state.validation_results = None
                    st.session_state.validation_complete = False

                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="Data validation attempted",
                        stage="Data Validation",
                        status="FAILED",
                        source_file=(
                            st.session_state.uploaded_filename
                            or ""
                        ),
                        details=str(
                            e
                        )
                    )

                    st.error(
                        f"Validation failed: {e}"
                    )

            if (
                st.session_state.validation_results
                is not None
            ):

                validation_results = (
                    st.session_state.validation_results
                )

                st.divider()

                st.subheader(
                    "Validation Results"
                )

                passed = int(
                    validation_results[
                        "Status"
                    ]
                    .eq(
                        "PASS"
                    )
                    .sum()
                )

                warnings = int(
                    validation_results[
                        "Status"
                    ]
                    .eq(
                        "WARNING"
                    )
                    .sum()
                )

                failed = int(
                    validation_results[
                        "Status"
                    ]
                    .eq(
                        "FAIL"
                    )
                    .sum()
                )

                quality_score = calculate_data_quality_score(
                    validation_results
                )

                col1, col2, col3, col4 = (
                    st.columns(
                        4
                    )
                )

                col1.metric(
                    "Data Quality Score",
                    f"{quality_score:.1f}%"
                )

                col2.metric(
                    "Passed",
                    passed
                )

                col3.metric(
                    "Warnings",
                    warnings
                )

                col4.metric(
                    "Failed",
                    failed
                )

                st.dataframe(
                    validation_results,
                    width="stretch",
                    hide_index=True
                )

                # Make geographic readiness visible without forcing the user to
                # inspect the full validation table. Unresolved labels are kept
                # as warnings so they can be corrected before Power BI mapping.
                country_validation = validation_results.loc[
                    validation_results["Check"].isin([
                        "Recognised Country Labels",
                        "Excluded Aggregate Country Labels",
                        "Unresolved Country Labels",
                    ])
                ].copy()

                if not country_validation.empty:
                    with st.expander("Country Mapping Status", expanded=True):
                        country_lookup = country_validation.set_index("Check")

                        recognised_count = int(
                            country_lookup.loc["Recognised Country Labels", "Count"]
                        ) if "Recognised Country Labels" in country_lookup.index else 0

                        excluded_count = int(
                            country_lookup.loc["Excluded Aggregate Country Labels", "Count"]
                        ) if "Excluded Aggregate Country Labels" in country_lookup.index else 0

                        unresolved_count = int(
                            country_lookup.loc["Unresolved Country Labels", "Count"]
                        ) if "Unresolved Country Labels" in country_lookup.index else 0

                        country_col1, country_col2, country_col3 = st.columns(3)
                        country_col1.metric("Recognised", recognised_count)
                        country_col2.metric("Excluded / Aggregate", excluded_count)
                        country_col3.metric("Unresolved", unresolved_count)

                        unresolved_row = country_validation.loc[
                            country_validation["Check"].eq("Unresolved Country Labels")
                        ]
                        if unresolved_count > 0 and not unresolved_row.empty:
                            st.warning(str(unresolved_row.iloc[0]["Details"]))
                        else:
                            st.success(
                                "All geography labels are ready for governed reporting or "
                                "explicitly excluded from country-level mapping."
                            )

                if failed > 0:

                    st.error(
                        "One or more critical validation checks failed."
                    )

                elif warnings > 0:

                    st.warning(
                        "Validation completed with warnings. "
                        "Review the findings before cleaning."
                    )

                else:

                    st.success(
                        "All validation checks passed."
                    )

                if st.session_state.validation_complete and failed == 0:
                    render_proceed_button(
                        "Proceed to Data Cleaning",
                        "Data Cleaning",
                        "proceed_validation_to_cleaning"
                    )


    # ========================================================
    # DATA CLEANING
    # ========================================================

    elif navigation == "Data Cleaning":

        st.header(
            "Data Cleaning"
        )

        st.write(
            "Apply the verified transaction preparation rules "
            "used by the customer-retention analysis."
        )

        if (
            not st.session_state.validation_complete
            or
            st.session_state.raw_data
            is None
        ):

            st.warning(
                "Complete Data Validation before cleaning."
            )

        else:

            validation_results = (
                st.session_state.validation_results
            )

            critical_failures = int(
                validation_results[
                    "Status"
                ]
                .eq(
                    "FAIL"
                )
                .sum()
            )

            if critical_failures > 0:

                st.error(
                    "Cleaning cannot continue while "
                    "critical validation failures remain."
                )

            else:

                if st.button(
                    "Run Data Cleaning",
                    type="primary"
                ):

                    try:

                        with loading_overlay(
                            "Standardising transactions, preserving cancellations and assigning analysis flags."
                        ):
                            (
                                cleaned_df,
                                cleaning_steps,
                                cleaning_summary

                            ) = clean_dataset(
                                st.session_state.raw_data
                            )

                        st.session_state.cleaned_data = (
                            cleaned_df
                        )

                        st.session_state.cleaning_steps = (
                            cleaning_steps
                        )

                        st.session_state.cleaning_summary = (
                            cleaning_summary
                        )

                        st.session_state.cleaning_complete = (
                            True
                        )

                        st.session_state.rfm_data = None
                        st.session_state.rfm_summary = None
                        st.session_state.rfm_complete = False

                        reset_publication_state()

                        log_audit_event(
                            username=user_name,
                            role=user_role,
                            action="Data cleaning completed",
                            stage="Data Cleaning",
                            status="SUCCESS",
                            source_file=(
                                st.session_state.uploaded_filename
                                or ""
                            ),
                            details=(
                                f"Cleaned dataset contains "
                                f"{len(cleaned_df):,} qualifying rows."
                            )
                        )

                        st.success(
                            "Data cleaning completed successfully."
                        )

                    except Exception as e:

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
                                st.session_state.uploaded_filename
                                or ""
                            ),
                            details=str(
                                e
                            )
                        )

                        st.error(
                            f"Cleaning failed: {e}"
                        )

            if (
                st.session_state.cleaning_complete
                and
                st.session_state.cleaned_data
                is not None
            ):

                cleaned_df = (
                    st.session_state.cleaned_data
                )

                summary = (
                    st.session_state.cleaning_summary
                )

                st.divider()

                st.subheader(
                    "Detailed Cleaning Report"
                )

                # Five cleaning KPIs are split across two rows so large retail
                # counts and longer labels remain fully visible on desktop.
                top1, top2, top3 = st.columns(3)

                top1.metric(
                    "Raw Rows",
                    f"{summary['starting_rows']:,}"
                )

                top2.metric(
                    "Duplicates Removed",
                    f"{summary['duplicates_removed']:,}"
                )

                top3.metric(
                    "Cancellations Preserved",
                    f"{summary['cancellation_rows']:,}"
                )

                bottom1, bottom2 = st.columns(2)

                bottom1.metric(
                    "Completed Sales",
                    f"{summary['completed_sales_rows']:,}"
                )

                bottom2.metric(
                    "Rows Retained",
                    f"{summary['retained_percentage']:.2f}%"
                )

                st.caption(
                    "Cancellations/returns remain in the clean transaction dataset. "
                    "Only rows flagged IsCompletedSale=True feed revenue, RFM, product, "
                    "market-basket and predictive analytical views."
                )

                st.dataframe(
                    st.session_state.cleaning_steps,
                    width="stretch",
                    hide_index=True
                )

                st.subheader(
                    "Post-Cleaning Quality Checks"
                )

                completed_sales = completed_sales_view(
                    cleaned_df
                )

                post_checks = pd.DataFrame({
                    "Check": [
                        "Exact Duplicates",
                        "Invalid Invoice Dates",
                        "Invalid Quantity Values",
                        "Invalid Price Values",
                        "Completed-Sale Rows",
                        "Preserved Cancellation / Return Rows",
                        "Missing Customer IDs"
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
                        "Retained for transaction analysis but excluded from customer RFM",
                    ]
                })

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
                    post_checks,
                    width="stretch",
                    hide_index=True
                )

                st.subheader(
                    "Cleaned Transaction Preview"
                )

                st.dataframe(
                    cleaned_df.head(20),
                    width="stretch"
                )

                render_proceed_button(
                    "Proceed to RFM Feature Engineering",
                    "RFM Feature Engineering",
                    "proceed_cleaning_to_rfm"
                )


    # ========================================================
    # RFM FEATURE ENGINEERING
    # ========================================================

    elif navigation == "RFM Feature Engineering":

        st.header(
            "RFM Feature Engineering"
        )

        st.write(
            "Create customer-level Recency, Frequency and Monetary "
            "features, RFM segments and the operational "
            "60-day inactivity indicator."
        )

        if (
            not st.session_state.cleaning_complete
            or
            st.session_state.cleaned_data
            is None
        ):

            st.warning(
                "Complete Data Cleaning before generating RFM features."
            )

        else:

            if st.button(
                "Generate RFM Features",
                type="primary"
            ):

                try:

                    with loading_overlay(
                        "Building RFM customer features from completed sales only."
                    ):
                        (
                            rfm_df,
                            rfm_summary

                        ) = build_rfm_features(
                            st.session_state.cleaned_data
                        )

                    st.session_state.rfm_data = (
                        rfm_df
                    )

                    st.session_state.rfm_summary = (
                        rfm_summary
                    )

                    st.session_state.rfm_complete = (
                        True
                    )

                    reset_publication_state()

                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="RFM features generated",
                        stage="RFM Feature Engineering",
                        status="SUCCESS",
                        source_file=(
                            st.session_state.uploaded_filename
                            or ""
                        ),
                        details=(
                            f"Generated RFM features for "
                            f"{len(rfm_df):,} customers."
                        )
                    )

                    st.success(
                        "RFM feature engineering completed."
                    )

                except Exception as e:

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
                            st.session_state.uploaded_filename
                            or ""
                        ),
                        details=str(
                            e
                        )
                    )

                    st.error(
                        f"RFM feature engineering failed: {e}"
                    )

            if (
                st.session_state.rfm_complete
                and
                st.session_state.rfm_data
                is not None
            ):

                rfm_df = (
                    st.session_state.rfm_data
                )

                summary = (
                    st.session_state.rfm_summary
                )

                st.divider()

                st.subheader(
                    "RFM Summary"
                )

                col1, col2, col3, col4 = (
                    st.columns(
                        4
                    )
                )

                col1.metric(
                    "Customers",
                    f"{summary['customers']:,}"
                )

                col2.metric(
                    "Purchase Events",
                    f"{summary['purchase_events']:,}"
                )

                col3.metric(
                    "At Risk",
                    f"{summary['at_risk_customers']:,}"
                )

                col4.metric(
                    "Active",
                    f"{summary['active_customers']:,}"
                )

                st.caption(
                    "Operational risk is defined as Recency >= 60 days. "
                    "This represents inactivity and is not confirmed churn."
                )

                st.subheader(
                    "RFM Descriptive Statistics"
                )

                descriptive_df = pd.DataFrame({

                    "Measure": [
                        "Mean Recency",
                        "Median Recency",
                        "Mean Frequency",
                        "Median Frequency",
                        "Mean Monetary",
                        "Median Monetary"
                    ],

                    "Value": [
                        f"{summary['mean_recency']:.2f}",
                        f"{summary['median_recency']:.2f}",
                        f"{summary['mean_frequency']:.2f}",
                        f"{summary['median_frequency']:.2f}",
                        f"{summary['mean_monetary']:.2f}",
                        f"{summary['median_monetary']:.2f}"
                    ]
                })

                st.dataframe(
                    descriptive_df,
                    width="stretch",
                    hide_index=True
                )

                st.subheader(
                    "RFM Segment Distribution"
                )

                st.dataframe(
                    summary[
                        "segment_counts"
                    ],
                    width="stretch",
                    hide_index=True
                )

                st.subheader(
                    "Operational Risk Distribution"
                )

                st.dataframe(
                    summary[
                        "risk_counts"
                    ],
                    width="stretch",
                    hide_index=True
                )

                st.subheader(
                    "RFM Data Preview"
                )

                st.dataframe(
                    rfm_df.head(
                        20
                    ),
                    width="stretch"
                )

                render_proceed_button(
                    "Proceed to Version & Publish",
                    "Version & Publish",
                    "proceed_rfm_to_publish"
                )


    # ========================================================
    # VERSION & PUBLISH
    # ========================================================

    elif navigation == "Version & Publish":

        st.header(
            "Version & Publish"
        )

        st.write(
            "Publish approved customer-retention outputs "
            "to governed reporting locations."
        )

        if (
            not st.session_state.rfm_complete
            or
            st.session_state.rfm_data
            is None
            or
            st.session_state.cleaned_data
            is None
        ):

            st.warning(
                "Complete the pipeline through "
                "RFM Feature Engineering before publishing."
            )

        else:

            rfm_df = (
                st.session_state.rfm_data
            )

            duplicate_customers = int(
                rfm_df[
                    "Customer ID"
                ]
                .duplicated()
                .sum()
            )

            missing_rfm = int(
                rfm_df[
                    [
                        "Recency",
                        "Frequency",
                        "Monetary"
                    ]
                ]
                .isna()
                .sum()
                .sum()
            )

            readiness_df = pd.DataFrame({

                "Check": [
                    "Cleaning Complete",
                    "RFM Complete",
                    "Duplicate Customer IDs",
                    "Missing RFM Values",
                    "Model CV Artifact",
                    "Temporal Prediction Artifact"
                ],

                "Status": [
                    "PASS",
                    "PASS",

                    (
                        "PASS"
                        if duplicate_customers == 0
                        else "FAIL"
                    ),

                    (
                        "PASS"
                        if missing_rfm == 0
                        else "FAIL"
                    ),

                    (
                        "PASS"
                        if (
                            MODEL_ARTIFACT_DIR
                            /
                            "model_cv_results.csv"
                        ).exists()
                        else "FAIL"
                    ),

                    (
                        "PASS"
                        if (
                            MODEL_ARTIFACT_DIR
                            /
                            "temporal_test_predictions.csv"
                        ).exists()
                        else "FAIL"
                    )
                ]
            })

            st.subheader(
                "Publication Readiness"
            )

            st.dataframe(
                readiness_df,
                width="stretch",
                hide_index=True
            )

            ready = bool(
                readiness_df[
                    "Status"
                ]
                .eq(
                    "PASS"
                )
                .all()
            )

            if ready:

                if st.button(
                    "Publish Approved Outputs",
                    type="primary"
                ):

                    try:

                        with loading_overlay(
                            "Writing the governed team outputs and Power BI hand-off datasets."
                        ):
                            (
                                published_rfm,
                                publication_summary

                            ) = publish_pipeline_outputs(

                                cleaned_df=(
                                    st.session_state.cleaned_data
                                ),

                                rfm_df=(
                                    st.session_state.rfm_data
                                ),

                                source_filename=(
                                    st.session_state.uploaded_filename
                                    or "Unknown"
                                ),

                                username=(
                                    user_name
                                ),

                                validation_results=(
                                    st.session_state.validation_results
                                ),

                                cleaning_steps=(
                                    st.session_state.cleaning_steps
                                )
                            )

                        st.session_state.published_rfm_data = (
                            published_rfm
                        )

                        st.session_state.publication_summary = (
                            publication_summary
                        )

                        st.session_state.published_at = (
                            publication_summary[
                                "publication_time"
                            ]
                        )

                        st.session_state.publication_complete = (
                            True
                        )

                        log_audit_event(
                            username=user_name,
                            role=user_role,
                            action="Approved outputs published",
                            stage="Version & Publish",
                            status="SUCCESS",
                            source_file=(
                                st.session_state.uploaded_filename
                                or ""
                            ),
                            publication_version=(
                                publication_summary[
                                    "publication_version"
                                ]
                            ),
                            details=(
                                f"Published "
                                f"{publication_summary['rfm_rows']:,} customers; "
                                f"high-value at risk="
                                f"{publication_summary['high_value_at_risk']:,}."
                            )
                        )

                        st.success(
                            "Approved outputs published successfully."
                        )

                    except Exception as e:

                        st.session_state.publication_complete = False

                        log_audit_event(
                            username=user_name,
                            role=user_role,
                            action="Publication attempted",
                            stage="Version & Publish",
                            status="FAILED",
                            source_file=(
                                st.session_state.uploaded_filename
                                or ""
                            ),
                            details=str(
                                e
                            )
                        )

                        st.error(
                            f"Publication failed: {e}"
                        )

            else:

                st.error(
                    "Publication readiness checks failed. "
                    "Resolve the reported issue before publishing."
                )

            if (
                st.session_state.publication_complete
                and
                st.session_state.publication_summary
                is not None
                and
                st.session_state.published_rfm_data
                is not None
            ):

                summary = (
                    st.session_state.publication_summary
                )

                published_rfm = (
                    st.session_state.published_rfm_data
                )

                st.divider()

                st.subheader(
                    "Latest Publication"
                )

                # Publication metadata uses a 2x2 layout so long version/user
                # values remain readable instead of being truncated.
                top1, top2 = st.columns(2)

                top1.metric(
                    "Publication Version",
                    summary[
                        "publication_version"
                    ]
                )

                top2.metric(
                    "Published Customers",
                    f"{summary['rfm_rows']:,}"
                )

                bottom1, bottom2 = st.columns(2)

                bottom1.metric(
                    "High-Value At Risk",
                    f"{summary['high_value_at_risk']:,}"
                )

                bottom2.metric(
                    "Published By",
                    summary[
                        "published_by"
                    ]
                )

                st.caption(
                    f"Data period: {format_business_date(summary.get('data_start_date'))} "
                    f"to {format_business_date(summary.get('data_through_date'))} | "
                    f"Published: {summary['publication_time']} | "
                    f"Source: {summary['source_filename']}"
                )

                st.subheader(
                    "Published Priority Distribution"
                )

                st.dataframe(
                    summary[
                        "priority_counts"
                    ],
                    width="stretch",
                    hide_index=True
                )

                st.subheader(
                    "Published Files"
                )

                published_files = pd.DataFrame({
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
                        Path(summary["team_paths"][key]).name
                        for key in [
                            "clean_transactions",
                            "customer_rfm",
                            "customer_summary",
                            "data_validation_report",
                            "final_customer_risk_prediction",
                            "invoice_summary",
                            "rfm_customer_features",
                        ]
                    ]
                })

                st.dataframe(
                    published_files,
                    width="stretch",
                    hide_index=True
                )

                st.subheader(
                    "Published RFM Preview"
                )

                st.dataframe(
                    published_rfm.head(
                        20
                    ),
                    width="stretch"
                )

                csv_data = (
                    published_rfm
                    .to_csv(
                        index=False
                    )
                    .encode(
                        "utf-8"
                    )
                )

                st.download_button(
                    label="Download Latest RFM Reporting Dataset",
                    data=csv_data,
                    file_name="latest_rfm_analysis_dataset.csv",
                    mime="text/csv"
                )

                st.subheader(
                    "Predictive Evaluation Handoff"
                )

                p1, p2, p3 = (
                    st.columns(
                        3
                    )
                )

                p1.metric(
                    "Temporal Test Customers",
                    f"{summary['temporal_rows']:,}"
                )

                p2.metric(
                    "Predicted At Risk",
                    f"{summary['predicted_at_risk']:,}"
                )

                p3.metric(
                    "Predicted Retained",
                    f"{summary['predicted_retained']:,}"
                )

                st.dataframe(
                    summary[
                        "predicted_counts"
                    ],
                    width="stretch",
                    hide_index=True
                )

                st.success(
                    "Power BI hand-off is ready. "
                    "Use the governed outputs in outputs/published/power_bi/. "
                    "Predictive labels are governed as "
                    "1 = At Risk and 0 = Retained."
                )

                render_proceed_button(
                    "Proceed to Audit Trail",
                    "Audit Trail",
                    "proceed_publish_to_audit"
                )


    # ========================================================
    # AUDIT TRAIL
    # ========================================================

    elif navigation == "Audit Trail":

        st.header(
            "Audit Trail"
        )

        st.write(
            "Review the persistent record of technical pipeline "
            "and account-administration activity."
        )

        audit_df = (
            load_audit_trail()
        )

        if audit_df.empty:

            st.info(
                "No audit events have been recorded yet."
            )

        else:

            successful_events = int(
                audit_df[
                    "Status"
                ]
                .eq(
                    "SUCCESS"
                )
                .sum()
            )

            failed_events = int(
                audit_df[
                    "Status"
                ]
                .eq(
                    "FAILED"
                )
                .sum()
            )

            latest_timestamp = (
                audit_df.iloc[
                    0
                ][
                    "Timestamp"
                ]
            )

            col1, col2, col3, col4 = (
                st.columns(
                    4
                )
            )

            col1.metric(
                "Recorded Events",
                f"{len(audit_df):,}"
            )

            col2.metric(
                "Successful",
                f"{successful_events:,}"
            )

            col3.metric(
                "Failed",
                f"{failed_events:,}"
            )

            col4.metric(
                "Latest Event",
                latest_timestamp
            )

            st.divider()

            st.subheader(
                "Filter Audit Events"
            )

            filter_col1, filter_col2, filter_col3 = (
                st.columns(
                    3
                )
            )

            stage_options = [
                "All"
            ] + sorted(
                audit_df[
                    "Stage"
                ]
                .dropna()
                .unique()
                .tolist()
            )

            status_options = [
                "All"
            ] + sorted(
                audit_df[
                    "Status"
                ]
                .dropna()
                .unique()
                .tolist()
            )

            user_options = [
                "All"
            ] + sorted(
                audit_df[
                    "User"
                ]
                .dropna()
                .unique()
                .tolist()
            )

            selected_stage = (
                filter_col1.selectbox(
                    "Stage",
                    stage_options
                )
            )

            selected_status = (
                filter_col2.selectbox(
                    "Status",
                    status_options
                )
            )

            selected_user = (
                filter_col3.selectbox(
                    "User",
                    user_options
                )
            )

            filtered_audit = (
                audit_df.copy()
            )

            if selected_stage != "All":

                filtered_audit = (
                    filtered_audit[
                        filtered_audit[
                            "Stage"
                        ]
                        == selected_stage
                    ]
                )

            if selected_status != "All":

                filtered_audit = (
                    filtered_audit[
                        filtered_audit[
                            "Status"
                        ]
                        == selected_status
                    ]
                )

            if selected_user != "All":

                filtered_audit = (
                    filtered_audit[
                        filtered_audit[
                            "User"
                        ]
                        == selected_user
                    ]
                )

            st.caption(
                f"Showing {len(filtered_audit):,} "
                f"of {len(audit_df):,} recorded events."
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
                "Details"
            ]

            st.dataframe(
                filtered_audit[
                    display_columns
                ],
                width="stretch",
                hide_index=True
            )

            audit_csv = (
                audit_df
                .to_csv(
                    index=False
                )
                .encode(
                    "utf-8"
                )
            )

            st.download_button(
                label="Download Audit Trail",
                data=audit_csv,
                file_name="audit_trail.csv",
                mime="text/csv"
            )

            st.caption(
                "Persistent audit file: "
                "outputs/audit/audit_trail.csv"
            )


    # ========================================================
    # USER MANAGEMENT
    # ========================================================

    elif navigation == "User Management":

        st.header(
            "User Management"
        )

        st.write(
            "Manage authorised application users "
            "and role-based system access."
        )

        st.caption(
            "This administration area is restricted "
            "to authorised Technical users."
        )

        users_df = (
            load_users_dataframe()
        )

        total_users = (
            len(
                users_df
            )
        )

        active_users = int(
            users_df[
                "Status"
            ]
            .eq(
                "Active"
            )
            .sum()
        )

        active_technical = int(
            (
                users_df[
                    "Role"
                ]
                .eq(
                    "Technical"
                )
                &
                users_df[
                    "Status"
                ]
                .eq(
                    "Active"
                )
            )
            .sum()
        )

        business_users = int(
            users_df[
                "Role"
            ]
            .eq(
                "Business"
            )
            .sum()
        )

        col1, col2, col3, col4 = (
            st.columns(
                4
            )
        )

        col1.metric(
            "Registered Users",
            total_users
        )

        col2.metric(
            "Active Users",
            active_users
        )

        col3.metric(
            "Active Technical",
            active_technical
        )

        col4.metric(
            "Business Users",
            business_users
        )

        st.divider()

        (
            users_tab,
            add_tab,
            edit_tab,
            status_tab,
            password_tab,
            remove_tab

        ) = st.tabs(
            [
                "Users",
                "Add User",
                "Edit User / Role",
                "Activate / Deactivate",
                "Reset Password",
                "Remove User"
            ]
        )


        # ----------------------------------------------------
        # USERS
        # ----------------------------------------------------

        with users_tab:

            st.subheader(
                "Registered Users"
            )

            st.dataframe(
                users_df,
                width="stretch",
                hide_index=True
            )

            st.info(
                "Deactivation is preferred to permanent removal "
                "because it preserves historical accountability."
            )


        # ----------------------------------------------------
        # ADD USER
        # ----------------------------------------------------

        with add_tab:

            st.subheader(
                "Add User"
            )

            with st.form(
                "add_user_form",
                clear_on_submit=True
            ):

                left, right = (
                    st.columns(
                        2
                    )
                )

                new_username = (
                    left.text_input(
                        "Username",
                        help=(
                            "Use lowercase letters, numbers, "
                            "dots, underscores or hyphens."
                        )
                    )
                )

                new_name = (
                    right.text_input(
                        "Full Name"
                    )
                )

                new_email = (
                    left.text_input(
                        "Email"
                    )
                )

                new_role = (
                    right.selectbox(
                        "Role",
                        [
                            "Business",
                            "Technical"
                        ]
                    )
                )

                new_password = (
                    left.text_input(
                        "Password",
                        type="password"
                    )
                )

                new_password_confirmation = (
                    right.text_input(
                        "Confirm Password",
                        type="password"
                    )
                )

                create_user_clicked = (
                    st.form_submit_button(
                        "Create User",
                        type="primary"
                    )
                )

            if create_user_clicked:

                try:

                    create_application_user(

                        username=(
                            new_username
                        ),

                        name=(
                            new_name
                        ),

                        email=(
                            new_email
                        ),

                        password=(
                            new_password
                        ),

                        confirmation=(
                            new_password_confirmation
                        ),

                        role=(
                            new_role.lower()
                        ),

                        performed_by=(
                            user_name
                        )
                    )

                    created_username = (
                        normalise_username(
                            new_username
                        )
                    )

                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="User created",
                        stage="User Management",
                        status="SUCCESS",
                        details=(
                            f"Created user "
                            f"'{created_username}' "
                            f"with role "
                            f"'{new_role.lower()}'."
                        )
                    )

                    st.success(
                        f"User '{created_username}' "
                        f"created successfully."
                    )

                    st.rerun()

                except Exception as e:

                    log_audit_event(
                        username=user_name,
                        role=user_role,
                        action="User creation attempted",
                        stage="User Management",
                        status="FAILED",
                        details=str(
                            e
                        )
                    )

                    st.error(
                        f"User could not be created: {e}"
                    )


        # ----------------------------------------------------
        # EDIT USER / ROLE
        # ----------------------------------------------------

        with edit_tab:

            st.subheader(
                "Edit User / Role"
            )

            editable_users = (
                load_users_dataframe()[
                    "Username"
                ]
                .tolist()
            )

            if len(
                editable_users
            ) == 0:

                st.info(
                    "No users are available."
                )

            else:

                edit_username = (
                    st.selectbox(
                        "Select User",
                        editable_users,
                        key="edit_user_selection"
                    )
                )

                edit_record = (
                    get_user_record(
                        edit_username
                    )
                )

                role_options = [
                    "Business",
                    "Technical"
                ]

                current_role_label = (
                    edit_record[
                        "role"
                    ]
                    .title()
                )

                role_index = (
                    role_options.index(
                        current_role_label
                    )
                )

                with st.form(
                    "edit_user_form"
                ):

                    left, right = (
                        st.columns(
                            2
                        )
                    )

                    edit_name = (
                        left.text_input(
                            "Full Name",
                            value=(
                                edit_record[
                                    "name"
                                ]
                            )
                        )
                    )

                    edit_email = (
                        right.text_input(
                            "Email",
                            value=(
                                edit_record[
                                    "email"
                                ]
                                or ""
                            )
                        )
                    )

                    edit_role = (
                        st.selectbox(
                            "Role",
                            role_options,
                            index=role_index
                        )
                    )

                    update_clicked = (
                        st.form_submit_button(
                            "Save Changes",
                            type="primary"
                        )
                    )

                if update_clicked:

                    try:

                        old_role = (
                            edit_record[
                                "role"
                            ]
                        )

                        new_role = (
                            edit_role.lower()
                        )

                        update_application_user(

                            username=(
                                edit_username
                            ),

                            name=(
                                edit_name
                            ),

                            email=(
                                edit_email
                            ),

                            role=(
                                new_role
                            ),

                            performed_by=(
                                user_name
                            )
                        )

                        log_audit_event(
                            username=user_name,
                            role=user_role,
                            action="User updated",
                            stage="User Management",
                            status="SUCCESS",
                            details=(
                                f"Updated user "
                                f"'{edit_username}'. "
                                f"Role: {old_role} -> {new_role}."
                            )
                        )

                        st.success(
                            f"User '{edit_username}' "
                            f"updated successfully."
                        )

                        st.rerun()

                    except Exception as e:

                        log_audit_event(
                            username=user_name,
                            role=user_role,
                            action="User update attempted",
                            stage="User Management",
                            status="FAILED",
                            details=str(
                                e
                            )
                        )

                        st.error(
                            f"User could not be updated: {e}"
                        )


        # ----------------------------------------------------
        # ACTIVATE / DEACTIVATE
        # ----------------------------------------------------

        with status_tab:

            st.subheader(
                "Activate / Deactivate User"
            )

            status_users = (
                load_users_dataframe()[
                    "Username"
                ]
                .tolist()
            )

            if len(
                status_users
            ) == 0:

                st.info(
                    "No users are available."
                )

            else:

                status_username = (
                    st.selectbox(
                        "Select User",
                        status_users,
                        key="status_user_selection"
                    )
                )

                status_record = (
                    get_user_record(
                        status_username
                    )
                )

                is_active = bool(
                    status_record[
                        "is_active"
                    ]
                )

                current_status = (
                    "Active"
                    if is_active
                    else "Inactive"
                )

                st.write(
                    f"Current status: "
                    f"**{current_status}**"
                )

                if is_active:

                    st.warning(
                        "Deactivation blocks future login "
                        "without deleting historical identity."
                    )

                    if st.button(
                        "Deactivate User",
                        type="primary",
                        key="deactivate_user_button"
                    ):

                        try:

                            set_application_user_status(

                                username=(
                                    status_username
                                ),

                                active=False,

                                performed_by=(
                                    user_name
                                ),

                                current_username=(
                                    current_user
                                )
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
                                )
                            )

                            st.success(
                                f"User '{status_username}' "
                                f"deactivated."
                            )

                            st.rerun()

                        except Exception as e:

                            log_audit_event(
                                username=user_name,
                                role=user_role,
                                action="User deactivation attempted",
                                stage="User Management",
                                status="FAILED",
                                details=str(
                                    e
                                )
                            )

                            st.error(
                                str(
                                    e
                                )
                            )

                else:

                    if st.button(
                        "Reactivate User",
                        type="primary",
                        key="reactivate_user_button"
                    ):

                        try:

                            set_application_user_status(

                                username=(
                                    status_username
                                ),

                                active=True,

                                performed_by=(
                                    user_name
                                ),

                                current_username=(
                                    current_user
                                )
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
                                )
                            )

                            st.success(
                                f"User '{status_username}' "
                                f"reactivated."
                            )

                            st.rerun()

                        except Exception as e:

                            log_audit_event(
                                username=user_name,
                                role=user_role,
                                action="User reactivation attempted",
                                stage="User Management",
                                status="FAILED",
                                details=str(
                                    e
                                )
                            )

                            st.error(
                                str(
                                    e
                                )
                            )


        # ----------------------------------------------------
        # RESET PASSWORD
        # ----------------------------------------------------

        with password_tab:

            st.subheader(
                "Reset User Password"
            )

            password_users = (
                load_users_dataframe()[
                    "Username"
                ]
                .tolist()
            )

            if len(
                password_users
            ) == 0:

                st.info(
                    "No users are available."
                )

            else:

                password_username = (
                    st.selectbox(
                        "Select User",
                        password_users,
                        key="password_user_selection"
                    )
                )

                with st.form(
                    "reset_password_form",
                    clear_on_submit=True
                ):

                    left, right = (
                        st.columns(
                            2
                        )
                    )

                    password_value = (
                        left.text_input(
                            "New Password",
                            type="password"
                        )
                    )

                    password_confirmation = (
                        right.text_input(
                            "Confirm New Password",
                            type="password"
                        )
                    )

                    password_clicked = (
                        st.form_submit_button(
                            "Reset Password",
                            type="primary"
                        )
                    )

                if password_clicked:

                    try:

                        reset_application_user_password(

                            username=(
                                password_username
                            ),

                            password=(
                                password_value
                            ),

                            confirmation=(
                                password_confirmation
                            ),

                            performed_by=(
                                user_name
                            )
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
                            )
                        )

                        st.success(
                            f"Password reset successfully "
                            f"for '{password_username}'."
                        )

                    except Exception as e:

                        log_audit_event(
                            username=user_name,
                            role=user_role,
                            action="Password reset attempted",
                            stage="User Management",
                            status="FAILED",
                            details=str(
                                e
                            )
                        )

                        st.error(
                            str(
                                e
                            )
                        )


        # ----------------------------------------------------
        # REMOVE USER
        # ----------------------------------------------------

        with remove_tab:

            st.subheader(
                "Remove User"
            )

            st.warning(
                "Permanent removal deletes the account record. "
                "Deactivation is preferred when historical "
                "traceability should be retained."
            )

            removable_users = (
                load_users_dataframe()[
                    "Username"
                ]
                .tolist()
            )

            if len(
                removable_users
            ) == 0:

                st.info(
                    "No users are available."
                )

            else:

                remove_username = (
                    st.selectbox(
                        "Select User",
                        removable_users,
                        key="remove_user_selection"
                    )
                )

                confirm_remove = (
                    st.checkbox(
                        (
                            f"I understand that "
                            f"'{remove_username}' will be "
                            f"permanently removed."
                        ),
                        key="confirm_remove_user"
                    )
                )

                if st.button(
                    "Remove User Permanently",
                    disabled=(
                        not confirm_remove
                    ),
                    key="remove_user_button"
                ):

                    try:

                        remove_record = (
                            get_user_record(
                                remove_username
                            )
                        )

                        removed_role = (
                            remove_record[
                                "role"
                            ]
                        )

                        remove_application_user(

                            username=(
                                remove_username
                            ),

                            current_username=(
                                current_user
                            )
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
                            )
                        )

                        st.success(
                            f"User '{remove_username}' "
                            f"permanently removed."
                        )

                        st.rerun()

                    except Exception as e:

                        log_audit_event(
                            username=user_name,
                            role=user_role,
                            action="User removal attempted",
                            stage="User Management",
                            status="FAILED",
                            details=str(
                                e
                            )
                        )

                        st.error(
                            str(
                                e
                            )
                        )


# ============================================================
# BUSINESS WORKSPACE
# ============================================================

else:

    # --------------------------------------------------------
    # LOAD LATEST APPROVED PUBLICATION
    # --------------------------------------------------------

    manifest_path = (
        PUBLISH_DIR
        /
        "publication_manifest.csv"
    )

    latest_rfm_path = (
        PUBLISH_DIR
        /
        "latest_rfm_analysis_dataset.csv"
    )

    latest_clean_path = (
        PUBLISH_DIR
        /
        "latest_clean_transactions.csv"
    )

    team_customer_summary_path = TEAM_OUTPUT_DIR / "customer_summary.csv"
    team_clean_transactions_path = TEAM_OUTPUT_DIR / "clean_transactions.csv"
    team_invoice_summary_path = TEAM_OUTPUT_DIR / "invoice_summary.csv"

    latest_publication = None
    business_rfm_df = None
    business_customer_summary_df = None
    business_transactions_df = None
    business_invoice_df = None

    if manifest_path.exists():

        try:

            business_manifest = pd.read_csv(
                manifest_path
            )

            if not business_manifest.empty:

                latest_publication = (
                    business_manifest
                    .iloc[
                        -1
                    ]
                    .to_dict()
                )

        except Exception:

            latest_publication = None

    if latest_rfm_path.exists():
        try:
            business_rfm_df = safe_read_published_csv(
                latest_rfm_path
            )
        except Exception:
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
    except Exception:
        # Quick Analytics is optional; the governed Power BI access and pipeline
        # status remain available even if an auxiliary business file cannot load.
        business_customer_summary_df = None
        business_transactions_df = None
        business_invoice_df = None

    publication_available = (

        latest_publication
        is not None

        and

        business_rfm_df
        is not None

        and

        not business_rfm_df.empty
    )

    # Power BI URL comes from Streamlit Secrets.
    power_bi_url = (
        POWER_BI_URL
    )


    # ========================================================
    # PIPELINE STATUS
    # ========================================================

    if navigation == "Pipeline Status":

        st.header(
            "Pipeline Status"
        )

        st.write(
            "Business users have read-only access "
            "to the latest approved customer-retention "
            "publication and reporting status."
        )

        if not publication_available:

            st.warning(
                "No approved publication is currently available. "
                "A Technical user must complete the controlled "
                "pipeline and publish the approved outputs first."
            )

        else:

            publication_version = str(
                latest_publication.get(
                    "PublicationVersion",
                    "Unavailable"
                )
            )

            publication_time = str(
                latest_publication.get(
                    "PublicationTimestamp",
                    "Unavailable"
                )
            )

            source_file = str(
                latest_publication.get(
                    "SourceFile",
                    "Unavailable"
                )
            )

            published_by = str(
                latest_publication.get(
                    "PublishedBy",
                    "Unavailable"
                )
            )

            high_value_at_risk = int(
                latest_publication.get(
                    "HighValueAtRisk",
                    0
                )
            )

            customer_rows = int(
                latest_publication.get(
                    "RFMRows",
                    len(
                        business_rfm_df
                    )
                )
            )

            col1, col2, col3, col4 = (
                st.columns(
                    4
                )
            )

            col1.metric(
                "Latest Publication",
                publication_version
            )

            col2.metric(
                "Published Customers",
                f"{customer_rows:,}"
            )

            col3.metric(
                "High-Value At Risk",
                f"{high_value_at_risk:,}"
            )

            col4.metric(
                "Power BI Handoff",
                "Ready"
            )

            data_start, data_through = resolve_publication_data_period(
                latest_publication,
                business_transactions_df
            )

            st.caption(
                f"Data period: {format_business_date(data_start)} "
                f"to {format_business_date(data_through)} | "
                f"Published: {publication_time} | "
                f"Source: {source_file} | Published by: {published_by}"
            )

            st.divider()

            st.subheader(
                "Approved Pipeline Status"
            )

            pipeline_status_df = pd.DataFrame({

                "Stage": [
                    "Dataset Ingestion",
                    "Data Validation",
                    "Data Cleaning",
                    "RFM Feature Engineering",
                    "Version & Publish",
                    "Power BI Handoff"
                ],

                "Status": [
                    "Completed",
                    "Completed",
                    "Completed",
                    "Completed",
                    "Published",
                    "Ready"
                ],

                "Business Access": [
                    "Read Only",
                    "Read Only",
                    "Read Only",
                    "Read Only",
                    "Read Only",
                    "Read Only"
                ]
            })

            st.dataframe(
                pipeline_status_df,
                width="stretch",
                hide_index=True
            )

            st.subheader(
                "Reporting Files"
            )

            team_reporting_paths = {
                "Clean Transactions": TEAM_OUTPUT_DIR / "clean_transactions.csv",
                "Customer RFM": TEAM_OUTPUT_DIR / "customer_rfm.csv",
                "Customer Summary": TEAM_OUTPUT_DIR / "customer_summary.csv",
                "Data Validation Report": TEAM_OUTPUT_DIR / "data_validation_report.csv",
                "Final Customer Risk Prediction": TEAM_OUTPUT_DIR / "final_customer_risk_prediction.csv",
                "Invoice Summary": TEAM_OUTPUT_DIR / "invoice_summary.csv",
                "RFM Customer Features": TEAM_OUTPUT_DIR / "rfm_customer_features.csv",
            }

            reporting_files_df = pd.DataFrame({
                "Output": list(team_reporting_paths.keys()),
                "Status": [
                    "Available" if path.exists() else "Unavailable"
                    for path in team_reporting_paths.values()
                ],
                "Purpose": [
                    "Governed transaction source including flagged cancellations",
                    "Approved RFM scoring and segmentation",
                    "Business-facing Customer 360 master",
                    "Validation and cleaning audit evidence",
                    "Approved predictive risk output",
                    "One row per invoice/order",
                    "Reusable RFM and behavioural customer features",
                ]
            })

            st.dataframe(
                reporting_files_df,
                width="stretch",
                hide_index=True
            )

            st.success(
                "The latest approved reporting dataset is available. "
                "Business access is read-only and technical processing "
                "functions remain restricted to authorised Technical users."
            )


    # ---QUICK ANALYTICS

    elif navigation == "Quick Analytics":

        st.header("Quick Analytics")
        st.write(
            "A lightweight business snapshot from the same approved publication "
            "used by Power BI. The full executive reporting experience remains in Power BI."
        )

        if not publication_available:
            st.warning(
                "No approved publication is currently available. A Technical user must "
                "publish the governed outputs first."
            )

        elif business_transactions_df is None or business_transactions_df.empty:
            st.warning(
                "The Quick Analytics transaction output is not available yet. "
                "Republish the latest pipeline once to create the seven team datasets."
            )

        else:
            sales = completed_sales_view(business_transactions_df)

            if sales.empty:
                st.warning("No completed-sale rows are available for Quick Analytics.")
            else:
                sales["Revenue"] = pd.to_numeric(
                    sales["Revenue"],
                    errors="coerce"
                ).fillna(0)

                # Re-apply country standardisation when reading an older approved
                # publication so the Quick Analytics labels remain consistent even
                # before the next technical republish.
                if "Country" in sales.columns:
                    sales["Country"] = standardise_country_names(
                        sales["Country"]
                    )

                data_start, data_through = resolve_publication_data_period(
                    latest_publication,
                    business_transactions_df
                )
                quick_publication_time = str(
                    latest_publication.get("PublicationTimestamp", "Unavailable")
                )
                quick_source_file = str(
                    latest_publication.get("SourceFile", "Unavailable")
                )
                st.caption(
                    f"Data period: {format_business_date(data_start)} "
                    f"to {format_business_date(data_through)} | "
                    f"Published: {quick_publication_time} | "
                    f"Source: {quick_source_file}"
                )

                overview_tab, product_tab, geo_tab = st.tabs([
                    "Overview",
                    "Products & Basket",
                    "Geography",
                ])


                # ---OVERVIEW

                with overview_tab:
                    total_revenue = float(sales["Revenue"].sum())
                    identifiable = sales.dropna(subset=["Customer ID"]).copy()
                    total_customers = int(identifiable["Customer ID"].nunique())

                    invoice_count = int(sales["Invoice"].nunique())
                    average_order_value = (
                        total_revenue / invoice_count
                        if invoice_count > 0
                        else 0.0
                    )

                    top_customer_text = "Unavailable"
                    top_customer_value = 0.0
                    if not identifiable.empty:
                        customer_value = (
                            identifiable.groupby("Customer ID")["Revenue"]
                            .sum()
                            .sort_values(ascending=False)
                        )
                        if not customer_value.empty:
                            top_customer_id = customer_value.index[0]
                            top_customer_text = str(int(float(top_customer_id)))
                            top_customer_value = float(customer_value.iloc[0])

                    country_revenue = (
                        sales.groupby("Country")["Revenue"]
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

                    # Give the revenue/AOV/order KPIs a wider first row.
                    # Customers moves below alongside the top-customer/country cards.
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Revenue", f"£{total_revenue:,.0f}")
                    c2.metric("Average Order Value", f"£{average_order_value:,.2f}")
                    c3.metric("Orders", f"{invoice_count:,}")

                    c4, c5, c6 = st.columns(3)
                    c4.metric("Customers", f"{total_customers:,}")
                    c5.metric(
                        "Top Customer",
                        top_customer_text,
                        help=f"Completed-sales value: £{top_customer_value:,.2f}"
                    )
                    c6.metric(
                        "Top Country",
                        top_country,
                        help=f"Completed-sales revenue: £{top_country_value:,.2f}"
                    )

                    if business_customer_summary_df is not None:
                        st.caption(
                            "Customer segmentation/risk measures are sourced from the approved "
                            "customer_summary.csv publication; transaction KPIs use completed sales only."
                        )

                # ---PRODUCTS & MARKET BASKET

                with product_tab:
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
                            help=f"Revenue: £{float(top_product['Revenue']):,.2f}"
                        )

                        if PLOTLY_AVAILABLE:
                            fig = px.bar(
                                product_summary.sort_values("Revenue"),
                                x="Revenue",
                                y="Description",
                                orientation="h",
                                title="Top 10 Products by Revenue",
                                labels={"Revenue": "Revenue (£)", "Description": "Product"}
                            )
                            fig.update_layout(height=480, margin=dict(l=10, r=10, t=50, b=10))
                            st.plotly_chart(fig, width="stretch")
                        else:
                            st.dataframe(product_summary, width="stretch", hide_index=True)

                    st.divider()
                    st.subheader("Market Basket Analysis")
                    st.caption(
                        "Apriori rules are calculated on completed sales at invoice level. "
                        "Use looser thresholds for exploration, then tighten them for reporting."
                    )

                    m1, m2, m3, m4 = st.columns(4)
                    mba_support = m1.number_input(
                        "Minimum support",
                        min_value=0.0005,
                        max_value=0.05,
                        value=0.002,
                        step=0.0005,
                        format="%.4f"
                    )
                    mba_confidence = m2.slider(
                        "Minimum confidence",
                        min_value=0.05,
                        max_value=0.90,
                        value=0.15,
                        step=0.05
                    )
                    mba_lift = m3.slider(
                        "Minimum lift",
                        min_value=1.0,
                        max_value=5.0,
                        value=1.0,
                        step=0.1
                    )
                    mba_products = m4.slider(
                        "Products analysed",
                        min_value=50,
                        max_value=300,
                        value=150,
                        step=25
                    )

                    if st.button("Run Market Basket Analysis", type="primary"):
                        with loading_overlay(
                            "Finding frequently co-purchased products from completed-sale invoices."
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
                        d1, d2, d3, d4 = st.columns(4)
                        d1.metric("Eligible Invoices", f"{diagnostics['eligible_invoices']:,}")
                        d2.metric("Products Analysed", f"{diagnostics['products_analysed']:,}")
                        d3.metric("Frequent Itemsets", f"{diagnostics['frequent_itemsets']:,}")
                        d4.metric("Rules Returned", f"{diagnostics['rules_after_lift']:,}")
                        st.caption(f"MBA status: {diagnostics['status']}")

                    if st.session_state.mba_rules is not None:
                        if st.session_state.mba_rules.empty:
                            st.info(
                                "No association rules met the selected thresholds. "
                                "Try lower support/confidence or analyse more products."
                            )
                        else:
                            st.dataframe(
                                st.session_state.mba_rules.head(50),
                                width="stretch",
                                hide_index=True
                            )

                # ---GEOGRAPHY

                with geo_tab:
                    country_summary = (
                        sales.dropna(subset=["Country"])
                        .groupby("Country")
                        .agg(
                            Revenue=("Revenue", "sum"),
                            Orders=("Invoice", "nunique"),
                            Customers=("Customer ID", "nunique"),
                        )
                        .reset_index()
                        .sort_values("Revenue", ascending=False)
                    )

                    # Keep aggregate/unknown labels in the country table, but do not
                    # send them to Plotly's country-name map where they cannot resolve.
                    map_country_summary = country_summary.loc[
                        ~country_summary["Country"].isin(COUNTRY_MAP_EXCLUSIONS)
                    ].copy()

                    if country_summary.empty:
                        st.info("No country information is available in the approved sales data.")
                    else:
                        g1, g2 = st.columns([2, 1])

                        with g1:
                            st.subheader("Revenue by Country")
                            if PLOTLY_AVAILABLE:
                                map_fig = px.choropleth(
                                    map_country_summary,
                                    locations="Country",
                                    locationmode="country names",
                                    color="Revenue",
                                    hover_name="Country",
                                    hover_data={
                                        "Revenue": ":,.2f",
                                        "Orders": ":,",
                                        "Customers": ":,",
                                    },
                                    title="Global Revenue Footprint"
                                )
                                map_fig.update_layout(
                                    height=520,
                                    margin=dict(l=0, r=0, t=50, b=0)
                                )
                                st.plotly_chart(map_fig, width="stretch")
                            else:
                                st.dataframe(
                                    country_summary,
                                    width="stretch",
                                    hide_index=True
                                )

                        with g2:
                            st.subheader("Top Countries")
                            st.dataframe(
                                country_summary.head(10),
                                width="stretch",
                                hide_index=True
                            )

            st.divider()
            st.info(
                "Quick Analytics is intentionally lightweight. Use the Power BI Dashboard "
                "for the full executive, retention and scenario-analysis experience."
            )

    # ---POWER BI DASHBOARD


    elif navigation == "Power BI Dashboard":

        st.header(
            "Power BI Dashboard"
        )

        st.write(
            "Access the approved customer-retention reporting layer. "
            "This workspace is read-only for Business users."
        )

        if not publication_available:

            st.warning(
                "The reporting layer is not ready because "
                "no approved publication is currently available."
            )

        else:

            publication_version = str(
                latest_publication.get(
                    "PublicationVersion",
                    "Unavailable"
                )
            )

            publication_time = str(
                latest_publication.get(
                    "PublicationTimestamp",
                    "Unavailable"
                )
            )

            high_value_at_risk = int(
                latest_publication.get(
                    "HighValueAtRisk",
                    0
                )
            )

            col1, col2, col3, col4 = (
                st.columns(
                    4
                )
            )

            col1.metric(
                "Approved Version",
                publication_version
            )

            col2.metric(
                "Customers",
                f"{len(business_rfm_df):,}"
            )

            at_risk_count = (

                int(
                    business_rfm_df[
                        "AtRisk60"
                    ]
                    .sum()
                )

                if "AtRisk60"
                in business_rfm_df.columns

                else 0
            )

            col3.metric(
                "At Risk",
                f"{at_risk_count:,}"
            )

            col4.metric(
                "High-Value At Risk",
                f"{high_value_at_risk:,}"
            )

            data_start, data_through = resolve_publication_data_period(
                latest_publication,
                business_transactions_df
            )
            source_file = str(
                latest_publication.get("SourceFile", "Unavailable")
            )

            st.caption(
                f"Data period: {format_business_date(data_start)} "
                f"to {format_business_date(data_through)} | "
                f"Published: {publication_time} | "
                f"Source: {source_file}"
            )

            st.divider()

            if (
                "Priority"
                in business_rfm_df.columns
            ):

                st.subheader(
                    "Retention Priority Distribution"
                )

                business_priority_counts = (
                    business_rfm_df[
                        "Priority"
                    ]
                    .value_counts()
                    .rename_axis(
                        "Priority"
                    )
                    .reset_index(
                        name="Customers"
                    )
                )

                st.dataframe(
                    business_priority_counts,
                    width="stretch",
                    hide_index=True
                )

            st.subheader(
                "Approved Reporting Dataset Preview"
            )

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
                    "Priority"
                ]

                if column
                in business_rfm_df.columns
            ]

            st.dataframe(
                business_rfm_df[
                    preview_columns
                ]
                .head(
                    20
                ),
                width="stretch"
            )

            st.divider()

            st.subheader(
                "Power BI Access"
            )

            if power_bi_url:

                st.link_button(
                    "Open Power BI Dashboard",
                    power_bi_url,
                    type="primary"
                )

                st.success(
                    "The dashboard link is connected "
                    "to the approved business reporting workspace."
                )

            else:

                st.info(
                    "The approved Power BI hand-off dataset is ready. "
                    "The Power BI dashboard URL has not yet "
                    "been configured in Streamlit Secrets."
                )

            reporting_csv = (
                business_rfm_df
                .to_csv(
                    index=False
                )
                .encode(
                    "utf-8"
                )
            )

            st.download_button(
                label="Download Approved RFM Reporting Dataset",
                data=reporting_csv,
                file_name="latest_rfm_analysis_dataset.csv",
                mime="text/csv"
            )

            st.caption(
                "Reporting source: "
                "outputs/published/"
                "latest_rfm_analysis_dataset.csv"
            )
