# ============================================================
# CUSTOMER RETENTION SYSTEM
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

# IMPORTS

import io
import re
import sqlite3

from datetime import datetime
from pathlib import Path

import bcrypt
import pandas as pd
import streamlit as st
import streamlit_authenticator as stauth
import yaml


# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="RNI Customer Retention System",
    page_icon="📊",
    layout="wide"
)

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

# CREATE REQUIRED DIRECTORIES
# ============================================================

for directory in [
    PUBLISH_DIR,
    ARCHIVE_DIR,
    POWER_BI_DIR,
    AUDIT_DIR,
    USER_DATA_DIR
]:
    directory.mkdir(
        parents=True,
        exist_ok=True
    )


# LOADING NON-SENSITIVE CONFIGURATION
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
            ]
        )
    )


elif user_role == BUSINESS_ROLE:

    navigation = (
        st.sidebar.radio(
            "Business Workspace",
            [
                "Pipeline Status",
                "Power BI Dashboard",
            ]
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

    st.session_state.cleaned_data = None
    st.session_state.cleaning_steps = None
    st.session_state.cleaning_summary = None
    st.session_state.cleaning_complete = False

    st.session_state.rfm_data = None
    st.session_state.rfm_summary = None
    st.session_state.rfm_complete = False

    reset_publication_state()


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

    raw_df = (
        df.copy()
    )

    summary_rows = []

    starting_rows = (
        len(
            raw_df
        )
    )

    summary_rows.append({

        "Step":
            "Raw dataset",

        "Rows Before":
            starting_rows,

        "Rows Removed":
            0,

        "Rows After":
            starting_rows,

        "Action":
            "Preserved source data before cleaning."
    })

    # Exact duplicates
    before_duplicates = (
        len(
            raw_df
        )
    )

    prepared_df = (
        raw_df
        .drop_duplicates()
        .copy()
    )

    after_duplicates = (
        len(
            prepared_df
        )
    )

    duplicates_removed = (
        before_duplicates
        -
        after_duplicates
    )

    summary_rows.append({

        "Step":
            "Exact duplicate removal",

        "Rows Before":
            before_duplicates,

        "Rows Removed":
            duplicates_removed,

        "Rows After":
            after_duplicates,

        "Action":
            "Removed only completely identical rows."
    })

    # Standardise text
    for column in [
        "Invoice",
        "StockCode",
        "Country"
    ]:

        prepared_df[
            column
        ] = (
            prepared_df[
                column
            ]
            .astype(
                str
            )
            .str.strip()
        )

    prepared_df[
        "Description"
    ] = (
        prepared_df[
            "Description"
        ]
        .astype(
            "string"
        )
        .str.strip()
    )

    # Types
    prepared_df[
        "InvoiceDate"
    ] = pd.to_datetime(
        prepared_df[
            "InvoiceDate"
        ],
        errors="coerce"
    )

    prepared_df[
        "Quantity"
    ] = pd.to_numeric(
        prepared_df[
            "Quantity"
        ],
        errors="coerce"
    )

    prepared_df[
        "Price"
    ] = pd.to_numeric(
        prepared_df[
            "Price"
        ],
        errors="coerce"
    )

    prepared_df[
        "Customer ID"
    ] = pd.to_numeric(
        prepared_df[
            "Customer ID"
        ],
        errors="coerce"
    )

    summary_rows.append({

        "Step":
            "Type and format standardisation",

        "Rows Before":
            len(
                prepared_df
            ),

        "Rows Removed":
            0,

        "Rows After":
            len(
                prepared_df
            ),

        "Action":
            (
                "Standardised text fields and converted "
                "date and numeric fields to consistent types."
            )
    })

    # Cancellation identification
    prepared_df[
        "IsCancellation"
    ] = (
        prepared_df[
            "Invoice"
        ]
        .str.upper()
        .str.startswith(
            "C"
        )
    )

    cancellation_count = int(
        prepared_df[
            "IsCancellation"
        ]
        .sum()
    )

    summary_rows.append({

        "Step":
            "Cancellation identification",

        "Rows Before":
            len(
                prepared_df
            ),

        "Rows Removed":
            0,

        "Rows After":
            len(
                prepared_df
            ),

        "Action":
            (
                f"Flagged {cancellation_count:,} cancellation "
                "records using invoice identifiers beginning with C."
            )
    })

    # Qualifying positive sales
    before_sales_filter = (
        len(
            prepared_df
        )
    )

    qualifying_mask = (

        ~prepared_df[
            "IsCancellation"
        ]

        &

        (
            prepared_df[
                "Quantity"
            ]
            > 0
        )

        &

        (
            prepared_df[
                "Price"
            ]
            > 0
        )

        &

        prepared_df[
            "InvoiceDate"
        ].notna()
    )

    transaction_df = (
        prepared_df
        .loc[
            qualifying_mask
        ]
        .copy()
    )

    after_sales_filter = (
        len(
            transaction_df
        )
    )

    non_qualifying_removed = (
        before_sales_filter
        -
        after_sales_filter
    )

    summary_rows.append({

        "Step":
            "Qualifying sales filter",

        "Rows Before":
            before_sales_filter,

        "Rows Removed":
            non_qualifying_removed,

        "Rows After":
            after_sales_filter,

        "Action":
            (
                "Retained non-cancellation records with "
                "Quantity > 0, Price > 0 and a valid InvoiceDate."
            )
    })

    # Revenue
    transaction_df[
        "Revenue"
    ] = (
        transaction_df[
            "Quantity"
        ]
        *
        transaction_df[
            "Price"
        ]
    )

    # Calendar fields
    transaction_df[
        "Year"
    ] = (
        transaction_df[
            "InvoiceDate"
        ]
        .dt.year
    )

    transaction_df[
        "Month"
    ] = (
        transaction_df[
            "InvoiceDate"
        ]
        .dt.month
    )

    transaction_df[
        "MonthName"
    ] = (
        transaction_df[
            "InvoiceDate"
        ]
        .dt.month_name()
    )

    transaction_df[
        "Quarter"
    ] = (
        transaction_df[
            "InvoiceDate"
        ]
        .dt.quarter
    )

    transaction_df[
        "Day"
    ] = (
        transaction_df[
            "InvoiceDate"
        ]
        .dt.day
    )

    transaction_df[
        "DayOfWeek"
    ] = (
        transaction_df[
            "InvoiceDate"
        ]
        .dt.day_name()
    )

    transaction_df[
        "Hour"
    ] = (
        transaction_df[
            "InvoiceDate"
        ]
        .dt.hour
    )

    final_rows = (
        len(
            transaction_df
        )
    )

    total_removed = (
        starting_rows
        -
        final_rows
    )

    retained_percentage = (

        (
            final_rows
            /
            starting_rows
        )
        *
        100

        if starting_rows > 0

        else 0
    )

    missing_customer_ids = int(
        transaction_df[
            "Customer ID"
        ]
        .isna()
        .sum()
    )

    final_summary = {

        "starting_rows":
            starting_rows,

        "prepared_rows":
            len(
                prepared_df
            ),

        "duplicates_removed":
            duplicates_removed,

        "cancellations_identified":
            cancellation_count,

        "non_qualifying_removed":
            non_qualifying_removed,

        "final_rows":
            final_rows,

        "total_removed":
            total_removed,

        "retained_percentage":
            retained_percentage,

        "missing_customer_ids":
            missing_customer_ids,

        "final_columns":
            len(
                transaction_df.columns
            )
    }

    return (
        transaction_df,
        pd.DataFrame(
            summary_rows
        ),
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

    rfm_df = (
        cleaned_df
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
    username
):

    publication_time = (
        datetime.now()
    )

    timestamp = (
        publication_time
        .strftime(
            "%Y%m%d_%H%M%S_%f"
        )
    )

    publication_version = (
        f"PUB_{timestamp}"
    )

    publication_display_time = (
        publication_time
        .strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    (
        reporting_df,
        high_value_threshold

    ) = build_reporting_dataset(
        rfm_df
    )

    cv_source = (
        MODEL_ARTIFACT_DIR
        /
        "model_cv_results.csv"
    )

    temporal_source = (
        MODEL_ARTIFACT_DIR
        /
        "temporal_test_predictions.csv"
    )

    if not cv_source.exists():

        raise FileNotFoundError(
            f"Approved model artifact not found: "
            f"{cv_source}"
        )

    if not temporal_source.exists():

        raise FileNotFoundError(
            f"Approved temporal prediction artifact not found: "
            f"{temporal_source}"
        )

    model_cv_df = pd.read_csv(
        cv_source
    )

    temporal_df = pd.read_csv(
        temporal_source
    )

    # Verify predictive label polarity
    required_prediction_columns = {
        "PredictedRetentionRisk",
        "PredictedRiskLevel"
    }

    if required_prediction_columns.issubset(
        temporal_df.columns
    ):

        invalid_mapping = temporal_df.loc[
            (
                (
                    temporal_df[
                        "PredictedRetentionRisk"
                    ]
                    == 1
                )
                &
                (
                    temporal_df[
                        "PredictedRiskLevel"
                    ]
                    != "At Risk"
                )
            )
            |
            (
                (
                    temporal_df[
                        "PredictedRetentionRisk"
                    ]
                    == 0
                )
                &
                (
                    temporal_df[
                        "PredictedRiskLevel"
                    ]
                    != "Retained"
                )
            )
        ]

        if len(
            invalid_mapping
        ) > 0:

            raise ValueError(
                "Predictive label mapping failed: "
                "1 must mean At Risk and 0 must mean Retained."
            )

    # Archive paths
    clean_archive_path = (
        ARCHIVE_DIR
        /
        f"clean_transactions_{timestamp}.csv"
    )

    rfm_archive_path = (
        ARCHIVE_DIR
        /
        f"rfm_analysis_dataset_{timestamp}.csv"
    )

    cv_archive_path = (
        ARCHIVE_DIR
        /
        f"model_cv_results_{timestamp}.csv"
    )

    temporal_archive_path = (
        ARCHIVE_DIR
        /
        f"temporal_test_predictions_{timestamp}.csv"
    )

    # Stable latest paths
    latest_clean_path = (
        PUBLISH_DIR
        /
        "latest_clean_transactions.csv"
    )

    latest_rfm_path = (
        PUBLISH_DIR
        /
        "latest_rfm_analysis_dataset.csv"
    )

    latest_cv_path = (
        PUBLISH_DIR
        /
        "latest_model_cv_results.csv"
    )

    latest_temporal_path = (
        PUBLISH_DIR
        /
        "latest_temporal_test_predictions.csv"
    )

    # Stable Power BI contract
    power_bi_rfm_path = (
        POWER_BI_DIR
        /
        "rfm_analysis_dataset.csv"
    )

    power_bi_cv_path = (
        POWER_BI_DIR
        /
        "model_cv_results.csv"
    )

    power_bi_temporal_path = (
        POWER_BI_DIR
        /
        "temporal_test_predictions.csv"
    )

    manifest_path = (
        PUBLISH_DIR
        /
        "publication_manifest.csv"
    )

    # Archive outputs
    cleaned_df.to_csv(
        clean_archive_path,
        index=False
    )

    reporting_df.to_csv(
        rfm_archive_path,
        index=False
    )

    model_cv_df.to_csv(
        cv_archive_path,
        index=False
    )

    temporal_df.to_csv(
        temporal_archive_path,
        index=False
    )

    # Latest outputs
    cleaned_df.to_csv(
        latest_clean_path,
        index=False
    )

    reporting_df.to_csv(
        latest_rfm_path,
        index=False
    )

    model_cv_df.to_csv(
        latest_cv_path,
        index=False
    )

    temporal_df.to_csv(
        latest_temporal_path,
        index=False
    )

    # Power BI handoff
    reporting_df.to_csv(
        power_bi_rfm_path,
        index=False
    )

    model_cv_df.to_csv(
        power_bi_cv_path,
        index=False
    )

    temporal_df.to_csv(
        power_bi_temporal_path,
        index=False
    )

    high_value_customers = int(
        reporting_df[
            "HighValue"
        ]
        .sum()
    )

    high_value_at_risk = int(
        (
            reporting_df[
                "HighValue"
            ]
            &
            reporting_df[
                "AtRisk60"
            ]
        )
        .sum()
    )

    priority_counts = (
        reporting_df[
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

    predicted_counts = (
        temporal_df[
            "PredictedRiskLevel"
        ]
        .value_counts()
        .rename_axis(
            "PredictedRiskLevel"
        )
        .reset_index(
            name="Customers"
        )
    )

    predicted_at_risk = int(
        (
            temporal_df[
                "PredictedRiskLevel"
            ]
            == "At Risk"
        )
        .sum()
    )

    predicted_retained = int(
        (
            temporal_df[
                "PredictedRiskLevel"
            ]
            == "Retained"
        )
        .sum()
    )

    manifest_record = pd.DataFrame({

        "PublicationTimestamp": [
            publication_display_time
        ],

        "PublicationVersion": [
            publication_version
        ],

        "PublishedBy": [
            username
        ],

        "SourceFile": [
            source_filename
        ],

        "CleanRows": [
            len(
                cleaned_df
            )
        ],

        "RFMRows": [
            len(
                reporting_df
            )
        ],

        "RFMColumns": [
            len(
                reporting_df.columns
            )
        ],

        "HighValueThreshold": [
            high_value_threshold
        ],

        "HighValueAtRisk": [
            high_value_at_risk
        ],

        "ModelCVRows": [
            len(
                model_cv_df
            )
        ],

        "TemporalPredictionRows": [
            len(
                temporal_df
            )
        ],

        "PredictedAtRisk": [
            predicted_at_risk
        ],

        "PredictedRetained": [
            predicted_retained
        ],

        "PowerBIRFMFile": [
            power_bi_rfm_path.name
        ],

        "PowerBICVFile": [
            power_bi_cv_path.name
        ],

        "PowerBITemporalFile": [
            power_bi_temporal_path.name
        ]
    })

    if manifest_path.exists():

        existing_manifest = pd.read_csv(
            manifest_path
        )

        publication_manifest = pd.concat(
            [
                existing_manifest,
                manifest_record
            ],
            ignore_index=True
        )

    else:

        publication_manifest = (
            manifest_record.copy()
        )

    publication_manifest.to_csv(
        manifest_path,
        index=False
    )

    publication_summary = {

        "publication_time":
            publication_display_time,

        "publication_version":
            publication_version,

        "published_by":
            username,

        "source_filename":
            source_filename,

        "clean_rows":
            len(
                cleaned_df
            ),

        "rfm_rows":
            len(
                reporting_df
            ),

        "rfm_columns":
            len(
                reporting_df.columns
            ),

        "high_value_threshold":
            high_value_threshold,

        "high_value_customers":
            high_value_customers,

        "high_value_at_risk":
            high_value_at_risk,

        "priority_counts":
            priority_counts,

        "model_cv_rows":
            len(
                model_cv_df
            ),

        "temporal_rows":
            len(
                temporal_df
            ),

        "predicted_at_risk":
            predicted_at_risk,

        "predicted_retained":
            predicted_retained,

        "predicted_counts":
            predicted_counts,

        "clean_archive_path":
            clean_archive_path,

        "rfm_archive_path":
            rfm_archive_path,

        "cv_archive_path":
            cv_archive_path,

        "temporal_archive_path":
            temporal_archive_path,

        "latest_clean_path":
            latest_clean_path,

        "latest_rfm_path":
            latest_rfm_path,

        "latest_cv_path":
            latest_cv_path,

        "latest_temporal_path":
            latest_temporal_path,

        "power_bi_rfm_path":
            power_bi_rfm_path,

        "power_bi_cv_path":
            power_bi_cv_path,

        "power_bi_temporal_path":
            power_bi_temporal_path,

        "manifest_path":
            manifest_path
    }

    return (
        reporting_df,
        publication_summary
    )


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

st.divider()


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

        col1, col2, col3, col4, col5 = (
            st.columns(
                5
            )
        )

        col1.metric(
            "Dataset",
            (
                "Loaded"
                if st.session_state.ingestion_complete
                else "Not Loaded"
            )
        )

        col2.metric(
            "Validation",
            (
                "Completed"
                if st.session_state.validation_complete
                else "Not Run"
            )
        )

        col3.metric(
            "Cleaning",
            (
                "Completed"
                if st.session_state.cleaning_complete
                else "Not Run"
            )
        )

        col4.metric(
            "RFM",
            (
                "Completed"
                if st.session_state.rfm_complete
                else "Not Run"
            )
        )

        col5.metric(
            "Power BI Handoff",
            (
                "Published"
                if st.session_state.publication_complete
                else "Not Published"
            )
        )

        st.info(
            "Use the Technical Workspace menu to continue "
            "through the controlled preparation pipeline."
        )


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
                            default=sheet_names
                        )
                    )

                    st.session_state[
                        "selected_sheets"
                    ] = selected_sheets

                except Exception as e:

                    st.error(
                        f"Unable to inspect Excel workbook: {e}"
                    )

            st.divider()

            if st.button(
                "Load Dataset",
                type="primary"
            ):

                try:

                    with st.spinner(
                        "Loading dataset..."
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
                use_container_width=True,
                hide_index=True
            )

            st.subheader(
                "Raw Data Preview"
            )

            st.dataframe(
                raw_df.head(
                    20
                ),
                use_container_width=True
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

                    validation_results = (
                        validate_dataset(
                            st.session_state.raw_data
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

                col1, col2, col3 = (
                    st.columns(
                        3
                    )
                )

                col1.metric(
                    "Passed",
                    passed
                )

                col2.metric(
                    "Warnings",
                    warnings
                )

                col3.metric(
                    "Failed",
                    failed
                )

                st.dataframe(
                    validation_results,
                    use_container_width=True,
                    hide_index=True
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
                    "Cleaning Summary"
                )

                col1, col2, col3, col4 = (
                    st.columns(
                        4
                    )
                )

                col1.metric(
                    "Raw Rows",
                    f"{summary['starting_rows']:,}"
                )

                col2.metric(
                    "Duplicates Removed",
                    f"{summary['duplicates_removed']:,}"
                )

                col3.metric(
                    "Final Qualifying Rows",
                    f"{summary['final_rows']:,}"
                )

                col4.metric(
                    "Rows Retained",
                    f"{summary['retained_percentage']:.2f}%"
                )

                st.dataframe(
                    st.session_state.cleaning_steps,
                    use_container_width=True,
                    hide_index=True
                )

                st.subheader(
                    "Post-Cleaning Quality Checks"
                )

                post_checks = pd.DataFrame({

                    "Check": [
                        "Exact Duplicates",
                        "Cancellation Transactions",
                        "Non-positive Quantity",
                        "Non-positive Price",
                        "Missing Invoice Dates"
                    ],

                    "Count": [

                        int(
                            cleaned_df
                            .duplicated()
                            .sum()
                        ),

                        int(
                            cleaned_df[
                                "IsCancellation"
                            ]
                            .sum()
                        ),

                        int(
                            (
                                cleaned_df[
                                    "Quantity"
                                ]
                                <= 0
                            )
                            .sum()
                        ),

                        int(
                            (
                                cleaned_df[
                                    "Price"
                                ]
                                <= 0
                            )
                            .sum()
                        ),

                        int(
                            cleaned_df[
                                "InvoiceDate"
                            ]
                            .isna()
                            .sum()
                        )
                    ]
                })

                post_checks[
                    "Status"
                ] = post_checks[
                    "Count"
                ].apply(
                    lambda value:
                        (
                            "PASS"
                            if value == 0
                            else "FAIL"
                        )
                )

                st.dataframe(
                    post_checks,
                    use_container_width=True,
                    hide_index=True
                )

                st.caption(
                    f"Missing Customer IDs retained for "
                    f"transaction-level analysis: "
                    f"{summary['missing_customer_ids']:,}. "
                    "They are excluded only during customer-level RFM analysis."
                )

                st.subheader(
                    "Cleaned Data Preview"
                )

                st.dataframe(
                    cleaned_df.head(
                        20
                    ),
                    use_container_width=True
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
                    use_container_width=True,
                    hide_index=True
                )

                st.subheader(
                    "RFM Segment Distribution"
                )

                st.dataframe(
                    summary[
                        "segment_counts"
                    ],
                    use_container_width=True,
                    hide_index=True
                )

                st.subheader(
                    "Operational Risk Distribution"
                )

                st.dataframe(
                    summary[
                        "risk_counts"
                    ],
                    use_container_width=True,
                    hide_index=True
                )

                st.subheader(
                    "RFM Data Preview"
                )

                st.dataframe(
                    rfm_df.head(
                        20
                    ),
                    use_container_width=True
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
                use_container_width=True,
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

                col1, col2, col3, col4 = (
                    st.columns(
                        4
                    )
                )

                col1.metric(
                    "Publication Version",
                    summary[
                        "publication_version"
                    ]
                )

                col2.metric(
                    "Published Customers",
                    f"{summary['rfm_rows']:,}"
                )

                col3.metric(
                    "High-Value At Risk",
                    f"{summary['high_value_at_risk']:,}"
                )

                col4.metric(
                    "Published By",
                    summary[
                        "published_by"
                    ]
                )

                st.caption(
                    f"Published at "
                    f"{summary['publication_time']} from "
                    f"{summary['source_filename']}"
                )

                st.subheader(
                    "Published Priority Distribution"
                )

                st.dataframe(
                    summary[
                        "priority_counts"
                    ],
                    use_container_width=True,
                    hide_index=True
                )

                st.subheader(
                    "Published Files"
                )

                published_files = pd.DataFrame({

                    "Output": [
                        "Power BI RFM Dataset",
                        "Power BI Model CV Results",
                        "Power BI Temporal Predictions",
                        "Publication Manifest"
                    ],

                    "File": [

                        Path(
                            summary[
                                "power_bi_rfm_path"
                            ]
                        ).name,

                        Path(
                            summary[
                                "power_bi_cv_path"
                            ]
                        ).name,

                        Path(
                            summary[
                                "power_bi_temporal_path"
                            ]
                        ).name,

                        Path(
                            summary[
                                "manifest_path"
                            ]
                        ).name
                    ]
                })

                st.dataframe(
                    published_files,
                    use_container_width=True,
                    hide_index=True
                )

                st.subheader(
                    "Published RFM Preview"
                )

                st.dataframe(
                    published_rfm.head(
                        20
                    ),
                    use_container_width=True
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
                    use_container_width=True,
                    hide_index=True
                )

                st.success(
                    "Power BI hand-off is ready. "
                    "Use the three files in outputs/published/power_bi/. "
                    "Predictive labels are governed as "
                    "1 = At Risk and 0 = Retained."
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
                use_container_width=True,
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
                use_container_width=True,
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

    latest_publication = None
    business_rfm_df = None

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

            business_rfm_df = pd.read_csv(
                latest_rfm_path
            )

        except Exception:

            business_rfm_df = None

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

            st.caption(
                f"Published at {publication_time} "
                f"from {source_file} "
                f"by {published_by}."
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
                use_container_width=True,
                hide_index=True
            )

            st.subheader(
                "Reporting Files"
            )

            reporting_files_df = pd.DataFrame({

                "Output": [
                    "Customer RFM Reporting Dataset",
                    "Clean Transaction Dataset",
                    "Publication Manifest"
                ],

                "Status": [

                    (
                        "Available"
                        if latest_rfm_path.exists()
                        else "Unavailable"
                    ),

                    (
                        "Available"
                        if latest_clean_path.exists()
                        else "Unavailable"
                    ),

                    (
                        "Available"
                        if manifest_path.exists()
                        else "Unavailable"
                    )
                ],

                "Purpose": [
                    "Customer segmentation, risk and retention reporting",
                    "Approved transaction-level reporting source",
                    "Publication version and governance record"
                ]
            })

            st.dataframe(
                reporting_files_df,
                use_container_width=True,
                hide_index=True
            )

            st.success(
                "The latest approved reporting dataset is available. "
                "Business access is read-only and technical processing "
                "functions remain restricted to authorised Technical users."
            )


    # ========================================================
    # POWER BI DASHBOARD
    # ========================================================

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

            st.caption(
                f"Latest approved publication: "
                f"{publication_time}."
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
                    use_container_width=True,
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
                use_container_width=True
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
