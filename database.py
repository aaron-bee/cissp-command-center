import os
import sqlite3
from pathlib import Path

from werkzeug.security import generate_password_hash


BASE_DIR = Path(__file__).resolve().parent

DATABASE_PATH = Path(
    os.environ.get(
        "DATABASE_PATH",
        str(BASE_DIR / "data" / "cissp.db"),
    )
)


CISSP_DOMAINS = [
    (1, 1, "CISSP", "Security & Risk Management", 16),
    (2, 2, "CISSP", "Asset Security", 10),
    (3, 3, "CISSP", "Security Architecture & Engineering", 13),
    (4, 4, "CISSP", "Communication & Network Security", 13),
    (5, 5, "CISSP", "Identity & Access Management", 13),
    (6, 6, "CISSP", "Security Assessment & Testing", 12),
    (7, 7, "CISSP", "Security Operations", 13),
    (8, 8, "CISSP", "Software Development Security", 10),
]

CISM_DOMAINS = [
    (101, 1, "CISM", "Information Security Governance", 17),
    (102, 2, "CISM", "Information Security Risk Management", 20),
    (103, 3, "CISM", "Information Security Program", 33),
    (104, 4, "CISM", "Incident Management", 30),
]


def get_db_connection():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")

    return connection


def column_exists(connection, table_name, column_name):
    columns = connection.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    return any(
        column["name"] == column_name
        for column in columns
    )


def add_column_if_missing(
    connection,
    table_name,
    column_name,
    definition,
):
    if not column_exists(
        connection,
        table_name,
        column_name,
    ):
        connection.execute(
            f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_name} {definition}
            """
        )


def table_exists(connection, table_name):
    row = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = ?
        """,
        (table_name,),
    ).fetchone()

    return row is not None


def ensure_admin_user(connection):
    """
    v1.2 migration:
    The first user becomes the administrator. On Render this is seeded
    from the existing DASHBOARD_USERNAME / DASHBOARD_PASSWORD variables.

    Existing study data is then assigned to that administrator.
    """
    existing_user = connection.execute(
        """
        SELECT id
        FROM users
        ORDER BY id
        LIMIT 1
        """
    ).fetchone()

    if existing_user:
        return existing_user["id"]

    username = os.environ.get(
        "DASHBOARD_USERNAME",
        "admin",
    ).strip() or "admin"

    password = os.environ.get(
        "DASHBOARD_PASSWORD",
        "",
    )

    if not password:
        password = "admin"
        print(
            "WARNING: DASHBOARD_PASSWORD is not set. "
            "Local bootstrap password is 'admin'. "
            "Do not deploy publicly without a real password."
        )

    display_name = os.environ.get(
        "DASHBOARD_DISPLAY_NAME",
        "Aaron",
    ).strip() or username

    cursor = connection.execute(
        """
        INSERT INTO users (
            username,
            display_name,
            password_hash,
            is_admin,
            is_active
        )
        VALUES (?, ?, ?, 1, 1)
        """,
        (
            username,
            display_name,
            generate_password_hash(password),
        ),
    )

    return cursor.lastrowid


def migrate_existing_data_to_admin(
    connection,
    admin_user_id,
):
    """
    Assigns all pre-v1.2 records to the administrator.

    This preserves the existing personal dashboard while new users start
    with isolated, empty study records.
    """

    # Existing per-domain totals were historically stored directly on
    # the shared domains table. Copy those totals to Aaron/admin exactly once.
    existing_stats = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM user_domain_stats
        WHERE user_id = ?
        """,
        (admin_user_id,),
    ).fetchone()["count"]

    if existing_stats == 0:
        connection.execute(
            """
            INSERT INTO user_domain_stats (
                user_id,
                domain_id,
                questions_answered,
                questions_correct
            )
            SELECT
                ?,
                id,
                questions_answered,
                questions_correct
            FROM domains
            """,
            (admin_user_id,),
        )

    # Assign legacy transactional data.
    for table_name in (
        "assessments",
        "study_sessions",
        "weak_topics",
        "certification_attempts",
    ):
        if table_exists(connection, table_name):
            add_column_if_missing(
                connection,
                table_name,
                "user_id",
                "INTEGER",
            )

            connection.execute(
                f"""
                UPDATE {table_name}
                SET user_id = ?
                WHERE user_id IS NULL
                """,
                (admin_user_id,),
            )

    # Move legacy global settings to admin's personal settings.
    if table_exists(connection, "settings"):
        rows = connection.execute(
            """
            SELECT key, value
            FROM settings
            """
        ).fetchall()

        for row in rows:
            connection.execute(
                """
                INSERT OR IGNORE INTO user_settings (
                    user_id,
                    key,
                    value
                )
                VALUES (?, ?, ?)
                """,
                (
                    admin_user_id,
                    row["key"],
                    row["value"],
                ),
            )


def ensure_user_defaults(
    connection,
    user_id,
):
    default_settings = [
        ("cism_exam_date", ""),
        ("cissp_exam_date", ""),
        ("weekly_hour_target", "10"),
    ]

    connection.executemany(
        """
        INSERT OR IGNORE INTO user_settings (
            user_id,
            key,
            value
        )
        VALUES (?, ?, ?)
        """,
        [
            (
                user_id,
                key,
                value,
            )
            for key, value in default_settings
        ],
    )

    connection.executemany(
        """
        INSERT OR IGNORE INTO user_domain_stats (
            user_id,
            domain_id,
            questions_answered,
            questions_correct
        )
        VALUES (?, ?, 0, 0)
        """,
        [
            (
                user_id,
                domain_id,
            )
            for domain_id, _, _, _, _ in (
                CISSP_DOMAINS + CISM_DOMAINS
            )
        ],
    )


def initialize_database():
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = get_db_connection()

    # =========================================================
    # SHARED DOMAIN REFERENCE DATA
    # =========================================================

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            weight INTEGER NOT NULL,
            questions_answered INTEGER NOT NULL DEFAULT 0,
            questions_correct INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    add_column_if_missing(
        connection,
        "domains",
        "certification",
        "TEXT NOT NULL DEFAULT 'CISSP'",
    )

    add_column_if_missing(
        connection,
        "domains",
        "domain_number",
        "INTEGER",
    )

    for (
        domain_id,
        domain_number,
        certification,
        name,
        weight,
    ) in CISSP_DOMAINS + CISM_DOMAINS:

        connection.execute(
            """
            INSERT OR IGNORE INTO domains (
                id,
                domain_number,
                certification,
                name,
                weight
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                domain_id,
                domain_number,
                certification,
                name,
                weight,
            ),
        )

        connection.execute(
            """
            UPDATE domains
            SET
                domain_number = ?,
                certification = ?,
                name = ?,
                weight = ?
            WHERE id = ?
            """,
            (
                domain_number,
                certification,
                name,
                weight,
                domain_id,
            ),
        )

    # =========================================================
    # USERS
    # =========================================================

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # Per-user aggregate stats.
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS user_domain_stats (
            user_id INTEGER NOT NULL,
            domain_id INTEGER NOT NULL,
            questions_answered INTEGER NOT NULL DEFAULT 0,
            questions_correct INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (user_id, domain_id),
            FOREIGN KEY (user_id)
                REFERENCES users (id),
            FOREIGN KEY (domain_id)
                REFERENCES domains (id)
        )
        """
    )

    # Per-user campaign settings.
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS user_settings (
            user_id INTEGER NOT NULL,
            key TEXT NOT NULL,
            value TEXT,
            PRIMARY KEY (user_id, key),
            FOREIGN KEY (user_id)
                REFERENCES users (id)
        )
        """
    )

    # =========================================================
    # ASSESSMENTS
    # =========================================================

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_type TEXT NOT NULL,
            source TEXT NOT NULL,
            domain_id INTEGER,
            questions_answered INTEGER NOT NULL,
            questions_correct INTEGER NOT NULL,
            knowledge_misses INTEGER NOT NULL DEFAULT 0,
            interpretation_misses INTEGER NOT NULL DEFAULT 0,
            mindset_misses INTEGER NOT NULL DEFAULT 0,
            minutes_spent INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            assessment_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (domain_id)
                REFERENCES domains (id)
        )
        """
    )

    add_column_if_missing(
        connection,
        "assessments",
        "certification",
        "TEXT NOT NULL DEFAULT 'CISSP'",
    )

    add_column_if_missing(
        connection,
        "assessments",
        "user_id",
        "INTEGER",
    )

    # =========================================================
    # MIXED ASSESSMENT DOMAIN RESULTS
    # =========================================================

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_domain_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL,
            domain_id INTEGER NOT NULL,
            questions_answered INTEGER NOT NULL,
            questions_correct INTEGER NOT NULL,
            FOREIGN KEY (assessment_id)
                REFERENCES assessments (id),
            FOREIGN KEY (domain_id)
                REFERENCES domains (id)
        )
        """
    )

    # =========================================================
    # STUDY SESSIONS
    # =========================================================

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS study_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER,
            resource TEXT,
            minutes_studied INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            session_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (domain_id)
                REFERENCES domains (id)
        )
        """
    )

    add_column_if_missing(
        connection,
        "study_sessions",
        "certification",
        "TEXT NOT NULL DEFAULT 'CISSP'",
    )

    add_column_if_missing(
        connection,
        "study_sessions",
        "resource",
        "TEXT",
    )

    add_column_if_missing(
        connection,
        "study_sessions",
        "minutes_studied",
        "INTEGER NOT NULL DEFAULT 0",
    )

    add_column_if_missing(
        connection,
        "study_sessions",
        "notes",
        "TEXT",
    )

    add_column_if_missing(
        connection,
        "study_sessions",
        "user_id",
        "INTEGER",
    )

    # =========================================================
    # WEAK TOPICS
    # =========================================================

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS weak_topics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER NOT NULL,
            topic TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            resolved_at TEXT,
            FOREIGN KEY (domain_id)
                REFERENCES domains (id)
        )
        """
    )

    add_column_if_missing(
        connection,
        "weak_topics",
        "certification",
        "TEXT NOT NULL DEFAULT 'CISSP'",
    )

    add_column_if_missing(
        connection,
        "weak_topics",
        "user_id",
        "INTEGER",
    )

    # =========================================================
    # HISTORICAL EXAM ATTEMPTS
    # =========================================================

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS certification_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            certification TEXT NOT NULL,
            attempt_period TEXT NOT NULL,
            overall_score INTEGER NOT NULL,
            result TEXT NOT NULL,
            user_id INTEGER
        )
        """
    )

    add_column_if_missing(
        connection,
        "certification_attempts",
        "user_id",
        "INTEGER",
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS attempt_domain_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attempt_id INTEGER NOT NULL,
            domain_id INTEGER NOT NULL,
            scaled_score INTEGER NOT NULL,
            FOREIGN KEY (attempt_id)
                REFERENCES certification_attempts (id),
            FOREIGN KEY (domain_id)
                REFERENCES domains (id)
        )
        """
    )

    # Legacy table retained only to migrate v1.1 settings.
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )

    legacy_defaults = [
        ("cism_exam_date", "2026-09-25"),
        ("cissp_exam_date", ""),
        ("weekly_hour_target", "10"),
    ]

    connection.executemany(
        """
        INSERT OR IGNORE INTO settings (
            key,
            value
        )
        VALUES (?, ?)
        """,
        legacy_defaults,
    )

    # =========================================================
    # V1.2 MIGRATION
    # =========================================================

    admin_user_id = ensure_admin_user(connection)

    migrate_existing_data_to_admin(
        connection,
        admin_user_id,
    )

    all_users = connection.execute(
        """
        SELECT id
        FROM users
        """
    ).fetchall()

    for user in all_users:
        ensure_user_defaults(
            connection,
            user["id"],
        )

    connection.commit()
    connection.close()


if __name__ == "__main__":
    initialize_database()

    print(
        f"Database initialized at: {DATABASE_PATH}"
    )
