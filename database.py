import os
import sqlite3
from pathlib import Path


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
    connection = sqlite3.connect(DATABASE_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def column_exists(connection, table_name, column_name):
    columns = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(column["name"] == column_name for column in columns)


def add_column_if_missing(connection, table_name, column_name, definition):
    if not column_exists(connection, table_name, column_name):
        connection.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"
        )


def initialize_database():
    DATABASE_PATH.parent.mkdir(exist_ok=True)
    connection = get_db_connection()

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
        connection, "domains", "certification", "TEXT NOT NULL DEFAULT 'CISSP'"
    )
    add_column_if_missing(connection, "domains", "domain_number", "INTEGER")

    for domain_id, domain_number, certification, name, weight in (
        CISSP_DOMAINS + CISM_DOMAINS
    ):
        connection.execute(
            """
            INSERT OR IGNORE INTO domains (
                id, domain_number, certification, name, weight
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (domain_id, domain_number, certification, name, weight),
        )
        connection.execute(
            """
            UPDATE domains
            SET domain_number = ?, certification = ?, name = ?, weight = ?
            WHERE id = ?
            """,
            (domain_number, certification, name, weight, domain_id),
        )

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
            FOREIGN KEY (domain_id) REFERENCES domains (id)
        )
        """
    )

    add_column_if_missing(
        connection,
        "assessments",
        "certification",
        "TEXT NOT NULL DEFAULT 'CISSP'",
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_domain_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL,
            domain_id INTEGER NOT NULL,
            questions_answered INTEGER NOT NULL,
            questions_correct INTEGER NOT NULL,
            FOREIGN KEY (assessment_id) REFERENCES assessments (id),
            FOREIGN KEY (domain_id) REFERENCES domains (id)
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS study_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER,
            resource TEXT,
            minutes_studied INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            session_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (domain_id) REFERENCES domains (id)
        )
        """
    )

    add_column_if_missing(
        connection,
        "study_sessions",
        "certification",
        "TEXT NOT NULL DEFAULT 'CISSP'",
    )
    add_column_if_missing(connection, "study_sessions", "resource", "TEXT")
    add_column_if_missing(
        connection,
        "study_sessions",
        "minutes_studied",
        "INTEGER NOT NULL DEFAULT 0",
    )
    add_column_if_missing(connection, "study_sessions", "notes", "TEXT")

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS weak_topics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER NOT NULL,
            topic TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            resolved_at TEXT,
            FOREIGN KEY (domain_id) REFERENCES domains (id)
        )
        """
    )

    add_column_if_missing(
        connection,
        "weak_topics",
        "certification",
        "TEXT NOT NULL DEFAULT 'CISSP'",
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS certification_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            certification TEXT NOT NULL,
            attempt_period TEXT NOT NULL,
            overall_score INTEGER NOT NULL,
            result TEXT NOT NULL,
            UNIQUE(certification, attempt_period)
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS attempt_domain_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attempt_id INTEGER NOT NULL,
            domain_id INTEGER NOT NULL,
            scaled_score INTEGER NOT NULL,
            FOREIGN KEY (attempt_id) REFERENCES certification_attempts (id),
            FOREIGN KEY (domain_id) REFERENCES domains (id),
            UNIQUE(attempt_id, domain_id)
        )
        """
    )

    connection.execute(
        """
        INSERT OR IGNORE INTO certification_attempts (
            certification, attempt_period, overall_score, result
        )
        VALUES (?, ?, ?, ?)
        """,
        ("CISM", "February 2026", 402, "Did Not Pass"),
    )

    attempt = connection.execute(
        """
        SELECT id
        FROM certification_attempts
        WHERE certification = 'CISM'
          AND attempt_period = 'February 2026'
        """
    ).fetchone()

    if attempt:
        historical_results = [
            (attempt["id"], 101, 372),
            (attempt["id"], 102, 426),
            (attempt["id"], 103, 432),
            (attempt["id"], 104, 372),
        ]
        connection.executemany(
            """
            INSERT OR IGNORE INTO attempt_domain_results (
                attempt_id, domain_id, scaled_score
            )
            VALUES (?, ?, ?)
            """,
            historical_results,
        )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )

    default_settings = [
        ("cism_exam_date", "2026-09-25"),
        ("cissp_exam_date", ""),
        ("weekly_hour_target", "10"),
    ]

    connection.executemany(
        """
        INSERT OR IGNORE INTO settings (key, value)
        VALUES (?, ?)
        """,
        default_settings,
    )

    connection.commit()
    connection.close()


if __name__ == "__main__":
    initialize_database()
    print(f"Database initialized at: {DATABASE_PATH}")
