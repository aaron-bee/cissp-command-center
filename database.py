import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "data" / "cissp.db"


DOMAINS = [
    (1, "Security & Risk Management", 16),
    (2, "Asset Security", 10),
    (3, "Security Architecture & Engineering", 13),
    (4, "Communication & Network Security", 13),
    (5, "Identity & Access Management", 13),
    (6, "Security Assessment & Testing", 12),
    (7, "Security Operations", 13),
    (8, "Software Development Security", 10),
]


def get_db_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def column_exists(connection, table, column):
    columns = connection.execute(
        f"PRAGMA table_info({table})"
    ).fetchall()

    return any(row["name"] == column for row in columns)


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

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS study_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER NOT NULL,
            questions_answered INTEGER NOT NULL DEFAULT 0,
            questions_correct INTEGER NOT NULL DEFAULT 0,
            knowledge_misses INTEGER NOT NULL DEFAULT 0,
            interpretation_misses INTEGER NOT NULL DEFAULT 0,
            mindset_misses INTEGER NOT NULL DEFAULT 0,
            minutes_studied INTEGER NOT NULL DEFAULT 0,
            resource TEXT,
            notes TEXT,
            session_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (domain_id) REFERENCES domains (id)
        )
        """
    )

    # Migration support for databases created during earlier builds.
    migrations = [
        ("knowledge_misses", "INTEGER NOT NULL DEFAULT 0"),
        ("interpretation_misses", "INTEGER NOT NULL DEFAULT 0"),
        ("mindset_misses", "INTEGER NOT NULL DEFAULT 0"),
        ("minutes_studied", "INTEGER NOT NULL DEFAULT 0"),
        ("resource", "TEXT"),
        ("notes", "TEXT"),
    ]

    for column, definition in migrations:
        if not column_exists(connection, "study_sessions", column):
            connection.execute(
                f"ALTER TABLE study_sessions ADD COLUMN {column} {definition}"
            )

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

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )

    connection.executemany(
        """
        INSERT OR IGNORE INTO domains (id, name, weight)
        VALUES (?, ?, ?)
        """,
        DOMAINS,
    )

    default_settings = [
        ("cism_exam_date", "2026-09-25"),
        ("cissp_exam_date", ""),
        ("phase", "CISM"),
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