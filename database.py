"""SQLite storage for users and syllabus items."""

import os
import sqlite3
from datetime import datetime

from auth import hash_password, is_hashed_password, verify_password


class SyllabusDB:
    """Provide the database operations used by the application."""

    ALLOWED_COLUMNS = {
        "details", "date", "time", "status", "started_at",
        "completed_at", "submission", "type", "subject"
    }

    def __init__(self, path=None):
        if path is None:
            base = os.path.dirname(os.path.abspath(__file__))
            path = os.path.join(base, "syllabus.db")
        self.path = path
        self.conn = sqlite3.connect(
            self.path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
        )
        self.conn.row_factory = sqlite3.Row
        self._migrate_table()

    def _migrate_table(self):
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS syllabus_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                details TEXT NOT NULL,
                date TEXT,
                time TEXT,
                created_at TEXT,
                status TEXT DEFAULT 'pending',
                started_at TEXT,
                completed_at TEXT,
                type TEXT DEFAULT 'topic',
                subject TEXT,
                submission TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)
        self.conn.commit()

        cur.execute("PRAGMA table_info(syllabus_items)")
        columns = {row["name"] for row in cur.fetchall()}
        missing_columns = (
            ("type", "ALTER TABLE syllabus_items ADD COLUMN type TEXT DEFAULT 'topic'"),
            ("subject", "ALTER TABLE syllabus_items ADD COLUMN subject TEXT"),
            ("submission", "ALTER TABLE syllabus_items ADD COLUMN submission TEXT"),
        )
        for column_name, statement in missing_columns:
            if column_name not in columns:
                try:
                    cur.execute(statement)
                except sqlite3.OperationalError:
                    pass

        cur.execute("SELECT id, password FROM users WHERE password NOT LIKE '%$%'")
        for user in cur.fetchall():
            cur.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (hash_password(user["password"]), user["id"]),
            )
        self.conn.commit()

    def add_user(self, email, password, role):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO users (email, password, role) VALUES (?, ?, ?)",
            (email, hash_password(password), role),
        )
        self.conn.commit()

    def get_user(self, email, password):
        cur = self.conn.cursor()
        cur.execute("SELECT password, role FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        if not row:
            return None

        stored_password = row["password"]
        if is_hashed_password(stored_password) and verify_password(password, stored_password):
            return row["role"]
        if not is_hashed_password(stored_password) and password == stored_password:
            upgraded_hash = hash_password(password)
            self.conn.execute(
                "UPDATE users SET password = ? WHERE email = ?",
                (upgraded_hash, email),
            )
            self.conn.commit()
            return row["role"]
        return None

    def add_item(self, details, date_iso, time_hm, item_type, subject):
        created = datetime.utcnow().isoformat() + "Z"
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO syllabus_items (details, date, time, created_at, status, type, subject) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (details, date_iso, time_hm, created, "pending", item_type, subject),
        )
        self.conn.commit()
        return cur.lastrowid

    def list_items(self):
        return self.conn.execute("SELECT * FROM syllabus_items").fetchall()

    def get_item(self, item_id):
        return self.conn.execute(
            "SELECT * FROM syllabus_items WHERE id = ?", (item_id,)
        ).fetchone()

    def delete_item(self, item_id):
        self.conn.execute("DELETE FROM syllabus_items WHERE id = ?", (item_id,))
        self.conn.commit()

    def update_item(self, item_id, **fields):
        if not fields:
            return
        invalid_columns = set(fields) - self.ALLOWED_COLUMNS
        if invalid_columns:
            raise ValueError(f"Invalid column names: {', '.join(sorted(invalid_columns))}")
        assignments = ", ".join(f"{key} = ?" for key in fields)
        values = list(fields.values()) + [item_id]
        self.conn.execute(
            f"UPDATE syllabus_items SET {assignments} WHERE id = ?", values
        )
        self.conn.commit()

    def close(self):
        self.conn.commit()
        self.conn.close()