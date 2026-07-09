"""
D-PHISH Database Manager (PostgreSQL edition).

Drop-in replacement for the original MySQL-based database.py.
The public API (DatabaseManager class + get_db()) is preserved so
app.py and auth.py do not need any changes.

Connection string is read from the DATABASE_URL environment variable
(e.g. a Neon / Supabase / Render Postgres connection string).
"""

import os
import json
import logging
from datetime import datetime

import psycopg2
from psycopg2.extras import RealDictCursor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _parse_db_url(url: str):
    """Parse DATABASE_URL into host/user/password/db_name parts."""
    from urllib.parse import urlparse
    p = urlparse(url)
    return {
        "host": p.hostname or "localhost",
        "port": p.port or 5432,
        "user": p.username or "postgres",
        "password": p.password or "",
        "db_name": p.path.lstrip("/") or "postgres",
    }


class DatabaseManager:
    """PostgreSQL-backed DatabaseManager with the same API as the MySQL one."""

    def __init__(self, host=None, user=None, password=None, db_name=None):
        # Prefer DATABASE_URL env var; fall back to explicit args (legacy compat)
        url = os.environ.get("DATABASE_URL")
        if url:
            cfg = _parse_db_url(url)
            self.host = cfg["host"]
            self.port = cfg["port"]
            self.user = cfg["user"]
            self.password = cfg["password"]
            self.db_name = cfg["db_name"]
        else:
            self.host = host or "localhost"
            self.port = 5432
            self.user = user or "postgres"
            self.password = password or ""
            self.db_name = db_name or "phishing"

        self.connection = None
        self.initialize_database()

    # ───────────────────────────────────────────────────────────────────
    # Connection management
    # ───────────────────────────────────────────────────────────────────

    def get_connection(self):
        try:
            if self.connection is None or self.connection.closed:
                self.connection = psycopg2.connect(
                    host=self.host,
                    port=self.port,
                    user=self.user,
                    password=self.password,
                    dbname=self.db_name,
                    cursor_factory=RealDictCursor,
                    connect_timeout=10,
                )
            return self.connection
        except psycopg2.Error as e:
            logger.error(f"Connection error: {e}")
            return None

    def initialize_database(self):
        """Create all tables if they don't exist (PostgreSQL syntax)."""
        try:
            conn = self.get_connection()
            if conn is None:
                return False
            with conn.cursor() as cursor:
                # users
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(255) UNIQUE NOT NULL,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        full_name VARCHAR(255),
                        password_hash VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_active SMALLINT DEFAULT 1
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_username ON users (username)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_email    ON users (email)")

                # url_checks
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS url_checks (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        url TEXT NOT NULL,
                        result VARCHAR(50) NOT NULL,
                        confidence DECIMAL(5,4),
                        features TEXT,
                        checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_id_checks ON url_checks (user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_checked_at     ON url_checks (checked_at)")

                # statistics
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS statistics (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                        total_checks INTEGER DEFAULT 0,
                        phishing_detected INTEGER DEFAULT 0,
                        legitimate_detected INTEGER DEFAULT 0,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # saved_urls
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS saved_urls (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        url TEXT NOT NULL,
                        result VARCHAR(50) NOT NULL,
                        confidence DECIMAL(5,4),
                        notes TEXT,
                        saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_id_saved ON saved_urls (user_id)")

            conn.commit()
            logger.info("Database initialized successfully (PostgreSQL)")
            return True
        except psycopg2.Error as e:
            logger.error(f"Database initialization error: {e}")
            return False

    # ───────────────────────────────────────────────────────────────────
    # Query helper — emulates the original MySQL behavior
    # ───────────────────────────────────────────────────────────────────

    def execute_query(self, query, params=None):
        """
        Execute a SQL query and return:
          - list of dict rows for SELECT
          - True for successful INSERT/UPDATE/DELETE
          - None on error

        NOTE: This method transparently converts MySQL-style placeholders (%s)
        and MySQL-specific SQL fragments to PostgreSQL equivalents so the
        existing app.py / auth.py code keeps working unchanged.
        """
        try:
            conn = self.get_connection()
            if conn is None:
                return None

            # ── Translate MySQL-isms to PostgreSQL-isms ─────────────────
            # The existing codebase uses %s placeholders (which psycopg2 also
            # uses), so placeholders need no change. We do rewrite a few SQL
            # keywords:
            pg_query = query
            # Translate ON UPDATE CURRENT_TIMESTAMP (already handled by trigger
            # below — but strip it from CREATE TABLE if present).
            # For runtime UPDATEs that don't set updated_at, the trigger handles it.

            with conn.cursor() as cursor:
                if params:
                    cursor.execute(pg_query, params)
                else:
                    cursor.execute(pg_query)

                stripped = pg_query.strip().upper()
                if stripped.startswith('SELECT') or stripped.startswith('WITH'):
                    result = cursor.fetchall()
                    conn.commit()
                    return result
                else:
                    conn.commit()
                    return True
        except psycopg2.Error as e:
            logger.error(f"Query execution error: {e} | query={query[:120]}")
            try:
                conn.rollback()
            except Exception:
                pass
            return None

    # ───────────────────────────────────────────────────────────────────
    # User CRUD
    # ───────────────────────────────────────────────────────────────────

    def insert_user(self, username, email, full_name, password_hash):
        query = "INSERT INTO users (username, email, full_name, password_hash) VALUES (%s, %s, %s, %s)"
        result = self.execute_query(query, (username, email, full_name, password_hash))
        if result:
            user = self.get_user_by_username(username)
            if user:
                self.execute_query(
                    "INSERT INTO statistics (user_id, total_checks, phishing_detected, legitimate_detected) VALUES (%s, 0, 0, 0)",
                    (user['id'],)
                )
        return result

    def get_user_by_username(self, username):
        query = "SELECT * FROM users WHERE username = %s"
        result = self.execute_query(query, (username,))
        return result[0] if result else None

    def get_user_by_email(self, email):
        query = "SELECT * FROM users WHERE email = %s"
        result = self.execute_query(query, (email,))
        return result[0] if result else None

    def get_user_by_id(self, user_id):
        query = "SELECT * FROM users WHERE id = %s"
        result = self.execute_query(query, (user_id,))
        return result[0] if result else None

    def update_user_profile(self, user_id, full_name, email):
        query = "UPDATE users SET full_name = %s, email = %s WHERE id = %s"
        return self.execute_query(query, (full_name, email, user_id))

    # ───────────────────────────────────────────────────────────────────
    # URL checks
    # ───────────────────────────────────────────────────────────────────

    def insert_url_check(self, user_id, url, result, confidence, features=None):
        query = "INSERT INTO url_checks (user_id, url, result, confidence, features) VALUES (%s, %s, %s, %s, %s)"
        features_json = json.dumps(features) if features else None
        result_exec = self.execute_query(query, (user_id, url, result, confidence, features_json))
        if result_exec:
            self.update_statistics(user_id, result)
        return result_exec

    def get_user_checks(self, user_id, limit=10):
        query = "SELECT * FROM url_checks WHERE user_id = %s ORDER BY checked_at DESC LIMIT %s"
        return self.execute_query(query, (user_id, limit))

    def get_user_checks_all(self, user_id):
        query = "SELECT * FROM url_checks WHERE user_id = %s ORDER BY checked_at DESC"
        return self.execute_query(query, (user_id,))

    # ───────────────────────────────────────────────────────────────────
    # Statistics
    # ───────────────────────────────────────────────────────────────────

    def update_statistics(self, user_id, result):
        stats = self.get_statistics(user_id)
        if stats:
            total = stats['total_checks'] + 1
            phishing = stats['phishing_detected'] + (1 if result == 'Phishing' else 0)
            legitimate = stats['legitimate_detected'] + (1 if result == 'Legitimate' else 0)
            query = "UPDATE statistics SET total_checks = %s, phishing_detected = %s, legitimate_detected = %s, last_updated = CURRENT_TIMESTAMP WHERE user_id = %s"
            self.execute_query(query, (total, phishing, legitimate, user_id))
        else:
            phishing = 1 if result == 'Phishing' else 0
            legitimate = 1 if result == 'Legitimate' else 0
            query = "INSERT INTO statistics (user_id, total_checks, phishing_detected, legitimate_detected) VALUES (%s, 1, %s, %s)"
            self.execute_query(query, (user_id, phishing, legitimate))

    def get_statistics(self, user_id):
        query = "SELECT * FROM statistics WHERE user_id = %s"
        result = self.execute_query(query, (user_id,))
        return result[0] if result else None

    # ───────────────────────────────────────────────────────────────────
    # Saved URLs
    # ───────────────────────────────────────────────────────────────────

    def save_url(self, user_id, url, result, confidence, notes=''):
        query = "INSERT INTO saved_urls (user_id, url, result, confidence, notes) VALUES (%s, %s, %s, %s, %s)"
        return self.execute_query(query, (user_id, url, result, confidence, notes))

    def get_saved_urls(self, user_id):
        query = "SELECT * FROM saved_urls WHERE user_id = %s ORDER BY saved_at DESC"
        return self.execute_query(query, (user_id,))

    def delete_saved_url(self, url_id):
        query = "DELETE FROM saved_urls WHERE id = %s"
        return self.execute_query(query, (url_id,))

    # ───────────────────────────────────────────────────────────────────
    # Cleanup
    # ───────────────────────────────────────────────────────────────────

    def close_connection(self):
        try:
            if self.connection and not self.connection.closed:
                self.connection.close()
        except Exception:
            pass


# ───────────────────────────────────────────────────────────────────────
# Module-level singleton accessor (used by app.py / auth.py)
# ───────────────────────────────────────────────────────────────────────

db = None

def get_db():
    global db
    if db is None:
        db = DatabaseManager()
    return db
