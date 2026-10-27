import os
import re
import sqlite3
from pathlib import Path
from urllib.parse import urlparse

import psycopg


def database_url():
    """Return a normalized PostgreSQL URL, or None for SQLite."""
    value = os.environ.get("DATABASE_URL", "").strip()

    if not value:
        return None

    if value.startswith("postgres://"):
        value = "postgresql://" + value[len("postgres://"):]

    parsed = urlparse(value)
    if parsed.scheme not in ("postgresql", "postgres"):
        raise ValueError(
            "DATABASE_URL must use a PostgreSQL connection URL."
        )

    return value


def using_postgresql():
    return database_url() is not None


def integrity_error_types():
    """Return integrity-error classes for the configured backend."""
    if using_postgresql():
        return (psycopg.IntegrityError,)
    return (sqlite3.IntegrityError,)


def inserted_id(cursor, backend=None):
    """Return the generated ID from an INSERT cursor."""
    if backend is None:
        backend = "postgresql" if using_postgresql() else "sqlite"

    if backend == "postgresql":
        row = cursor.fetchone()
        if row is None:
            raise RuntimeError(
                "The INSERT did not return an ID. "
                "Use INSERT ... RETURNING id."
            )
        return row["id"]

    return cursor.lastrowid


class HybridRow(tuple):
    """Support both row['column'] and row[index] access."""

    def __new__(cls, values, columns):
        instance = super().__new__(cls, values)
        instance._columns = tuple(columns)
        instance._column_indexes = {
            name: index for index, name in enumerate(columns)
        }
        return instance

    def __getitem__(self, key):
        if isinstance(key, str):
            key = self._column_indexes[key]
        return super().__getitem__(key)

    def keys(self):
        return self._columns


def hybrid_row_factory(cursor):
    """Build PostgreSQL rows compatible with sqlite3.Row access."""
    columns = [column.name for column in cursor.description]

    def make_row(values):
        return HybridRow(values, columns)

    return make_row


def translate_sql(sql):
    """Translate the SQLite-specific SQL syntax used by this project."""
    sql = sql.strip()

    if re.match(r"^PRAGMA\s+foreign_keys\s*=\s*ON\s*;?$", sql, re.I):
        return None

    if re.match(r"^BEGIN\s+IMMEDIATE\s*;?$", sql, re.I):
        return "BEGIN"

    # Replace SQL parameter markers outside quoted strings and comments.
    result = []
    i = 0
    quote = None
    while i < len(sql):
        char = sql[i]

        if quote:
            result.append(char)
            if char == quote:
                if i + 1 < len(sql) and sql[i + 1] == quote:
                    result.append(sql[i + 1])
                    i += 1
                else:
                    quote = None
            elif char == "\\" and quote == "'":
                if i + 1 < len(sql):
                    result.append(sql[i + 1])
                    i += 1
            i += 1
            continue

        if char in ("'", '"'):
            quote = char
            result.append(char)
            i += 1
            continue

        if sql.startswith("--", i):
            result.append(sql[i:])
            break

        if char == "?":
            result.append("%s")
        else:
            result.append(char)
        i += 1

    return "".join(result)


class DatabaseConnection:
    """Small compatibility wrapper around SQLite and PostgreSQL."""

    def __init__(self, connection, backend):
        self._connection = connection
        self.backend = backend

    @property
    def row_factory(self):
        return self._connection.row_factory if self.backend == "sqlite" else None

    @row_factory.setter
    def row_factory(self, value):
        if self.backend == "sqlite":
            self._connection.row_factory = value

    def execute(self, sql, parameters=()):
        if self.backend == "sqlite":
            return self._connection.execute(sql, parameters)

        translated = translate_sql(sql)
        if translated is None:
            return self._connection.execute("SELECT 1 WHERE FALSE")

        return self._connection.execute(translated, parameters)

    def executescript(self, script):
        if self.backend == "sqlite":
            return self._connection.executescript(script)

        cursor = None
        for statement in script.split(";"):
            statement = statement.strip()
            if statement:
                cursor = self._connection.execute(statement, prepare=False)
        return cursor

    def commit(self):
        return self._connection.commit()

    def rollback(self):
        return self._connection.rollback()

    def close(self):
        return self._connection.close()

    def __enter__(self):
        self._connection.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self._connection.__exit__(exc_type, exc_value, traceback)


def connect_database(database_path):
    """Open the configured PostgreSQL or SQLite database."""
    url = database_url()

    if url:
        connection = psycopg.connect(
            url,
            row_factory=hybrid_row_factory,
        )
        return DatabaseConnection(connection, "postgresql")

    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return DatabaseConnection(connection, "sqlite")
