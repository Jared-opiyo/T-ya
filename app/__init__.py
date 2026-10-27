import os
from contextlib import closing
from datetime import timedelta

import click
from flask import Flask

from config import Config
from app.database import connect_database, using_postgresql


def create_app():
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
    )

    app.config.from_object(Config)
    app.config["DATABASE_PATH"].parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Safer browser-session defaults.
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = (
        os.environ.get("TYA_COOKIE_SECURE", "0") == "1"
    )
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

    from app.routes.public import public_bp
    from app.routes.auth import auth_bp
    from app.routes.admin import admin_bp
    from app.routes.payments import payments_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(payments_bp)

    @app.cli.command("init-db")
    def init_db():
        """Initialize the configured SQLite or PostgreSQL schema."""
        postgres = using_postgresql()
        database_path = app.config["DATABASE_PATH"]

        schema_name = (
            "schema_postgresql.sql" if postgres else "schema.sql"
        )
        schema_path = (
            app.config["SCHEMA_PATH"].parent / schema_name
        )
        with open(schema_path, "r", encoding="utf-8-sig") as schema_file:
            schema_text = schema_file.read()

        with closing(connect_database(database_path)) as connection:
            connection.executescript(schema_text)
            connection.commit()

        backend = "PostgreSQL" if postgres else "SQLite"
        click.echo(f"{backend} database initialized successfully.")

    return app
