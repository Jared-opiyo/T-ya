import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-this-key")
    DATABASE_PATH = Path(
        os.environ.get("TYA_DATABASE", str(INSTANCE_DIR / "tya.db"))
    )
    SCHEMA_PATH = BASE_DIR / "database" / "schema.sql"
