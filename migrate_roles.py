import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "instance" / "tya.db"

def main():
    if not DB_PATH.exists():
        raise FileNotFoundError(f"Database not found: {DB_PATH}")

    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(users)")
        }

        if not columns:
            raise RuntimeError(
                "The users table was not found. No changes were made."
            )

        if "role" in columns:
            print("The users table already has a role column.")
            print("No database changes were needed.")
            return

        connection.execute("BEGIN IMMEDIATE")

        connection.execute("""
            ALTER TABLE users
            ADD COLUMN role TEXT NOT NULL DEFAULT 'member'
            CHECK (role IN ('member', 'admin'))
        """)

        connection.commit()

        print("Migration completed successfully.")
        print("Existing accounts retain their data.")
        print("Existing accounts default to the member role.")

if __name__ == "__main__":
    main()
