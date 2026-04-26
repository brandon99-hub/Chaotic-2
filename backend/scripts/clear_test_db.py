import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from sqlalchemy import text

# Add backend to path and load env from THREE levels up
project_root = Path(__file__).parent.parent.parent
load_dotenv(project_root / ".env")
sys.path.append(os.path.join(project_root, 'backend'))

from database import engine

def clear_db():
    print("WARNING: This will delete ALL users, devices, and audit logs from the database.")
    confirm = input("Are you sure you want to proceed? (y/N): ")
    
    if confirm.lower() != 'y':
        print("Operation cancelled.")
        return

    print("Connecting to database...")
    with engine.connect() as conn:
        print("Deleting records (respecting constraints)...")
        # Delete in order of dependency
        conn.execute(text("DELETE FROM audit_logs"))
        conn.execute(text("DELETE FROM devices"))
        conn.execute(text("DELETE FROM users"))
        conn.commit()
        print("Done. Database is now empty and ready for fresh registration.")

if __name__ == "__main__":
    clear_db()
