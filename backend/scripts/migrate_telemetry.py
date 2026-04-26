import sys
import os
from pathlib import Path
from dotenv import load_dotenv
from sqlalchemy import text

# Add backend to path and load env from THREE levels up
project_root = Path(__file__).parent.parent.parent
load_dotenv(project_root / ".env")
sys.path.append(os.path.join(project_root, 'backend'))

from database import engine

def migrate():
    print("Checking database schema for AuditLog...")
    with engine.connect() as conn:
        # Check if column exists
        result = conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='audit_logs' AND column_name='challenge_latency_ms'"))
        exists = result.fetchone()
        
        if not exists:
            print("Adding 'challenge_latency_ms' column to 'audit_logs' table...")
            conn.execute(text("ALTER TABLE audit_logs ADD COLUMN challenge_latency_ms FLOAT DEFAULT 0.0"))
            # Also ensure latency_ms is FLOAT (was Integer in previous model)
            conn.execute(text("ALTER TABLE audit_logs ALTER COLUMN latency_ms TYPE FLOAT"))
            conn.commit()
            print("Migration successful.")
        else:
            print("'challenge_latency_ms' column already exists.")

if __name__ == "__main__":
    migrate()
