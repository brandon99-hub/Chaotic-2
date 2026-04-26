import sys
import os

# Append project root to path for absolute imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from sqlalchemy import text
from backend.database import engine

def main():
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS latency_ms INTEGER;"))
            conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS security_check JSON;"))
            print("\033[32m[Success]\033[0m Re-applied missing 'latency_ms' and 'security_check' columns to PostgreSQL audit_logs table!")
    except Exception as e:
        print(f"\033[31m[ERROR]\033[0m Failed to patch database: {e}")

if __name__ == '__main__':
    main()
