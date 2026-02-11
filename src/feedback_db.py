"""
Feedback Database Module
Handles storage of user feedback for RL-Lite (Active Learning)
"""

import sqlite3
import datetime
from pathlib import Path

# Database path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "feedback.db"

def init_db():
    """Initialize the feedback database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create feedback table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            verdict TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print(f"[INFO] Feedback database initialized at {DB_PATH}")

def add_feedback(url: str, verdict: str):
    """Add user feedback to database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO feedback (url, verdict) VALUES (?, ?)",
            (url, verdict)
        )
        
        conn.commit()
        conn.close()
        print(f"[INFO] Feedback added: {url} -> {verdict}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to add feedback: {e}")
        return False

def get_all_feedback():
    """Retrieve all feedback for retraining"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM feedback")
        rows = cursor.fetchall()
        
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        print(f"[ERROR] Failed to retrieve feedback: {e}")
        return []

if __name__ == "__main__":
    init_db()
