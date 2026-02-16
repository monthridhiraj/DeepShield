"""
Feedback Database Module
Handles storage of user feedback for RL-Lite (Active Learning)
"""

import sqlite3
import datetime
from pathlib import Path
from urllib.parse import urlparse

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

def get_whitelisted_domains():
    """Get list of domains user marked as safe"""
    try:
        feedback = get_all_feedback()
        safe_domains = set()
        
        for item in feedback:
            if item['verdict'] == 'safe':
                try:
                    # Extract domain from URL
                    parsed = urlparse(item['url'])
                    domain = parsed.netloc.lower().replace('www.', '')
                    if domain:
                        safe_domains.add(domain)
                except:
                    continue
                    
        return list(safe_domains)
    except Exception as e:
        print(f"[ERROR] Failed to get whitelist: {e}")
        return []

def get_feedback_stats():
    """Get statistics about collected feedback for RL monitoring"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM feedback")
        total = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM feedback WHERE verdict='safe'")
        safe_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM feedback WHERE verdict='phishing'")
        phishing_count = cursor.fetchone()[0]
        
        conn.close()
        return {
            "total_samples": total,
            "safe_samples": safe_count,
            "phishing_samples": phishing_count
        }
    except Exception as e:
        print(f"[ERROR] Failed to get stats: {e}")
        return {"total_samples": 0, "safe_samples": 0, "phishing_samples": 0}

if __name__ == "__main__":
    init_db()
