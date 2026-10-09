import sqlite3
import datetime

DB_NAME = "cyber_shield.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            target_evidence TEXT,
            risk_score TEXT,
            verdict TEXT,
            message_excerpt TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_scan(target_evidence: str, risk_score: str, verdict: str, message: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    excerpt = message[:60] + "..." if len(message) > 60 else message
    
    cursor.execute("""
        INSERT INTO scan_logs (timestamp, target_evidence, risk_score, verdict, message_excerpt)
        VALUES (?, ?, ?, ?, ?)
    """, (timestamp, target_evidence or "N/A", risk_score, verdict, excerpt))
    conn.commit()
    conn.close()

def get_recent_scans(limit=5):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, target_evidence, risk_score, verdict, message_excerpt 
        FROM scan_logs 
        ORDER BY id DESC 
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows
