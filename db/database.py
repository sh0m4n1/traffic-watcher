import sqlite3
from datetime import datetime

DB_NAME = "traffic_watcher.db"

def get_connection():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # جدول الترافيك
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            length INTEGER
        )
    """)

    # جدول التنبيهات
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            alert_type TEXT,
            details TEXT
        )
    """)

    conn.commit()
    conn.close()

def insert_traffic(pkt):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO traffic (
            timestamp, src_ip, dst_ip,
            src_port, dst_port, protocol, length
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        pkt.get("src_ip"),
        pkt.get("dst_ip"),
        pkt.get("src_port"),
        pkt.get("dst_port"),
        pkt.get("protocol"),
        pkt.get("length")
    ))

    conn.commit()
    conn.close()

def insert_alert(alert):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            timestamp, src_ip, alert_type, details
        ) VALUES (?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        alert.get("src_ip"),
        alert.get("alert"),
        f"Ports scanned: {alert.get('ports')} in {alert.get('window')}s"
    ))

    conn.commit()
    conn.close()
