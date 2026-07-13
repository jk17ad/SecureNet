import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get(
    "SECURENET_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "securenet.db"),
)

def get_db_connection():
    db_directory = os.path.dirname(DB_PATH)
    if db_directory:
        os.makedirs(db_directory, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
    )
    """)
    
    # Create URL History table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS url_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        prediction TEXT NOT NULL CHECK(prediction IN ('Safe', 'Malicious')),
        confidence REAL NOT NULL,
        scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)
    
    # Create Threats table (for Network scans and alert logging)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_type TEXT NOT NULL,
        source_ip TEXT,
        destination_ip TEXT,
        severity TEXT NOT NULL CHECK(severity IN ('Low', 'Medium', 'High')),
        confidence REAL NOT NULL,
        scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)
    
    # Create Reports table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_name TEXT NOT NULL,
        report_type TEXT NOT NULL CHECK(report_type IN ('PDF', 'CSV')),
        generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        file_path TEXT NOT NULL
    )
    """)
    
    # Seed default users if they do not exist
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        admin_hash = generate_password_hash("admin123", method="pbkdf2:sha256")
        user_hash = generate_password_hash("user123", method="pbkdf2:sha256")
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ("admin", admin_hash, "admin"))
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ("user", user_hash, "user"))
        
        # Seed some dummy threat history to make dashboard populate initially with data
        cursor.execute("""
        INSERT INTO url_history (url, prediction, confidence, scan_time, user_id) VALUES
        ('https://google.com', 'Safe', 0.99, '2026-07-10 10:00:00', 1),
        ('http://malicious-login-update-free.temp/login', 'Malicious', 0.88, '2026-07-11 11:30:00', 1),
        ('https://github.com', 'Safe', 0.98, '2026-07-12 09:15:00', 2),
        ('http://secure-bank-verify.xyz/signin', 'Malicious', 0.95, '2026-07-12 14:22:00', 2)
        """)
        
        cursor.execute("""
        INSERT INTO threats (threat_type, source_ip, destination_ip, severity, confidence, scan_time, user_id) VALUES
        ('DoS', '192.168.1.50', '192.168.1.1', 'High', 0.94, '2026-07-10 12:45:00', 1),
        ('Brute-Force', '185.220.101.5', '192.168.1.10', 'Medium', 0.87, '2026-07-11 03:10:00', 1),
        ('Malware', '10.0.0.12', '8.8.8.8', 'High', 0.91, '2026-07-12 18:05:00', 2),
        ('Normal', '192.168.1.15', '142.250.190.46', 'Low', 0.97, '2026-07-12 21:40:00', 2)
        """)
        
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
