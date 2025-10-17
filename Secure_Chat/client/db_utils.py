import sqlite3

def init_db(db_file):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
        ts DATETIME DEFAULT CURRENT_TIMESTAMP,
        content TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()

def save_message(db_file, content):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute("INSERT INTO messages (content) VALUES (?)", (content,))
    conn.commit()
    conn.close()

def get_all_messages(db_file):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute("SELECT ts, content FROM messages ORDER BY ts DESC")
    rows = c.fetchall()
    conn.close()
    return rows
