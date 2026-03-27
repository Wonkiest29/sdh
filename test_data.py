import sqlite3
from datetime import datetime, timedelta

# Connect to database (same as in main.py)
conn = sqlite3.connect("access_control.db")
cur = conn.cursor()

# Test users
test_users = [
    ("D65D321A", "user1"),
    ("E63008F8", "user2"),
]

print("Adding test users...")
for rfid, name in test_users:
    try:
        cur.execute("INSERT INTO users (rfid_id, name) VALUES (?, ?)", (rfid, name))
        print(f"  OK - {name} ({rfid})")
    except sqlite3.IntegrityError:
        print(f"  WARNING - {name} already exists")

conn.commit()

# Get user IDs
cur.execute("SELECT id, name FROM users")
users = cur.fetchall()

conn.close()
print("\nDone! Now run main.py and send AUDIT_ENTRY")
