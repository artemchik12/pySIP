#!/usr/bin/env python3
import sys
import sqlite3
import hashlib

DB_FILE = "sip_users.db"
DEFAULT_REALM = "sip.local"


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            ha1 TEXT NOT NULL,
            realm TEXT NOT NULL
        )
        """
    )
    return conn


def calculate_ha1(username, realm, password):
    raw = f"{username}:{realm}:{password}"
    return hashlib.md5(raw.encode("utf-8")).hexdigest()


def add_user(username, password, realm=DEFAULT_REALM):
    ha1 = calculate_ha1(username, realm, password)
    conn = get_db()
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO users (username, ha1, realm) VALUES (?, ?, ?)",
            (username, ha1, realm),
        )
    print(f"✓ User '{username}' registered for realm '{realm}'.")


def list_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, realm FROM users")
    rows = cursor.fetchall()
    if not rows:
        print("No users found.")
        return
    print(f"{'Username / Extension':<25} {'Realm':<20}")
    print("-" * 45)
    for u, r in rows:
        print(f"{u:<25} {r:<20}")


def delete_user(username):
    conn = get_db()
    with conn:
        cursor = conn.execute("DELETE FROM users WHERE username = ?", (username,))
        if cursor.rowcount > 0:
            print(f"✓ User '{username}' deleted.")
        else:
            print(f"User '{username}' not found.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 manage_users.py add <extension> <password> [realm]")
        print("  python3 manage_users.py list")
        print("  python3 manage_users.py del <extension>")
        sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd == "add" and len(sys.argv) >= 4:
        realm = sys.argv[4] if len(sys.argv) > 4 else DEFAULT_REALM
        add_user(sys.argv[2], sys.argv[3], realm)
    elif cmd == "list":
        list_users()
    elif cmd == "del" and len(sys.argv) >= 3:
        delete_user(sys.argv[2])
    else:
        print("Invalid arguments. Run without flags to see usage.")
