import sqlite3
from passlib.hash import sha256_crypt

dummy_users = [
    ("Alice Johnson", "alice@example.com", "alicej", sha256_crypt.encrypt("password1")),
    ("Bob Smith", "bob@example.com", "bobsmith", sha256_crypt.encrypt("password2")),
    ("Charlie Brown", "charlie@example.com", "charlieb", sha256_crypt.encrypt("password3")),
    ("Diana Prince", "diana@example.com", "dianap", sha256_crypt.encrypt("password4")),
    ("Ethan Hunt", "ethan@example.com", "ethanh", sha256_crypt.encrypt("password5")),
]

conn = sqlite3.connect("wanguana.db")
cur = conn.cursor()

cur.executemany("INSERT INTO users (name, email, username, password) VALUES (?, ?, ?, ?)", dummy_users)
conn.commit()
conn.close()

print("Dummy users added successfully!")
