import os
import bcrypt
import psycopg2

PG_DSN = "postgresql://aegisai:aegisai_pg_pass@postgres:5432/aegisai_db"

password = b"aegisai-admin-2024"
hashed = bcrypt.hashpw(password, bcrypt.gensalt(12)).decode('utf-8')

print(f"New hash: {hashed}")

conn = psycopg2.connect(PG_DSN)
cur = conn.cursor()
cur.execute("UPDATE users SET password_hash = %s WHERE username = 'admin'", (hashed,))
conn.commit()
print("Updated admin password successfully!")
