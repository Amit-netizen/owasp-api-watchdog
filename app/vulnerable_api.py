"""
OWASP Top 10 Vulnerable Flask API
----------------------------------
PURPOSE: Intentionally vulnerable API for security testing demonstrations.
This is NOT production code — every flaw here is deliberate and documented.

OWASP Issues present:
  API1:2023  - Broken Object Level Authorization (BOLA)
  API2:2023  - Broken Authentication (weak JWT, no expiry)
  API3:2023  - Broken Object Property Level Authorization (mass assignment)
  API5:2023  - Broken Function Level Authorization
  API8:2023  - Security Misconfiguration (debug mode, verbose errors)
  API10:2023 - Unsafe Consumption of APIs / Injection (SQL Injection)
"""

import sqlite3
import jwt
import datetime
import os
from flask import Flask, request, jsonify, g

app = Flask(__name__)

# VULN: Hardcoded weak secret key (API2)
JWT_SECRET = "secret123"
DB_PATH = ":memory:"

# ─── Database bootstrap ───────────────────────────────────────────────────────

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        _seed_db(db)
    return db

def _seed_db(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            email TEXT,
            ssn TEXT,
            credit_card TEXT
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            item TEXT NOT NULL,
            amount REAL NOT NULL
        );
        INSERT OR IGNORE INTO users VALUES
            (1, 'alice', 'password123', 'user',  'alice@example.com', '123-45-6789', '4111111111111111'),
            (2, 'bob',   'pass456',     'user',  'bob@example.com',   '987-65-4321', '5500005555555559'),
            (3, 'admin', 'admin',       'admin', 'admin@example.com', '000-00-0000', '0000000000000000');
        INSERT OR IGNORE INTO orders VALUES
            (1, 1, 'Laptop',  999.99),
            (2, 1, 'Phone',   499.99),
            (3, 2, 'Tablet',  299.99);
    """)
    db.commit()

@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

# ─── Auth helpers ─────────────────────────────────────────────────────────────

def _generate_token(user_id: int, role: str) -> str:
    # VULN: No expiry (API2), algorithm=HS256 is acceptable but secret is weak
    payload = {"user_id": user_id, "role": role}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def _decode_token(token: str) -> dict | None:
    try:
        # VULN: algorithms list accepts "none" implicitly in older PyJWT — we
        # intentionally do NOT validate expiry or audience
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256", "none"])
    except jwt.InvalidTokenError:
        return None

def _current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return _decode_token(auth[7:])

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "debug": True})  # VULN: exposes debug flag (API8)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # VULN: SQL Injection (API10) — direct string interpolation
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        row = get_db().execute(query).fetchone()
    except sqlite3.OperationalError as e:
        # VULN: verbose error leaks query details (API8)
        return jsonify({"error": str(e), "query": query}), 500

    if row:
        token = _generate_token(row["id"], row["role"])
        return jsonify({"token": token, "user_id": row["id"], "role": row["role"]})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    # VULN: BOLA (API1) — no ownership check; any authenticated user can read
    # any other user's sensitive data including SSN and credit card
    caller = _current_user()
    if not caller:
        return jsonify({"error": "Unauthorized"}), 401

    row = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404

    # VULN: returns ALL fields including sensitive ones (API3)
    return jsonify(dict(row))


@app.route("/users/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    # VULN: Mass Assignment (API3) — caller can set any field, including role
    caller = _current_user()
    if not caller:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True) or {}
    # VULN: no field allowlist — attacker can promote themselves to admin
    updates = ", ".join(f"{k}='{v}'" for k, v in data.items())
    if not updates:
        return jsonify({"error": "No fields provided"}), 400

    get_db().execute(f"UPDATE users SET {updates} WHERE id={user_id}")
    get_db().commit()
    return jsonify({"message": "Updated", "fields_changed": list(data.keys())})


@app.route("/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    # VULN: BOLA (API1) — no check that order belongs to caller
    caller = _current_user()
    if not caller:
        return jsonify({"error": "Unauthorized"}), 401

    row = get_db().execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(dict(row))


@app.route("/admin/users", methods=["GET"])
def admin_list_users():
    # VULN: Broken Function Level Authorization (API5) — only checks token exists,
    # not that the caller is actually an admin
    caller = _current_user()
    if not caller:
        return jsonify({"error": "Unauthorized"}), 401
    # Missing: if caller["role"] != "admin": return 403

    rows = get_db().execute("SELECT * FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/search", methods=["GET"])
def search_users():
    # VULN: SQL Injection via query param (API10)
    term = request.args.get("q", "")
    query = f"SELECT id, username, email FROM users WHERE username LIKE '%{term}%'"
    try:
        rows = get_db().execute(query).fetchall()
    except sqlite3.OperationalError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    # VULN: debug=True in production (API8)
    app.run(debug=True, host="0.0.0.0", port=5000)
