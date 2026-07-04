"""
Local backend for the SME Header Auditor extension.

Run this alongside the browser extension:
    pip install flask flask-cors --break-system-packages
    python server.py

The extension posts to http://localhost:5000. This writes into the same
SQLite schema you're already using for the dataset, so records added via
the extension land in the same table as your manually-inserted ones.

IMPORTANT: change DB_PATH below to point at your actual .db file.

SCORING METHODOLOGY (kept here for reference so any batch-scanning script
you write later stays consistent with the extension's popup.js):
Severity-tiered weights, sum to 1.0:
    Content-Security-Policy      0.25
    Strict-Transport-Security    0.20
    X-Frame-Options              0.15
    Referrer-Policy              0.15
    Permissions-Policy           0.15
    X-Content-Type-Options       0.10

Quality-graded credit per header (not just presence):
    pass (well-configured)       full weight    x1.0
    weak (present, misconfigured) half weight   x0.5
    fail (absent)                 no weight     x0.0

score = sum(weight_i * credit_i) for i in the 6 headers
Tiers: A >= 0.90, B >= 0.75, C >= 0.60, D >= 0.40, F < 0.40
"""
HEADER_WEIGHTS = {
    "content-security-policy": 0.25,
    "strict-transport-security": 0.20,
    "x-frame-options": 0.15,
    "referrer-policy": 0.15,
    "permissions-policy": 0.15,
    "x-content-type-options": 0.10,
}
QUALITY_CREDIT = {"pass": 1.0, "weak": 0.5, "fail": 0.0}


import sqlite3
from datetime import date

from flask import Flask, request, jsonify
from flask_cors import CORS

DB_PATH = "sme_dataset.db"  # <-- point this at your existing database file

app = Flask(__name__)
CORS(app)  # allows the chrome-extension:// origin to call this backend


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            business_name TEXT,
            url TEXT UNIQUE NOT NULL,
            category TEXT,
            city TEXT,
            state TEXT,
            source TEXT,
            date_added TEXT,
            notes TEXT
        )
        """
    )
    conn.commit()
    conn.close()


@app.route("/check_duplicate", methods=["GET"])
def check_duplicate():
    url = request.args.get("url", "")
    conn = get_conn()
    row = conn.execute("SELECT 1 FROM sites WHERE url = ?", (url,)).fetchone()
    conn.close()
    return jsonify({"exists": row is not None})


@app.route("/add_site", methods=["POST"])
def add_site():
    data = request.get_json(force=True)
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"status": "error", "message": "missing url"}), 400

    conn = get_conn()
    try:
        conn.execute(
            """
            INSERT INTO sites (business_name, url, category, city, state, source, date_added, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data.get("business_name", ""),
                url,
                data.get("category", ""),
                data.get("city", ""),
                data.get("state", ""),
                "extension",
                date.today().isoformat(),
                data.get("notes", ""),
            ),
        )
        conn.commit()
        status = "added"
    except sqlite3.IntegrityError:
        status = "duplicate"
    finally:
        conn.close()

    return jsonify({"status": status})


if __name__ == "__main__":
    init_db()
    print(f"Using database: {DB_PATH}")
    app.run(port=5000, debug=True)
