"""
app.py

PhishGuard - Flask backend.

Serves the web UI, handles URL scan requests, runs predictions with
the trained Random Forest model, logs every scan to a SQLite
database, and exposes scan history / dashboard statistics.
"""

import os
import sqlite3
import traceback
from datetime import datetime, timezone
from html import escape

import joblib
from flask import Flask, g, jsonify, render_template, request

from feature_extractor import extract_features
from url_validator import is_valid_url, normalize_url

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "phishing_model.pkl")
DATABASE_PATH = os.path.join(BASE_DIR, "database", "logs.db")

app = Flask(__name__)

# ---------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------
_model = None
_model_load_error = None

try:
    if os.path.exists(MODEL_PATH):
        _model = joblib.load(MODEL_PATH)
    else:
        _model_load_error = (
            "Model file not found. Please run 'python training.py' "
            "first to train and save the model."
        )
except Exception as exc:  # noqa: BLE001 - we want to catch any load error
    _model_load_error = f"Failed to load model: {exc}"


# ---------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------
def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            confidence REAL NOT NULL,
            timestamp TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def log_scan(url: str, result: str, confidence: float):
    db = get_db()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    db.execute(
        "INSERT INTO logs (url, result, confidence, timestamp) VALUES (?, ?, ?, ?)",
        (url, result, confidence, timestamp),
    )
    db.commit()


# ---------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html", page="home")


@app.route("/history")
def history():
    db = get_db()
    rows = db.execute(
        "SELECT url, result, confidence, timestamp FROM logs ORDER BY id DESC LIMIT 200"
    ).fetchall()

    total = db.execute("SELECT COUNT(*) AS count FROM logs").fetchone()["count"]
    safe_count = db.execute(
        "SELECT COUNT(*) AS count FROM logs WHERE result = 'SAFE'"
    ).fetchone()["count"]
    phishing_count = db.execute(
        "SELECT COUNT(*) AS count FROM logs WHERE result = 'PHISHING'"
    ).fetchone()["count"]

    scans = [
        {
            "url": escape(row["url"]),
            "result": row["result"],
            "confidence": row["confidence"],
            "timestamp": row["timestamp"],
        }
        for row in rows
    ]

    stats = {"total": total, "safe": safe_count, "phishing": phishing_count}

    return render_template("index.html", page="history", scans=scans, stats=stats)


@app.route("/about")
def about():
    return render_template("index.html", page="about")


@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(silent=True) or {}
        raw_url = (data.get("url") or "").strip()

        if not raw_url:
            return jsonify({"error": "Please enter a URL to scan."}), 400

        if not is_valid_url(raw_url):
            return jsonify({
                "error": "That doesn't look like a valid URL. "
                         "Example: example.com or https://example.com"
            }), 400

        if _model is None:
            return jsonify({
                "error": _model_load_error or "Model is not available."
            }), 503

        normalized = normalize_url(raw_url)
        features = extract_features(normalized)

        prediction = _model.predict([features])[0]

        confidence = None
        if hasattr(_model, "predict_proba"):
            probabilities = _model.predict_proba([features])[0]
            confidence = float(max(probabilities)) * 100

        result = "PHISHING" if int(prediction) == 1 else "SAFE"

        if result == "SAFE":
            message = "This URL appears to be safe based on the trained model."
        else:
            message = "This URL appears to be potentially dangerous/phishing."

        log_scan(raw_url, result, confidence if confidence is not None else 0.0)

        return jsonify({
            "url": escape(raw_url),
            "result": result,
            "message": message,
            "confidence": round(confidence, 2) if confidence is not None else None,
            "disclaimer": (
                "Machine-learning predictions are not guaranteed. Do not "
                "enter passwords, payment information, or other sensitive "
                "data on suspicious websites."
            ),
        })

    except Exception:  # noqa: BLE001 - never leak internals to the client
        app.logger.error("Prediction error:\n%s", traceback.format_exc())
        return jsonify({
            "error": "Something went wrong while scanning this URL. Please try again."
        }), 500


@app.route("/clear-history", methods=["POST"])
def clear_history():
    try:
        db = get_db()
        db.execute("DELETE FROM logs")
        db.commit()
        return jsonify({"success": True})
    except Exception:  # noqa: BLE001
        app.logger.error("Clear history error:\n%s", traceback.format_exc())
        return jsonify({"error": "Could not clear history. Please try again."}), 500


@app.route("/api/dashboard-stats")
def dashboard_stats():
    db = get_db()
    total = db.execute("SELECT COUNT(*) AS count FROM logs").fetchone()["count"]
    safe_count = db.execute(
        "SELECT COUNT(*) AS count FROM logs WHERE result = 'SAFE'"
    ).fetchone()["count"]
    phishing_count = db.execute(
        "SELECT COUNT(*) AS count FROM logs WHERE result = 'PHISHING'"
    ).fetchone()["count"]
    recent_rows = db.execute(
        "SELECT url, result, confidence, timestamp FROM logs ORDER BY id DESC LIMIT 5"
    ).fetchall()
    recent = [
        {
            "url": escape(row["url"]),
            "result": row["result"],
            "confidence": row["confidence"],
            "timestamp": row["timestamp"],
        }
        for row in recent_rows
    ]
    return jsonify({
        "total": total,
        "safe": safe_count,
        "phishing": phishing_count,
        "recent": recent,
    })


@app.errorhandler(404)
def not_found(_error):
    return render_template("index.html", page="home"), 404


@app.errorhandler(500)
def server_error(_error):
    return jsonify({"error": "An unexpected server error occurred."}), 500


if __name__ == "__main__":
    init_db()
    if _model_load_error:
        print(f"WARNING: {_model_load_error}")
    app.run(debug=True, host="127.0.0.1", port=5000)
