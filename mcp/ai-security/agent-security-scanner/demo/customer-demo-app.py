"""
customer-demo-app.py
====================
A realistic (but intentionally vulnerable) e-commerce backend.
This single file is the target for the customer demo — it demonstrates
every capability category of the agent-security-scanner:

  LAYER 1 — Code vulnerabilities (AST + taint analysis)
    [1] SQL injection (direct string concat)
    [2] Command injection (cross-file hop via helper)
    [3] XSS / unsafe HTML rendering
    [4] Hardcoded secret / API key
    [5] Weak crypto (MD5 password hashing)
    [6] Path traversal on file download
    [7] SSL verification disabled
    [8] Insecure deserialization (pickle)

  LAYER 2 — AI-agent specific threats
    [9]  Hallucinated package import
    [10] Prompt injection in LLM pipeline

  LAYER 3 — Advanced / inter-procedural
    [11] 3-hop taint chain (order -> process -> execute -> db)
    [12] Cross-file taint (sanitize_input defined in helper_module)
"""

import os
import hashlib
import pickle
import sqlite3
import subprocess
import urllib.request

# ── [9] HALLUCINATED PACKAGE ──────────────────────────────────────────────────
# 'flask-ai-guard' does not exist on PyPI — an AI agent invented it.
# scan_packages will flag this before it reaches production.
import flask_ai_guard          # noqa: F401  ← hallucinated
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# ── [4] HARDCODED SECRET ──────────────────────────────────────────────────────
# INTENTIONAL VULNERABILITY FOR DEMO - NOT REAL CREDENTIALS
# These are clearly fake placeholder values for demonstration purposes only
STRIPE_SECRET_KEY  = "sk_test_FAKE_KEY_FOR_DEMO_PURPOSES_ONLY_1234567890"
DATABASE_URL       = "postgresql://admin:SuperSecret123@prod-db.internal/shop"
JWT_SECRET         = "my_jwt_signing_secret_do_not_share"

db = sqlite3.connect(":memory:", check_same_thread=False)


# ── [5] WEAK CRYPTO ───────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    """Hash password with MD5 (broken — for display purposes)."""
    return hashlib.md5(password.encode()).hexdigest()   # noqa: S324


# ── [1] SQL INJECTION ─────────────────────────────────────────────────────────
@app.route("/users/search")
def search_users():
    query = request.args.get("q", "")
    # Direct string concatenation — classic SQLi
    sql = "SELECT id, name, email FROM users WHERE name = '" + query + "'"
    cursor = db.execute(sql)
    return jsonify(cursor.fetchall())


# ── [3] XSS ───────────────────────────────────────────────────────────────────
@app.route("/products/<int:product_id>/review")
def show_review(product_id):
    review = request.args.get("review", "")
    # User content injected directly into HTML template
    template = f"""
    <html><body>
      <h1>Product {product_id}</h1>
      <div class='review'>{review}</div>
    </body></html>
    """
    return render_template_string(template)   # XSS via unescaped `review`


# ── [6] PATH TRAVERSAL ────────────────────────────────────────────────────────
@app.route("/download")
def download_file():
    filename = request.args.get("file", "")
    # No sanitisation — ../../etc/passwd works
    filepath = os.path.join("/app/uploads", filename)
    with open(filepath, "rb") as f:
        return f.read()


# ── [7] SSL VERIFY=FALSE ──────────────────────────────────────────────────────
def fetch_payment_status(order_id: str) -> dict:
    import requests
    resp = requests.get(
        f"https://payments.internal/status/{order_id}",
        verify=False                          # SSL cert check disabled
    )
    return resp.json()


# ── [8] INSECURE DESERIALIZATION ──────────────────────────────────────────────
@app.route("/cart/restore", methods=["POST"])
def restore_cart():
    cart_data = request.get_data()
    cart = pickle.loads(cart_data)            # Arbitrary code execution risk
    return jsonify({"items": len(cart)})


# ── [10] PROMPT INJECTION IN LLM PIPELINE ────────────────────────────────────
@app.route("/ai/support", methods=["POST"])
def ai_support():
    """Pass user message directly to LLM without sanitisation."""
    user_message = request.json.get("message", "")
    # The prompt is assembled without scanning for injection
    system_prompt = "You are a helpful e-commerce support agent."
    full_prompt = f"{system_prompt}\n\nUser: {user_message}"
    # In production this goes to an LLM API — injected payload executes here
    return jsonify({"prompt": full_prompt})


# ── [11] 3-HOP INTER-PROCEDURAL TAINT CHAIN ──────────────────────────────────
def step1_receive_order(raw_input: str) -> str:
    """Step 1: accept order data from HTTP layer."""
    return "order:" + raw_input


def step2_process_order(order_str: str) -> str:
    """Step 2: enrich with metadata."""
    return order_str + ":processed"


def step3_format_command(processed: str) -> str:
    """Step 3: build a shell command for the fulfillment system."""
    return f"fulfill.sh --data={processed}"


@app.route("/orders/fulfill", methods=["POST"])
def fulfill_order():
    raw = request.form.get("order_data", "")   # ← taint source
    hop1 = step1_receive_order(raw)
    hop2 = step2_process_order(hop1)
    cmd  = step3_format_command(hop2)
    os.system(cmd)                              # ← sink, 3 hops away
    return jsonify({"status": "queued"})


# ── [2] COMMAND INJECTION ─────────────────────────────────────────────────────
@app.route("/admin/ping")
def admin_ping():
    host = request.args.get("host", "localhost")
    # Shell=True + user input = command injection
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True, capture_output=True, text=True
    )
    return result.stdout


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
