"""
Benchmark corpus: Python taint analysis flows.
Tests dataflow tracking of user-controlled inputs through various sinks.
"""

import os
import subprocess
import pickle
import yaml
import sqlite3
import ldap
import requests
from flask import Flask, request, render_template_string, make_response
from jinja2 import Template

app = Flask(__name__)

# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------

@app.route("/users")
def search_users():
    db = sqlite3.connect("app.db")
    username = request.args.get("username")

    # VULN: python.lang.security.sql-injection
    cursor = db.execute("SELECT * FROM users WHERE name = '" + username + "'")

    # VULN: python.lang.security.sql-injection
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor = db.execute(query)

    # SAFE: python.lang.security.sql-injection
    cursor = db.execute("SELECT * FROM users WHERE name = ?", (username,))

    return str(cursor.fetchall())


@app.route("/orders")
def search_orders():
    db = sqlite3.connect("app.db")
    order_id = request.args.get("order_id")

    # VULN: python.lang.security.sql-injection
    intermediate = "SELECT * FROM orders WHERE id = " + order_id
    cursor = db.execute(intermediate)

    # SAFE: python.lang.security.sql-injection
    cursor = db.execute("SELECT * FROM orders WHERE id = ?", (int(order_id),))

    return str(cursor.fetchall())


# ---------------------------------------------------------------------------
# Command Injection
# ---------------------------------------------------------------------------

@app.route("/ping")
def ping_host():
    host = request.args.get("host")

    # VULN: python.lang.security.command-injection
    os.system("ping -c 1 " + host)

    # VULN: python.lang.security.command-injection
    subprocess.call("nslookup " + host, shell=True)

    # SAFE: python.lang.security.command-injection
    subprocess.call(["ping", "-c", "1", host])

    return "done"


@app.route("/convert")
def convert_file():
    filename = request.args.get("file")

    # VULN: python.lang.security.command-injection
    cmd = f"convert {filename} output.png"
    os.popen(cmd)

    # SAFE: python.lang.security.command-injection
    subprocess.run(["convert", filename, "output.png"], shell=False)

    return "converted"


# ---------------------------------------------------------------------------
# Path Traversal
# ---------------------------------------------------------------------------

@app.route("/read")
def read_file():
    filepath = request.args.get("path")

    # VULN: python.lang.security.path-traversal
    with open("/var/data/" + filepath, "r") as f:
        data = f.read()

    # VULN: python.lang.security.path-traversal
    full = os.path.join("/var/data", filepath)
    with open(full, "r") as f:
        data = f.read()

    # SAFE: python.lang.security.path-traversal
    safe_name = os.path.basename(filepath)
    with open(os.path.join("/var/data", safe_name), "r") as f:
        data = f.read()

    return data


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------

@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")

    # VULN: python.lang.security.ssrf
    resp = requests.get(url)

    # VULN: python.lang.security.ssrf
    target = "http://" + request.args.get("host") + "/api"
    resp = requests.get(target)

    # SAFE: python.lang.security.ssrf
    allowed = ["https://api.example.com", "https://cdn.example.com"]
    if url in allowed:
        resp = requests.get(url)

    return resp.text


# ---------------------------------------------------------------------------
# Template Injection (SSTI)
# ---------------------------------------------------------------------------

@app.route("/greet")
def greet():
    name = request.args.get("name")

    # VULN: python.lang.security.template-injection
    return render_template_string("Hello " + name)

    # VULN: python.lang.security.template-injection
    tmpl = Template("Welcome, " + name + "!")
    return tmpl.render()


@app.route("/greet_safe")
def greet_safe():
    name = request.args.get("name")

    # SAFE: python.lang.security.template-injection
    return render_template_string("Hello {{ name }}", name=name)


# ---------------------------------------------------------------------------
# Deserialization
# ---------------------------------------------------------------------------

@app.route("/load", methods=["POST"])
def load_object():
    data = request.get_data()

    # VULN: python.lang.security.deserialization
    obj = pickle.loads(data)

    # VULN: python.lang.security.deserialization
    obj = yaml.load(data, Loader=yaml.Loader)

    # SAFE: python.lang.security.deserialization
    obj = yaml.safe_load(data)

    return str(obj)


# ---------------------------------------------------------------------------
# LDAP Injection
# ---------------------------------------------------------------------------

@app.route("/ldap_search")
def ldap_search():
    username = request.args.get("user")
    conn = ldap.initialize("ldap://directory.example.com")

    # VULN: python.lang.security.ldap-injection
    filter_str = "(uid=" + username + ")"
    results = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, filter_str)

    # SAFE: python.lang.security.ldap-injection
    import ldap.filter
    safe_filter = ldap.filter.filter_format("(uid=%s)", [username])
    results = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, safe_filter)

    return str(results)


# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------

@app.route("/profile")
def profile():
    bio = request.args.get("bio")

    # VULN: python.lang.security.xss
    return "<html><body><div>" + bio + "</div></body></html>"

    # VULN: python.lang.security.xss
    resp = make_response("<p>" + bio + "</p>")
    resp.headers["Content-Type"] = "text/html"
    return resp


@app.route("/profile_safe")
def profile_safe():
    from markupsafe import escape
    bio = request.args.get("bio")

    # SAFE: python.lang.security.xss
    return "<html><body><div>" + str(escape(bio)) + "</div></body></html>"


# ---------------------------------------------------------------------------
# Format String Injection
# ---------------------------------------------------------------------------

@app.route("/log")
def log_event():
    msg = request.args.get("msg")

    # VULN: python.lang.security.format-string-injection
    log_entry = "Event: {}".format(msg)
    eval(log_entry)

    # SAFE: python.lang.security.format-string-injection
    import logging
    logging.info("Event: %s", msg)

    return "logged"


# ---------------------------------------------------------------------------
# SSRF via redirect following
# ---------------------------------------------------------------------------

@app.route("/proxy")
def proxy_request():
    url = request.args.get("target")

    # VULN: python.lang.security.ssrf
    resp = requests.get(url, allow_redirects=True)

    return resp.text
