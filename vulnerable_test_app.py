# Intentionally Vulnerable Python Application
# DO NOT USE IN PRODUCTION

import os
import sqlite3
import pickle
import subprocess
import random
import hashlib
import requests
import jwt
import ssl
import importlib
import ldap3
from flask import Flask, request, redirect, make_response
from lxml import etree
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = Flask(__name__)

# ===============================
# Hardcoded Secrets
# ===============================
HARDCODED_PASSWORD = "admin123"
HARDCODED_TOKEN = "SECRET_TOKEN_ABC"
HARDCODED_DB_PATH = "/tmp/test.db"  # Hardcoded File Path

# Hardcoded AES key (insecure length)
AES_KEY = b"12345678"  # Weak key length

# ===============================
# Unsafe DB Connection String Building
# ===============================
def unsafe_db_connection():
    conn_string = "file:" + HARDCODED_DB_PATH + "?mode=rw"
    conn = sqlite3.connect(conn_string)
    return conn

# ===============================
# Unsafe SQL Query Construction
# ===============================
@app.route("/user")
def unsafe_sql():
    username = request.args.get("username")
    conn = unsafe_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)  # Unsafe SQL generation
    return str(cursor.fetchall())

# ===============================
# File Creation without Permissions
# ===============================
def create_file():
    f = open("/tmp/public.txt", "w")  # Temporary hardcoded file
    f.write("Sensitive Data")
    # Resource leak (not closed)

# ===============================
# File Deletion without Check
# ===============================
def delete_file():
    os.remove("/tmp/old.txt")

# ===============================
# Insecure Exception Handling
# ===============================
try:
    1 / 0
except Exception as e:
    print(e)  # Insecure error logging

# ===============================
# Potential XSS
# ===============================
@app.route("/xss")
def xss():
    user_input = request.args.get("input")
    return "<html>" + user_input + "</html>"

# ===============================
# Unsafe Deserialization
# ===============================
@app.route("/deserialize", methods=["POST"])
def unsafe_deserialization():
    data = request.data
    obj = pickle.loads(data)  # Unsafe deserialization
    return str(obj)

# ===============================
# Insecure Cookie (No HttpOnly, No Domain)
# ===============================
@app.route("/setcookie")
def set_cookie():
    resp = make_response("Cookie set")
    resp.set_cookie("sessionId", "12345")
    return resp

# ===============================
# Unsafe Path Handling
# ===============================
@app.route("/readfile")
def read_file():
    filename = request.args.get("name")
    with open("/uploads/" + filename, "r") as f:
        return f.read()

# ===============================
# Missing HTTP Status Code Validation + No Timeout
# ===============================
def rest_call():
    response = requests.get("http://example.com")
    print(response.text)

# ===============================
# Potential SSRF
# ===============================
@app.route("/fetch")
def ssrf():
    target = request.args.get("url")
    r = requests.get(target)
    return r.text

# ===============================
# Unsafe Redirect
# ===============================
@app.route("/redirect")
def unsafe_redirect():
    url = request.args.get("url")
    return redirect(url)

# ===============================
# Weak Random
# ===============================
def weak_random():
    return random.random()

# ===============================
# Weak Hashing (MD5)
# ===============================
def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

# ===============================
# Deprecated Crypto + Weak Mode + Non-random IV
# ===============================
def weak_encryption():
    iv = b"\x00" * 16  # Non-random IV
    cipher = AES.new(AES_KEY.ljust(16, b'0'), AES.MODE_ECB)  # Weak mode ECB
    encrypted = cipher.encrypt(pad(b"secret", 16))
    return encrypted

# ===============================
# Unsafe OS Command Generation
# ===============================
def unsafe_exec(cmd):
    subprocess.call("ls " + cmd, shell=True)

# ===============================
# Unsafe XPath String + Potential XXE
# ===============================
def unsafe_xpath(xml_data, user_input):
    parser = etree.XMLParser(resolve_entities=True)
    root = etree.fromstring(xml_data.encode(), parser)
    xpath_query = "//user[name='" + user_input + "']"
    return root.xpath(xpath_query)

# ===============================
# Unsafe importlib (Reflection-like)
# ===============================
def unsafe_import(module_name):
    module = importlib.import_module(module_name)
    return module

# ===============================
# Unsafe LDAP Search
# ===============================
def unsafe_ldap(user_input):
    server = ldap3.Server("ldap://localhost")
    conn = ldap3.Connection(server)
    search_filter = "(cn=" + user_input + ")"
    conn.search("dc=example,dc=com", search_filter)

# ===============================
# JWT Without Expiration
# ===============================
def jwt_without_exp():
    token = jwt.encode({"user": "admin"}, HARDCODED_TOKEN, algorithm="HS256")
    return token

# ===============================
# Sensitive Data Exposure
# ===============================
@app.route("/debug")
def debug():
    return str(os.environ)

# ===============================
# Unsafe Thread Termination
# ===============================
def unsafe_thread():
    import threading
    t = threading.Thread(target=lambda: print("Running"))
    t.start()
    t._stop()  # Unsafe thread termination

# ===============================
# Ignoring SSL Verification + Weak SSL Protocol
# ===============================
def insecure_ssl():
    requests.get("https://example.com", verify=False)

    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

# ===============================
# Unsafe Code Execution (Duplicate Intentional)
# ===============================
def run_code(code):
    exec(code)

# ===============================
# Unsafe Reflection Use
# ===============================
def unsafe_reflection(obj_name):
    return globals()[obj_name]

# ===============================
# Unrecommended GOTO usage (simulated)
# ===============================
def goto_simulation():
    while True:
        break  # Placeholder for bad control flow

# ===============================
# Unused Error Variable
# ===============================
def unused_error():
    try:
        open("file.txt")
    except Exception as err:
        pass  # Ignored error

# ===============================
# Start App
# ===============================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
