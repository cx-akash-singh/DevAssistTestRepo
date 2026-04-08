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

HARDCODED_PASSWORD = "admin123"
HARDCODED_TOKEN = "SECRET_TOKEN_ABC"
HARDCODED_DB_PATH = "/tmp/test.db"  # Hardcoded File Path


AES_KEY = b"12345678"  # Weak key length

def unsafe_db_connection():
    conn_string = "file:" + HARDCODED_DB_PATH + "?mode=rw"
    conn = sqlite3.connect(conn_string)
    return conn

=
@app.route("/user")
def unsafe_sql():
    username = request.args.get("username")
    conn = unsafe_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)  # Unsafe SQL generation
    return str(cursor.fetchall())


def create_file():
    f = open("/tmp/public.txt", "w")  # Temporary hardcoded file
    f.write("Sensitive Data")
    # Resource leak (not closed)


def delete_file():
    os.remove("/tmp/old.txt")


try:
    1 / 0
except Exception as e:
    print(e)  # Insecure error logging


@app.route("/xss")
def xss():
    user_input = request.args.get("input")
    return "<html>" + user_input + "</html>"


@app.route("/deserialize", methods=["POST"])
def unsafe_deserialization():
    data = request.data
    obj = pickle.loads(data)  # Unsafe deserialization
    return str(obj)


@app.route("/setcookie")
def set_cookie():
    resp = make_response("Cookie set")
    resp.set_cookie("sessionId", "12345")
    return resp


@app.route("/readfile")
def read_file():
    filename = request.args.get("name")
    with open("/uploads/" + filename, "r") as f:
        return f.read()


def rest_call():
    response = requests.get("http://example.com")
    print(response.text)


@app.route("/fetch")
def ssrf():
    target = request.args.get("url")
    r = requests.get(target)
    return r.text


@app.route("/redirect")
def unsafe_redirect():
    url = request.args.get("url")
    return redirect(url)


def weak_random():
    return random.random()


def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


def weak_encryption():
    iv = b"\x00" * 16  # Non-random IV
    cipher = AES.new(AES_KEY.ljust(16, b'0'), AES.MODE_ECB)  # Weak mode ECB
    encrypted = cipher.encrypt(pad(b"secret", 16))
    return encrypted


def unsafe_exec(cmd):
    subprocess.call("ls " + cmd, shell=True)


def unsafe_xpath(xml_data, user_input):
    parser = etree.XMLParser(resolve_entities=True)
    root = etree.fromstring(xml_data.encode(), parser)
    xpath_query = "//user[name='" + user_input + "']"
    return root.xpath(xpath_query)


def unsafe_import(module_name):
    module = importlib.import_module(module_name)
    return module

def unsafe_ldap(user_input):
    server = ldap3.Server("ldap://localhost")
    conn = ldap3.Connection(server)
    search_filter = "(cn=" + user_input + ")"
    conn.search("dc=example,dc=com", search_filter)


def jwt_without_exp():
    token = jwt.encode({"user": "admin"}, HARDCODED_TOKEN, algorithm="HS256")
    return token


@app.route("/debug")
def debug():
    return str(os.environ)


def unsafe_thread():
    import threading
    t = threading.Thread(target=lambda: print("Running"))
    t.start()
    t._stop()  # Unsafe thread termination
=
def insecure_ssl():
    requests.get("https://example.com", verify=False)

    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE


def run_code(code):
    exec(code)


def unsafe_reflection(obj_name):
    return globals()[obj_name]


def goto_simulation():
    while True:
        break  # Placeholder for bad control flow

def unused_error():
    try:
        open("file.txt")
    except Exception as err:
        pass  # Ignored error

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
