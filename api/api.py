from flask import Flask, request
import sqlite3
import pickle
import subprocess
import hashlib
import os
import logging

app = Flask(__name__)

# SECRET HARDCODÉ (mauvaise pratique)
# 🧨 6️⃣ Hardcoded Secret — API_KEY
# API_KEY = "API-KEY-123456"
API_KEY = os.getenv("API_KEY")

# Logging non sécurisé
logging.basicConfig(level=logging.DEBUG)


@app.route("/auth", methods=["POST"])
def auth():
    username = request.json.get("username")
    password = request.json.get("password")

    # SQL Injection
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    #1 MOCKEL SQL Injection — /auth
    # query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    # cursor.execute(query)

    cursor.execute(
    "SELECT * FROM users WHERE username=? AND password=?",
    (username, password)
    )

    if cursor.fetchone():
        return {"status": "authenticated"}

    return {"status": "denied"}


@app.route("/exec", methods=["POST"])
def exec_cmd():
    cmd = request.json.get("cmd")

    # Command Injection
    # 2️⃣ Command Injection — /exec
    # output = subprocess.check_output(cmd, shell=True)
    # subprocess.check_output(["ping", host])
    


@app.route("/deserialize", methods=["POST"])
def deserialize():
    data = request.data

    # Désérialisation dangereuse
    # 3️⃣ Unsafe Deserialization — /deserialize
    # obj = pickle.loads(data)
    import json
    obj = json.loads(data)
    return {"object": str(obj)}


@app.route("/encrypt", methods=["POST"])
def encrypt():
    text = request.json.get("text", "")

    # Chiffrement faible
    # 4️⃣ Weak Cryptography (MD5) — /encrypt
    # hashed = hashlib.md5(text.encode()).hexdigest()
    import bcrypt
    hashed = bcrypt.hashpw(text.encode(), bcrypt.gensalt())
    return {"hash": hashed}


@app.route("/file", methods=["POST"])
def read_file():
    filename = request.json.get("filename")

    # Path Traversal
    # 5️⃣ Path Traversal — /file
    # with open(filename, "r") as f:
            # return {"content": f.read()}
    import os
    BASE_DIR = "/app/files"
    path = os.path.join(BASE_DIR, filename)



@app.route("/debug", methods=["GET"])
def debug():
    # Divulgation d'informations sensibles
    # 🧨 7️⃣ Sensitive Data Exposure — /debug
    return {
        # "api_key": API_KEY,
        # "env": dict(os.environ),
        "cwd": os.getcwd()
    }


@app.route("/log", methods=["POST"])
def log_data():
    data = request.json

    # Log Injection
    # 🧨 8️⃣ Log Injection — /log
    # logging.info(f"User input: {data}")
    logging.info("User data received")
    return {"status": "logged"}

# 🧨 9️⃣ Debug Mode Enabled
# debug=True
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
