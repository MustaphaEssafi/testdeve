from flask import Flask, request
import sqlite3
import os
import logging
import json
import bcrypt
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()
app = Flask(__name__)

# ======================================================
# 🧨 6️⃣ Hardcoded Secret — FIX
# ❌ قبل: API_KEY = "API-KEY-123456"
# ❗ خطر: السر كان مكتوب فالكود
# ✅ دابا: كنستعمل variable d’environnement
# ======================================================
API_KEY = os.getenv("API_KEY")

# ======================================================
# 🧨 Logging non sécurisé — FIX
# ❌ قبل: logging level DEBUG (كيخرج معلومات حساسة)
# ✅ دابا: INFO فقط
# ======================================================
logging.basicConfig(level=logging.INFO)

# ======================================================
# 🧨 1️⃣ SQL Injection — /auth — FIX
# ❌ قبل: f-string فـ SQL query
# ❗ خطر: user يقدر يدير bypass
# ✅ دابا: requêtes préparées
# ======================================================
@app.route("/auth", methods=["POST"])
def auth():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password)
    )

    if cursor.fetchone():
        return {"status": "authenticated"}

    return {"status": "denied"}, 401


# ======================================================
# 🧨 2️⃣ Command Injection — /exec — FIX
# ❌ قبل: subprocess.check_output(cmd, shell=True)
# ❗ خطر: تنفيذ أوامر النظام
# ✅ دابا: endpoint محذوف نهائياً
# ======================================================
@app.route("/exec", methods=["POST"])
def exec_cmd():
    return {
        "error": "Command execution disabled for security reasons"
    }, 403


# ======================================================
# 🧨 3️⃣ Unsafe Deserialization — /deserialize — FIX
# ❌ قبل: pickle.loads(data)
# ❗ خطر: تنفيذ كود خبيث
# ✅ دابا: JSON آمن
# ======================================================
@app.route("/deserialize", methods=["POST"])
def deserialize():
    try:
        obj = json.loads(request.data)
        return {"object": obj}
    except Exception:
        return {"error": "Invalid JSON"}, 400


# ======================================================
# 🧨 4️⃣ Weak Cryptography (MD5) — /encrypt — FIX
# ❌ قبل: hashlib.md5
# ❗ خطر: hash ضعيف
# ✅ دابا: bcrypt (best practice)
# ======================================================
@app.route("/encrypt", methods=["POST"])
def encrypt():
    text = request.json.get("text", "")
    hashed = bcrypt.hashpw(text.encode(), bcrypt.gensalt())
    return {"hash": hashed.decode()}


# ======================================================
# 🧨 5️⃣ Path Traversal — /file — FIX
# ❌ قبل: open(filename)
# ❗ خطر: قراءة ملفات النظام
# ✅ دابا: directory محدد + validation
# ======================================================
@app.route("/file", methods=["POST"])
def read_file():
    filename = request.json.get("filename")

    BASE_DIR = Path("/app/files")
    file_path = (BASE_DIR / filename).resolve()

    if not str(file_path).startswith(str(BASE_DIR)):
        return {"error": "Access denied"}, 403

    try:
        with open(file_path, "r") as f:
            return {"content": f.read()}
    except FileNotFoundError:
        return {"error": "File not found"}, 404


# ======================================================
# 🧨 7️⃣ Sensitive Data Exposure — /debug — FIX
# ❌ قبل: إرجاع api_key و env
# ❗ خطر: تسريب معلومات
# ✅ دابا: endpoint محمي / محدود
# ======================================================
@app.route("/debug", methods=["GET"])
def debug():
    return {
        "status": "debug disabled in production"
    }


# ======================================================
# 🧨 8️⃣ Log Injection — /log — FIX
# ❌ قبل: logging user input مباشرة
# ❗ خطر: تزوير logs
# ✅ دابا: log غير معلومات عامة
# ======================================================
@app.route("/log", methods=["POST"])
def log_data():
    logging.info("User data received")
    return {"status": "logged"}


# ======================================================
# 🧨 9️⃣ Debug Mode Enabled — FIX
# ❌ قبل: debug=True
# ❗ خطر: stack trace + infos
# ✅ دابا: debug=False
# ======================================================
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
