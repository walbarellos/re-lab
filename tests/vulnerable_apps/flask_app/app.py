import os
import sqlite3
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
app.config["FLAG"] = "CTF{mock_target_ssti_success}"


# Configura o banco de dados SQLite em memória
def init_db():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'administrator')")
    cursor.execute("INSERT INTO users (username, password, role) VALUES ('user', 'user123', 'user')")
    conn.commit()
    return conn

# Mantém uma conexão global simplificada para o mock
db_conn = init_db()

@app.after_request
def add_headers(response):
    response.headers["Server"] = "Flask"
    response.headers["X-Powered-By"] = "Python 3.10"
    return response

@app.route("/")
def index():
    debug = request.args.get("debug", "")
    if debug in ("1", "true"):
        return jsonify({
            "status": "success",
            "message": "Painel de Depuração Ativo",
            "flag": "CTF{h1dd3n_p4r4m_d1sc0v3ry_w1n}"
        })
    return "<html><body>Welcome! Visit /wp-content, /ssti, /sqli, or /lfi</body></html>"

@app.route("/wp-content")
def wp_content():
    return "WordPress Content Directory"

@app.route("/ssti")
def ssti():
    template = request.args.get("template", "Guest")
    # Vulnerabilidade SSTI real via Jinja2 render_template_string
    try:
        # Injeta uma flag secreta no contexto do ambiente para verificação
        os.environ["FLAG"] = "CTF{mock_target_ssti_success}"
        result = render_template_string(template)
        return result
    except Exception as e:
        return f"Error: {e}", 500

@app.route("/sqli")
def sqli():
    user_id = request.args.get("id", "")
    # Vulnerabilidade SQL Injection real usando concatenação direta
    try:
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
        cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'administrator')")
        cursor.execute("INSERT INTO users (username, password, role) VALUES ('user', 'user123', 'user')")
        
        query = f"SELECT username, role FROM users WHERE id = '{user_id}'"
        cursor.execute(query)
        rows = cursor.fetchall()
        return jsonify({"status": "success", "results": rows})
    except Exception as e:
        return f"Database Error: {e}", 500

@app.route("/lfi")
def lfi():
    filename = request.args.get("file", "")
    # Vulnerabilidade LFI real lendo arquivos locais
    try:
        # Bypasses simples se o usuário tentar subir diretórios
        safe_path = os.path.abspath(filename)
        with open(filename, "r") as f:
            return f.read()
    except Exception as e:
        return f"File Error: {e}", 500

@app.route("/login", methods=["POST"])
def login():
    # Suporta POST JSON ou Form URL Encoded
    if request.is_json:
        data = request.json
    else:
        data = request.form

    username = data.get("username", "")
    password = data.get("password", "")

    # Autenticação real
    if username == "admin" and password == "admin123":
        return jsonify({"status": "success", "token": "admin_session_active"})
    return jsonify({"status": "failed", "error": "Invalid credentials"}), 401

@app.route("/waf")
def waf():
    # Simula resposta de bloqueio do Cloudflare
    response = jsonify({"error": "blocked by cloudflare-nginx"})
    response.headers["CF-RAY"] = "12345abcdef"
    return response, 403


@app.route("/waf_profile")
def waf_profile():
    q = request.args.get("q", "")
    # Simula bloqueio de caracteres especiais do ModSecurity WAF
    if "'" in q or '"' in q:
        return "error: blocked by ModSecurity WAF rules", 406
    return "No blocked characters found."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
