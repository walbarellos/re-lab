from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/")
def index():
    name = request.args.get("name", "Guest")
    # Vulnerabilidade clássica de SSTI (Jinja2 / Flask)
    # Interpolação direta na string do template antes do render
    template = f"""
    <html>
        <head><title>SSTI Jinja2 Challenge</title></head>
        <body>
            <h2>Bem-vindo, {name}!</h2>
            <p>Use o parâmetro '?name=' para testar o template.</p>
            <!-- Dica de Flag: CTF{{j1nj42_sst1_fl4sk_pwn}} -->
        </body>
    </html>
    """
    return render_template_string(template)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1337)
