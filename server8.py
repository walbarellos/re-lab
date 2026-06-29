from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/")
def index():
    name = request.args.get("name", "Guest")
    
    # Filtro básico de segurança (Bloqueia espaços e aspas comuns)
    forbidden = [" ", "'", "\"", "_"]
    if any(char in name for char in forbidden):
        return "Acesso Negado: Caracteres proibidos detectados pelo WAF!", 403

    template = f"""
    <html>
        <head><title>SSTI Filter Bypass Challenge</title></head>
        <body>
            <h2>Olá, {name}!</h2>
            <!-- Dica de Flag: CTF{{ '{{' }}sst1_f1lt3r_byp4ss_succ3ss{{ '}}' }} -->
        </body>
    </html>
    """
    return render_template_string(template)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1337)
