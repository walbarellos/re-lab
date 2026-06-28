from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/")
def index():
    # Parâmetro visível
    q = request.args.get("q", "")
    
    # Parâmetros ocultos que o desenvolvedor esqueceu expostos
    debug = request.args.get("debug", "")
    admin = request.args.get("admin", "")
    
    if debug == "1" or admin == "true":
        return jsonify({
            "status": "success",
            "message": "Painel de Depuração Ativo",
            "flag": "CTF{{h1dd3n_p4r4m_d1sc0v3ry_w1n}}"
        })

    return "<html><body><h3>Portal do Estudante</h3><p>Pesquise usando '?q='</p></body></html>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1337)
