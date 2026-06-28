"""
core/dashboard.py — Dashboard Visual v6.0.

Um servidor FastAPI que serve o Visual Command Center do CTFLab.
Exibe sessões, vulnerabilidades, evidências e flags em tempo real.
"""

import json
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from jinja2 import Environment, select_autoescape
import uvicorn
from .repository import SQLiteRepository

app = FastAPI()
repo = SQLiteRepository()

# Configura ambiente Jinja2 com autoescape para prevenir XSS
jinja_env = Environment(
    autoescape=select_autoescape(['html', 'xml'])
)

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CTFLab v6.0 | Command Center</title>
    <style>
        :root {
            --bg: #030712;
            --card-bg: #111827;
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.2);
            --border: #1f2937;
            --text-main: #f3f4f6;
            --text-dim: #9ca3af;
            --high: #ef4444;
            --med: #f59e0b;
            --low: #10b981;
            --flag: #db2777;
        }

        body { font-family: 'JetBrains Mono', 'Fira Code', monospace; background-color: var(--bg); color: var(--text-main); margin: 0; padding: 20px; line-height: 1.5; }
        
        .container { max-width: 1200px; margin: 0 auto; }
        
        header { 
            display: flex; justify-content: space-between; align-items: center;
            border-bottom: 2px solid var(--accent); padding-bottom: 20px; margin-bottom: 30px;
            box-shadow: 0 10px 20px -10px var(--accent-glow);
        }
        
        h1 { margin: 0; font-size: 1.8rem; letter-spacing: -1px; background: linear-gradient(to right, var(--accent), #fff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .version { font-size: 0.8rem; background: var(--accent); color: var(--bg); padding: 2px 8px; border-radius: 4px; vertical-align: middle; }

        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; margin-bottom: 40px; }
        .stat-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 24px; position: relative; overflow: hidden; }
        .stat-card::after { content: ''; position: absolute; top: 0; left: 0; width: 4px; height: 100%; background: var(--accent); }
        .stat-label { color: var(--text-dim); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
        .stat-value { font-size: 2.5rem; font-weight: 800; color: #fff; }

        .section-title { font-size: 1.2rem; color: var(--accent); margin: 40px 0 20px; display: flex; align-items: center; gap: 10px; }
        .section-title::after { content: ''; flex-grow: 1; height: 1px; background: var(--border); }

        .session-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 30px; overflow: hidden; }
        .session-header { background: rgba(255,255,255,0.03); padding: 15px 25px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
        .session-target { font-weight: bold; color: var(--accent); }
        
        .vuln-table { width: 100%; border-collapse: collapse; }
        .vuln-table th { text-align: left; padding: 12px 25px; color: var(--text-dim); font-size: 0.8rem; border-bottom: 1px solid var(--border); }
        .vuln-table td { padding: 15px 25px; border-bottom: 1px solid var(--border); }
        
        .sev-badge { padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }
        .sev-Critical { background: var(--high); box-shadow: 0 0 10px rgba(239, 68, 68, 0.4); }
        .sev-High { background: var(--high); }
        .sev-Medium { background: var(--med); }
        .sev-Low { background: var(--low); }
        
        .payload-box { background: #000; color: var(--low); padding: 8px 12px; border-radius: 6px; font-size: 0.85rem; border: 1px solid #111; }
        
        .empty-state { text-align: center; padding: 40px; color: var(--text-dim); font-style: italic; border: 1px dashed var(--border); border-radius: 12px; }

        .flag-tag { display: inline-block; background: var(--flag); color: #fff; padding: 2px 10px; border-radius: 99px; font-size: 0.8rem; margin: 5px; font-weight: bold; }
        
        .evidence-snippet { font-size: 0.75rem; color: #64748b; margin-top: 8px; display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 400px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>CTFLAB <span class="version">V6.0</span></h1>
                <p style="margin: 5px 0 0; color: var(--text-dim);">Visual Command Center • Operational Intelligence</p>
            </div>
            <div style="text-align: right">
                <div id="clock" style="font-size: 1.2rem; color: var(--accent);"></div>
                <div style="font-size: 0.7rem; color: var(--text-dim);">STATUS: CONNECTED</div>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Sessões Ativas</div>
                <div class="stat-value">{{ total_sessions }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Vulnerabilidades</div>
                <div class="stat-value">{{ total_vulns }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Flags Capturadas</div>
                <div class="stat-value" style="color: var(--flag);">{{ total_flags }}</div>
            </div>
        </div>

        <div class="section-title">DETALHES DAS OPERAÇÕES</div>

        {% if not session_data %}
            <div class="empty-state">Aguardando início de operações para capturar telemetria...</div>
        {% endif %}

        {% for s_id, data in session_data.items() %}
        <div class="session-card">
            <div class="session-header">
                <div>
                    <span class="session-target">{{ data.target }}</span>
                    <span style="color: var(--text-dim); font-size: 0.8rem; margin-left: 15px;">{{ data.date }}</span>
                </div>
                <div>
                    {% for flag in data.flags %}
                        <span class="flag-tag">🚩 {{ flag }}</span>
                    {% endfor %}
                </div>
            </div>
            
            <table class="vuln-table">
                <thead>
                    <tr>
                        <th style="width: 15%;">SEVERIDADE</th>
                        <th style="width: 25%;">MÓDULO</th>
                        <th style="width: 25%;">DESCOBERTA</th>
                        <th style="width: 35%;">PAYLOAD / EVIDÊNCIA</th>
                    </tr>
                </thead>
                <tbody>
                    {% for v in data.vulns %}
                    <tr>
                        <td><span class="sev-badge sev-{{ v.severity }}">{{ v.severity }}</span></td>
                        <td><span style="color: var(--text-main);">{{ v.module }}</span></td>
                        <td>{{ v.name }}</td>
                        <td>
                            <div class="payload-box">{{ v.payload }}</div>
                            {% if v.evidence %}
                                <span class="evidence-snippet">Snippet: {{ v.evidence }}</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                    {% if not data.vulns %}
                    <tr>
                        <td colspan="4" style="text-align: center; color: var(--text-dim); padding: 30px;">
                            Nenhuma vulnerabilidade confirmada até o momento.
                        </td>
                    </tr>
                    {% endif %}
                </tbody>
            </table>
        </div>
        {% endfor %}
    </div>

    <script>
        function updateClock() {
            const now = new Date();
            document.getElementById('clock').innerText = now.toLocaleTimeString('pt-BR');
        }
        setInterval(updateClock, 1000);
        updateClock();
        
        // Auto-refresh do dashboard a cada 30 segundos
        setTimeout(() => window.location.reload(), 30000);
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def index():
    sessions = repo.list_sessions()
    
    session_data = {}
    total_vulns = 0
    total_flags = 0
    
    with repo._get_conn() as conn:
        for s in sessions:
            s_id = s['id']
            # Busca notas e flags
            row = conn.execute("SELECT notes, flags FROM sessions WHERE id = ?", (s_id,)).fetchone()
            notes = json.loads(row[0]) if row and row[0] else []
            flags = json.loads(row[1]) if row and row[1] else []
            total_flags += len(flags)

            # Busca vulnerabilidades com evidência
            vulns = []
            v_rows = conn.execute("""
                SELECT v.module, v.name, v.payload, v.severity, e.snippet 
                FROM vulnerabilities v
                LEFT JOIN evidence e ON v.session_id = e.session_id AND v.module = e.module
                WHERE v.session_id = ?
                GROUP BY v.id
            """, (s_id,)).fetchall()
            
            for vr in v_rows:
                vulns.append({
                    "module": vr[0],
                    "name": vr[1],
                    "payload": vr[2],
                    "severity": vr[3],
                    "evidence": vr[4]
                })
                total_vulns += 1
                
            session_data[s_id] = {
                "target": s['target'],
                "date": s['date'],
                "flags": flags,
                "vulns": vulns
            }
    
    template = jinja_env.from_string(DASHBOARD_TEMPLATE)
    return template.render(
        total_sessions=len(sessions),
        session_data=session_data,
        total_vulns=total_vulns,
        total_flags=total_flags
    )

def run_dashboard(port: int = 8080):
    print(f"[ok] Dashboard subindo em http://localhost:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="error")
