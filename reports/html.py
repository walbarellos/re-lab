"""
reports/html.py — Gerador de Relatórios Profissionais.

Consolida evidências, vulnerabilidades e cronograma da sessão
em um documento HTML estético e funcional.
"""

from pathlib import Path
from datetime import datetime
from ctflab.core.session import Session

class HTMLReportGenerator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def generate(self, session: Session) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.html"
        report_path = self.output_dir / filename

        # Template HTML básico (estilo 2026 / God Mode)
        html_content = f"""
        <!DOCTYPE html>
        <html lang="pt-br">
        <head>
            <meta charset="UTF-8">
            <title>CTFLab Report - {session.target}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #e2e8f0; margin: 40px; }}
                h1 {{ color: #38bdf8; border-bottom: 2px solid #1e293b; padding-bottom: 10px; }}
                .summary {{ background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
                .vuln-card {{ background: #1e293b; border-left: 5px solid #ef4444; padding: 15px; margin: 15px 0; border-radius: 4px; }}
                .severity-High {{ border-left-color: #ef4444; }}
                .severity-Medium {{ border-left-color: #f59e0b; }}
                .severity-Low {{ border-left-color: #10b981; }}
                .evidence {{ background: #000; padding: 10px; color: #10b981; font-family: monospace; overflow-x: auto; }}
                .flag {{ background: #db2777; color: white; padding: 5px 10px; border-radius: 20px; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>Relatório de Pentest - CTFLab v5.0</h1>
            <div class="summary">
                <p><strong>Alvo:</strong> {session.target}</p>
                <p><strong>Nível de Risco:</strong> <span class="score-badge">{self._calculate_total_score(session)}</span> / 10.0</p>
                <p><strong>Vulnerabilidades:</strong> {len(session.vulnerabilities)}</p>
                <p><strong>Flags:</strong> {len(session.flags)}</p>
            </div>

            <h2>Vulnerabilidades Encontradas</h2>
            {"".join(self._render_vuln(v) for v in session.vulnerabilities) if session.vulnerabilities else "<p>[dim]Nenhuma vulnerabilidade registrada nesta sessão.[/dim]</p>"}

            <h2>Flags Capturadas</h2>
            <p>{" ".join(f'<span class="flag">{f}</span>' for f in session.flags)}</p>
            
            <h2>Histórico de Operações</h2>
            <ul>
                {"".join(f"<li>{note}</li>" for note in session.notes)}
            </ul>
        </body>
        </html>
        """
        
        report_path.write_text(html_content)
        return report_path

    def _calculate_total_score(self, session: Session) -> float:
        from ctflab.core.scoring import ScoringEngine
        return ScoringEngine.calculate_session_score(session.vulnerabilities)

    def _render_vuln(self, v):
        return f"""
        <div class="vuln-card severity-{v.severity}">
            <h3>[{v.severity}] {v.name}</h3>
            <p><strong>Módulo:</strong> {v.module} | <strong>Confiança:</strong> {v.confidence*100}%</p>
            <p><strong>Payload:</strong> <code>{v.payload}</code></p>
            <div class="evidence">
                <pre>{v.evidence[0].response_snippet if v.evidence else "Nenhuma evidência capturada"}</pre>
            </div>
        </div>
        """
