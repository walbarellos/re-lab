"""
reports/html.py — Gerador de Relatórios Profissionais e Estéticos do CTFLab.

Consolida as descobertas da sessão, incluindo dados de risco preditivo, stacks
detectadas, endpoints identificados e vulnerabilidades, em um layout HTML estético
de alta fidelidade.
"""

from __future__ import annotations

from pathlib import Path
from datetime import datetime
from typing import Any
from ctflab.core.session import Session

class HTMLReportGenerator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def generate(self, session: Session) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.html"
        report_path = self.output_dir / filename

        # 📊 Cálculo dos índices de risco detalhados
        all_eps = session.recall("_all_discovered_endpoints", [])
        from ctflab.core.scoring import ScoringEngine
        risk_report = ScoringEngine.calculate_session_score(session.vulnerabilities, all_eps)

        confirmed_risk = risk_report.get("confirmed_risk", 0.0)
        exposure_level = risk_report.get("exposure_level", 0.0)
        total_threat = risk_report.get("total_threat", 0.0)

        # 🏷️ Badge e cor do score de risco global
        threat_color = "#10b981"  # Verde (Low)
        threat_status = "Baixo Risco"
        if total_threat >= 7.0:
            threat_color = "#ef4444"  # Vermelho (Critical)
            threat_status = "Ameaça Crítica"
        elif total_threat >= 4.0:
            threat_color = "#f59e0b"  # Laranja (Medium)
            threat_status = "Ameaça Média"

        # ⚙️ Geração do HTML com visual premium e moderno (Glassmorphism & Neon Accent)
        html_content = f"""<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório CTFLab - {session.target}</title>
    <style>
        :root {{
            --bg-dark: #0b0f19;
            --card-bg: #111827;
            --card-border: #1f2937;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.15);
            --flag-pink: #ec4899;
        }}

        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-primary);
            margin: 0;
            padding: 40px 20px;
            display: flex;
            justify-content: center;
        }}

        .container {{
            max-width: 1000px;
            width: 100%;
        }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--card-border);
            padding-bottom: 20px;
            margin-bottom: 40px;
        }}

        h1 {{
            color: var(--accent);
            margin: 0;
            font-size: 2.2rem;
            text-shadow: 0 0 10px rgba(56, 189, 248, 0.3);
        }}

        .meta-time {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        /* Grid de Informações da Sessão */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}

        .card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}

        .card h3 {{
            margin-top: 0;
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .card-value {{
            font-size: 1.8rem;
            font-weight: bold;
            margin: 10px 0;
        }}

        /* Medidor de Ameaça Global */
        .threat-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: bold;
            margin-top: 5px;
            color: #fff;
        }}

        /* Tecnologias Detectadas */
        .tech-tag {{
            display: inline-block;
            background: rgba(56, 189, 248, 0.1);
            color: var(--accent);
            border: 1px solid rgba(56, 189, 248, 0.3);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.9rem;
            margin-right: 8px;
            margin-bottom: 8px;
            font-weight: 500;
        }}

        .section-title {{
            border-left: 4px solid var(--accent);
            padding-left: 12px;
            margin-top: 40px;
            margin-bottom: 20px;
            font-size: 1.5rem;
            color: var(--text-primary);
        }}

        /* Cartão de Vulnerabilidade */
        .vuln-card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
        }}

        .vuln-header {{
            padding: 16px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: bold;
        }}

        .vuln-header.severity-Critical {{ background: rgba(239, 68, 68, 0.1); border-bottom: 1px solid rgba(239, 68, 68, 0.2); }}
        .vuln-header.severity-High {{ background: rgba(245, 158, 11, 0.1); border-bottom: 1px solid rgba(245, 158, 11, 0.2); }}
        .vuln-header.severity-Medium {{ background: rgba(59, 130, 246, 0.1); border-bottom: 1px solid rgba(59, 130, 246, 0.2); }}
        .vuln-header.severity-Low {{ background: rgba(16, 185, 129, 0.1); border-bottom: 1px solid rgba(16, 185, 129, 0.2); }}

        .vuln-badge {{
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.75rem;
            text-transform: uppercase;
            color: #fff;
        }}

        .vuln-badge.severity-Critical {{ background-color: #ef4444; }}
        .vuln-badge.severity-High {{ background-color: #f59e0b; }}
        .vuln-badge.severity-Medium {{ background-color: #3b82f6; }}
        .vuln-badge.severity-Low {{ background-color: #10b981; }}

        .vuln-body {{
            padding: 20px;
        }}

        .vuln-meta {{
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin-bottom: 15px;
        }}

        .vuln-meta strong {{
            color: var(--text-primary);
        }}

        .code-box {{
            background: #090d16;
            border: 1px solid #1f2937;
            border-radius: 6px;
            padding: 12px 16px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.9rem;
            color: #a7f3d0;
            overflow-x: auto;
            margin-top: 10px;
        }}

        /* Flags Section */
        .flag-box {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 30px;
        }}

        .flag-pill {{
            background: rgba(236, 72, 153, 0.1);
            color: var(--flag-pink);
            border: 1px solid rgba(236, 72, 153, 0.3);
            padding: 8px 16px;
            border-radius: 30px;
            font-weight: bold;
            font-family: monospace;
            box-shadow: 0 0 10px rgba(236, 72, 153, 0.15);
        }}

        /* Endpoints / Paths List */
        .endpoints-list {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 8px;
            padding: 15px;
            font-family: monospace;
            font-size: 0.95rem;
            color: #34d399;
            max-height: 250px;
            overflow-y: auto;
        }}

        .endpoints-list div {{
            padding: 6px 10px;
            border-bottom: 1px solid #1e293b;
        }}

        .endpoints-list div:last-child {{
            border-bottom: none;
        }}

        /* Cronograma das notas */
        .notes-timeline {{
            list-style: none;
            padding-left: 0;
            margin: 0;
        }}

        .notes-timeline li {{
            position: relative;
            padding-left: 24px;
            margin-bottom: 15px;
            font-size: 0.95rem;
            color: var(--text-secondary);
        }}

        .notes-timeline li::before {{
            content: '';
            position: absolute;
            left: 0;
            top: 6px;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent);
            box-shadow: 0 0 8px var(--accent);
        }}

        .empty-state {{
            color: var(--text-secondary);
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>CTFLab Audit Report</h1>
                <div class="meta-time">Sessão finalizada em {datetime.now().strftime("%d/%m/%Y às %H:%M:%S")}</div>
            </div>
            <div>
                <span style="font-weight: bold; color: var(--accent);">v5.7 Stable</span>
            </div>
        </header>

        <div class="summary-grid">
            <!-- Risco Geral -->
            <div class="card" style="border-top: 4px solid {threat_color};">
                <h3>Ameaça Global</h3>
                <div class="card-value" style="color: {threat_color};">{total_threat} <span style="font-size: 1.1rem; color: var(--text-secondary);">/ 10.0</span></div>
                <span class="threat-badge" style="background-color: {threat_color};">{threat_status}</span>
            </div>

            <!-- Detalhes do Risco -->
            <div class="card">
                <h3>Métricas de Risco</h3>
                <p style="margin: 6px 0;">Risco Confirmado: <strong>{confirmed_risk} / 10.0</strong></p>
                <p style="margin: 6px 0;">Nível de Exposição: <strong>{exposure_level} / 10.0</strong></p>
                <p style="margin: 6px 0;">Alvo URL: <strong style="font-size: 0.85rem; color: var(--accent); word-break: break-all;">{session.target}</strong></p>
            </div>

            <!-- Números da Operação -->
            <div class="card">
                <h3>Ações Realizadas</h3>
                <p style="margin: 6px 0;">Requisições Totais: <strong>{len(session.history)}</strong></p>
                <p style="margin: 6px 0;">Vulnerabilidades: <strong>{len(session.vulnerabilities)}</strong></p>
                <p style="margin: 6px 0;">Flags Capturadas: <strong>{len(session.flags)}</strong></p>
            </div>
        </div>

        <!-- Tecnologias Classificadas -->
        <div class="section-title">Tecnologias Identificadas</div>
        <div class="card" style="margin-bottom: 40px;">
            { "".join(f'<span class="tech-tag">{tech}</span>' for tech in session._technologies) if session._technologies else '<span class="empty-state">Nenhuma tecnologia/CMS identificada de forma conclusiva.</span>' }
        </div>

        <!-- Flags Section -->
        { f'<div class="section-title">Flags Capturadas ({len(session.flags)})</div><div class="flag-box">' + "".join(f'<span class="flag-pill">🏁 {f}</span>' for f in session.flags) + '</div>' if session.flags else '' }

        <!-- Vulnerabilidades Section -->
        <div class="section-title">Vulnerabilidades Detectadas ({len(session.vulnerabilities)})</div>
        { "".join(self._render_vuln(v) for v in session.vulnerabilities) if session.vulnerabilities else '<p class="empty-state">Nenhuma vulnerabilidade confirmada registrada nesta sessão.</p>' }

        <!-- Endpoints Descobertos -->
        <div class="section-title">Endpoints e Rotas Identificados ({len(all_eps)})</div>
        <div class="endpoints-list" style="margin-bottom: 40px;">
            { "".join(f"<div>GET / POST {ep}</div>" for ep in sorted(all_eps)) if all_eps else '<div class="empty-state">Nenhum endpoint secundário mapeado durante o reconhecimento.</div>' }
        </div>

        <!-- Histórico e Notas -->
        <div class="section-title">Diário Técnico de Operações</div>
        <div class="card" style="margin-bottom: 60px;">
            { f'<ul class="notes-timeline">' + "".join(f"<li>{note}</li>" for note in session.notes) + '</ul>' if session.notes else '<p class="empty-state">Nenhuma nota ou log de eventos disponível.</p>' }
        </div>
    </div>
</body>
</html>
        """
        
        report_path.write_text(html_content, encoding="utf-8")
        return report_path

    def _render_vuln(self, v: Any) -> str:
        evidence_snippet = v.evidence[0].response_snippet if v.evidence else "Nenhuma evidência textual capturada."
        evidence_payload = v.evidence[0].payload if v.evidence else v.payload
        evidence_status = v.evidence[0].status if v.evidence else 200

        return f"""
        <div class="vuln-card">
            <div class="vuln-header severity-{v.severity}">
                <span>{v.name}</span>
                <span class="vuln-badge severity-{v.severity}">{v.severity}</span>
            </div>
            <div class="vuln-body">
                <div class="vuln-meta">
                    Módulo Ativo: <strong>{v.module}</strong> | 
                    Grau de Confiança: <strong>{v.confidence*100:.0f}%</strong> | 
                    Status HTTP da Evidência: <strong>{evidence_status}</strong>
                </div>
                <div style="font-weight: bold; margin-bottom: 8px;">Payload de Disparo:</div>
                <div class="code-box" style="color: #60a5fa; font-weight: bold;">{evidence_payload}</div>
                <div style="font-weight: bold; margin-top: 15px; margin-bottom: 8px;">Snippet de Resposta (Evidência):</div>
                <div class="code-box">{evidence_snippet}</div>
            </div>
        </div>
        """
