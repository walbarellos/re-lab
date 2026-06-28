"""
core/intel.py — extração automática de inteligência das respostas.
"""

from __future__ import annotations

import json
import re
from typing import Any
import httpx

from .session import Session
from .logger import logger

# 🕵️ REGEX BROAD VISION (v6.3.3)
_ENDPOINT_RE = re.compile(
    r'\b(GET|POST|PUT|PATCH|DELETE)\s+([^"\'>\s]+)',
    re.IGNORECASE,
)

_HTML_PATH_RE = re.compile(
    r'(?:href|action|src|data-url|fetch|axios\.(?:get|post)|url)\s*[=:(]\s*["\']'
    r'([^"\'>\s]{2,})["\']',
    re.IGNORECASE,
)

_FIELD_RE  = re.compile(r'"([\w_]+)"\s*:', re.IGNORECASE)
_FLAG_RE   = re.compile(r'(?:CTF|FLAG|HTB|picoCTF|DUCTF)\{[^}]+\}', re.IGNORECASE)

_TOKEN_HEX_RE = re.compile(r'\b[0-9a-f]{32,64}\b', re.IGNORECASE)
_TOKEN_B64_RE = re.compile(r'[A-Za-z0-9+/]{32,}={0,2}')

def _flatten_values(obj: Any) -> list[str]:
    out: list[str] = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_flatten_values(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_flatten_values(v))
    elif isinstance(obj, str):
        out.append(obj)
    return out

def _extract_fields(text: str) -> list[str]:
    found: list[str] = []
    for match in re.finditer(r'\{[^}]+\}', text):
        try:
            obj = json.loads(match.group())
            found.extend(obj.keys())
        except Exception:
            pass
    if not found:
        found = _FIELD_RE.findall(text)
    return found

def _looks_like_token(value: str) -> bool:
    if _TOKEN_HEX_RE.fullmatch(value):
        return True
    if value.count(".") == 2 and all(len(p) > 10 for p in value.split(".")):
        return True
    if len(value) >= 32 and _TOKEN_B64_RE.fullmatch(value):
        if "/" not in value and "+" not in value:
            return True
    return False

# 🕵️ LISTA DE EXCLUSÃO (Somente lixo confirmado v6.3.3)
_IGNORE_EXT = {
    '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.css', '.woff', '.woff2', 
    '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.zip', '.tar', '.gz'
}

def _is_noise(path: str) -> bool:
    p_lower = path.lower().split('?')[0]
    if any(x in p_lower for x in ["api", "rest", "admin", "login", "auth", "graphql", "db", "config"]):
        return False
    if any(p_lower.endswith(ext) for ext in _IGNORE_EXT):
        return True
    return False

def analyze(
    session: Session,
    body: str,
    status: int,
    headers: dict | None = None,
) -> dict[str, Any]:
    if not body.strip():
        return {}

    body = body.replace("\\/", "/")
    discovered: dict[str, Any] = {}

    try:
        data = json.loads(body)
    except Exception:
        data = {}

    all_strings = _flatten_values(data) + [body]
    discovered_endpoints = session.recall("_all_discovered_endpoints", set())
    if isinstance(discovered_endpoints, list): 
        discovered_endpoints = set(discovered_endpoints)

    # 🕸️ 1. JS SPIDER: Busca e analisa arquivos JS linkados
    scripts = re.findall(r'src=["\']([^"\']+\.js)["\']', body, re.I)
    # 🔍 BUSCA EM JSON: Se for JSON, busca qualquer string que termine em .js
    if not scripts:
        scripts = re.findall(r'["\']([^"\'\s]+\.js)["\']', body, re.I)

    if scripts:
        from urllib.parse import urlparse
        target_netloc = urlparse(session.target).netloc

        with httpx.Client(verify=False, timeout=3.0) as client:
            for js_url in scripts:
                # ── Proteção contra SSRF: Valida se a URL é interna/externa ──
                if js_url.startswith("http"):
                    parsed_js = urlparse(js_url)
                    # Só permite se for do mesmo domínio do alvo original
                    if parsed_js.netloc != target_netloc:
                        logger.warning(f"Intel Spider: Ignorando script externo/potencial SSRF: {js_url}")
                        continue
                    full_url = js_url
                else:
                    full_url = session.target.rstrip("/") + "/" + js_url.lstrip("/")
                
                if full_url in session._visited_js:
                    continue
                session._visited_js.add(full_url)

                try:
                    js_resp = client.get(full_url)
                    if js_resp.status_code == 200:
                        # Extrai caminhos que pareçam rotas de API do código JS
                        js_hints = re.findall(r"['\"](/(?:api|rest|v1|v2|user|admin|auth|ftp|assets)[\w/\-.]*)['\"]", js_resp.text)
                        extra_hints = re.findall(r"['\"](/[a-z0-9_\-]+/[a-z0-9_\-]+)['\"]", js_resp.text)
                        
                        for hint in (js_hints + extra_hints):
                            if len(hint) > 3 and hint not in discovered_endpoints and not _is_noise(hint):
                                session.remember(f"js_hint_{hint}", hint)
                                discovered_endpoints.add(hint)
                                all_strings.append(hint)
                                if hint.endswith(".js") and hint not in scripts:
                                    scripts.append(hint)

                        # SECRET HUNTER
                        secrets_regex = r"(?i)(?:key|password|secret|token|auth|admin|credential|access_key)['\"]\s*[:=]\s*['\"]([^\"'>\s]{4,})['\"]"
                        secrets = re.findall(secrets_regex, js_resp.text)
                        for s in secrets:
                            if len(s) < 100: 
                                session.remember("leaked_secret", s)

                        for m in _FLAG_RE.finditer(js_resp.text):
                            session.flag(m.group())
                except Exception:
                    pass

    # ── endpoints ─────────────────────────────────────────────
    seen_paths: set[str] = set()
    for s in all_strings:
        for m in _ENDPOINT_RE.finditer(s):
            method, path = m.group(1).upper(), m.group(2)
            if path in seen_paths or _is_noise(path):
                continue
            seen_paths.add(path)
            discovered_endpoints.add(path)

    for m in _HTML_PATH_RE.finditer(body):
        path = m.group(1).split("?")[0]
        if path in seen_paths or len(path) < 2 or _is_noise(path):
            continue
        seen_paths.add(path)
        discovered_endpoints.add(path)

    # 🕵️ HEURÍSTICA SPA
    juice_shop_patterns = [
        r"/rest/(?:user|admin|product|basket|languages|feedback|captcha)",
        r"/api/(?:Users|Products|Baskets|Feedbacks|Cards)",
        r"/ftp/(?:legal|coupons|package|declarations)",
        r"/assets/i18n/(?:en|de|pt|zh|es|fr)\.json",
    ]
    for pattern in juice_shop_patterns:
        matches = re.findall(pattern, body, re.I)
        for m in matches:
            if m not in discovered_endpoints and not _is_noise(m):
                discovered_endpoints.add(m)

    session.remember("_all_discovered_endpoints", list(discovered_endpoints))

    # ── flags ─────────────────────────────────────────────────
    for s_val in all_strings:
        for m in _FLAG_RE.finditer(s_val):
            session.flag(m.group())

    # ── tokens ────────────────────────────────────────────────
    token_keys = {"token", "access_token", "jwt", "auth_token", "api_key"}
    if isinstance(data, dict):
        for k, v in data.items():
            if k.lower() in token_keys and isinstance(v, str) and len(v) > 10:
                session.remember("token", v)
                # Injeta no client imediatamente — toda requisição seguinte
                # sai com Authorization: Bearer <token> automaticamente
                if "Authorization" not in session.headers:
                    session.set_header("Authorization", f"Bearer {v}")

    # REFLECTION
    last_req = session.history[-1] if session.history else None
    if last_req:
        params = last_req.payload or {}
        if isinstance(params, dict):
            for k, v in params.items():
                if isinstance(v, str) and len(v) > 3 and v in body:
                    session.remember(f"reflected_{k}", k)

    if headers:
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            for m in re.finditer(r'([^=;\s]+)=([^;]{4,})', set_cookie):
                session.remember(f"cookie_{m.group(1)}", m.group(2))

    return {}
