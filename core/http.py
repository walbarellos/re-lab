"""
core/http.py — camada HTTP isolada.

GET, POST, PUT, PATCH, DELETE + fuzz assíncrono + race condition.
Retry com backoff exponencial. Toggle SSL.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from .session import RequestRecord, Session
from .intel import analyze as intel_analyze
from .fingerprint import Fingerprinter as _Fingerprinter
from .models import Target as _Target
from .waf import WafDetector


_fingerprinter = _Fingerprinter()  # singleton — instanciar uma vez

_DEFAULT_RETRY = 2
_BACKOFF_BASE  = 0.3


# ── fábrica de cliente ────────────────────────────────────────

import random

# 🕵️ LISTA DE USER-AGENTS REAIS (v6.1.1)
_UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1"
]

def make_client(session: Session) -> httpx.Client:
    headers = dict(session.headers)
    headers.setdefault("User-Agent", random.choice(_UA_LIST))
    headers.setdefault("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
    headers.setdefault("Accept-Language", "en-US,en;q=0.9")
    headers.setdefault("Sec-Fetch-Dest", "document")
    headers.setdefault("Sec-Fetch-Mode", "navigate")
    headers.setdefault("Sec-Fetch-Site", "none")
    headers.setdefault("Sec-Fetch-User", "?1")

    # 🛡️ WAF Bypass / IP Spoofing (Essencial para bypass local e rate-limits em CTFs)
    if getattr(session, "waf_bypass", False):
        spoofed_ip = "127.0.0.1"
        headers.setdefault("X-Forwarded-For", spoofed_ip)
        headers.setdefault("X-Originating-IP", spoofed_ip)
        headers.setdefault("X-Real-IP", spoofed_ip)
        headers.setdefault("X-Remote-IP", spoofed_ip)
        headers.setdefault("X-Remote-Addr", spoofed_ip)
        headers.setdefault("X-Client-IP", spoofed_ip)
        headers.setdefault("Client-IP", spoofed_ip)

    # 🍪 Cookie Session Persistence
    cookies_list = [f"{ck[7:]}={cv}" for ck, cv in session.ctx.items() if ck.startswith("cookie_") and isinstance(cv, str)]
    if cookies_list:
        existing_cookie = headers.get("Cookie", "")
        if existing_cookie:
            headers["Cookie"] = existing_cookie.rstrip("; ") + "; " + "; ".join(cookies_list)
        else:
            headers["Cookie"] = "; ".join(cookies_list)

    # 🛡️ CSRF Token Injection
    csrf_token = session.recall("csrf_token", "")
    if csrf_token:
        headers.setdefault("X-CSRF-Token", csrf_token)
        headers.setdefault("X-CSRFToken", csrf_token)
        headers.setdefault("X-XSRF-TOKEN", csrf_token)

    return httpx.Client(
        base_url=session.target,
        headers=headers,
        timeout=session.timeout,
        follow_redirects=True,
        verify=session.ssl,
        proxy=session.proxy,
    )


def make_async_client(session: Session) -> httpx.AsyncClient:
    headers = dict(session.headers)
    headers.setdefault("User-Agent", random.choice(_UA_LIST))
    headers.setdefault("Accept", "application/json, text/plain, */*")
    headers.setdefault("Accept-Language", "en-US,en;q=0.9")
    headers.setdefault("Sec-Ch-Ua", '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"')
    headers.setdefault("Sec-Ch-Ua-Mobile", "?0")
    headers.setdefault("Sec-Ch-Ua-Platform", '"Windows"')

    # 🛡️ WAF Bypass / IP Spoofing (Essencial para bypass local e rate-limits em CTFs)
    if getattr(session, "waf_bypass", False):
        spoofed_ip = "127.0.0.1"
        headers.setdefault("X-Forwarded-For", spoofed_ip)
        headers.setdefault("X-Originating-IP", spoofed_ip)
        headers.setdefault("X-Real-IP", spoofed_ip)
        headers.setdefault("X-Remote-IP", spoofed_ip)
        headers.setdefault("X-Remote-Addr", spoofed_ip)
        headers.setdefault("X-Client-IP", spoofed_ip)
        headers.setdefault("Client-IP", spoofed_ip)

    # 🍪 Cookie Session Persistence
    cookies_list = [f"{ck[7:]}={cv}" for ck, cv in session.ctx.items() if ck.startswith("cookie_") and isinstance(cv, str)]
    if cookies_list:
        existing_cookie = headers.get("Cookie", "")
        if existing_cookie:
            headers["Cookie"] = existing_cookie.rstrip("; ") + "; " + "; ".join(cookies_list)
        else:
            headers["Cookie"] = "; ".join(cookies_list)

    # 🛡️ CSRF Token Injection
    csrf_token = session.recall("csrf_token", "")
    if csrf_token:
        headers.setdefault("X-CSRF-Token", csrf_token)
        headers.setdefault("X-CSRFToken", csrf_token)
        headers.setdefault("X-XSRF-TOKEN", csrf_token)

    return httpx.AsyncClient(
        base_url=session.target,
        headers=headers,
        timeout=session.timeout,
        follow_redirects=True,
        verify=session.ssl,
        proxy=session.proxy,
    )




# aliases de retrocompatibilidade
_make_client       = make_client
_make_async_client = make_async_client


# ── registro ──────────────────────────────────────────────────

def _record(
    session: Session,
    method: str,
    path: str,
    payload: Any,
    r: httpx.Response,
    elapsed: float,
) -> RequestRecord:
    rec = RequestRecord(
        method=method,
        url=str(r.url),
        payload=payload,
        status=r.status_code,
        body=r.text,
        elapsed=elapsed,
    )
    session.add_record(rec)
    
    # 🔍 INTEGRAÇÃO INTEL: Analisa a resposta automaticamente
    intel_analyze(session, r.text, r.status_code, dict(r.headers))

    # 🕵️ INTEGRAÇÃO FINGERPRINT: Detecta stack (v6.1.1 — Persistent)
    _fingerprinter.analyze(r, _Target(base_url=session.target, technologies=session._technologies), session)

    # 🛡️ INTEGRAÇÃO WAF: Identifica firewalls e adapta comportamento
    WafDetector.detect_and_adapt(session, r.text, r.status_code, dict(r.headers))

    return rec

# ── núcleo síncrono ───────────────────────────────────────────

def _request(
    session: Session,
    method: str,
    path: str,
    payload: Any = None,
    params: dict | None = None,
    form: bool = False,
    retries: int | None = None,
    headers: dict | None = None,
    raw: bool = False,
    use_cache: bool | None = None,
) -> httpx.Response:
    method    = method.upper()
    
    if retries is None:
        retries = getattr(session, "retries", _DEFAULT_RETRY)

    
    # 🧠 CACHE POLICY: Só cacheia GET por padrão. Outros métodos requerem flag explícita.
    if use_cache is None:
        use_cache = (method == "GET")

    # 🧠 INTEGRAÇÃO CACHE: Verifica se já temos a resposta
    cache = getattr(session, "_cache", None)
    if use_cache and cache:
        cached = cache.get(method, path, payload, params)
        if cached:
            return cached

    last_exc: Exception | None = None

    for attempt in range(retries + 1):
        try:
            with make_client(session) as c:
                start       = time.perf_counter()
                req_headers = headers or {}
                csrf_token = session.recall("csrf_token", "")
                kwargs: dict = {"params": params or {}}


                if payload is not None:
                    # Injeta CSRF no corpo de requisições de alteração (JSON/Form)
                    if isinstance(payload, dict) and method in ("POST", "PUT", "PATCH", "DELETE") and csrf_token:
                        payload = dict(payload) # Evita alterar in-place o dicionário original
                        csrf_param = session.recall("csrf_param_name", "csrf_token")
                        if csrf_param not in payload:
                            payload[csrf_param] = csrf_token

                    if raw:
                        kwargs["content"] = str(payload)
                    elif form:
                        kwargs["data"] = payload
                    else:
                        kwargs["json"] = payload
                        if (
                            "Content-Type" not in session.headers
                            and "Content-Type" not in req_headers
                        ):
                            req_headers["Content-Type"] = "application/json"


                r       = c.request(method, path, headers=req_headers, **kwargs)
                elapsed = time.perf_counter() - start

                # Se o servidor retornar rate limit (429) ou erro temporário (503), faz backoff inteligente
                if r.status_code in (429, 503) and attempt < retries:
                    retry_after = r.headers.get("Retry-After", "")
                    try:
                        sleep_time = float(retry_after)
                    except ValueError:
                        sleep_time = _BACKOFF_BASE * (2 ** attempt)
                    sleep_time += random.uniform(0.1, 0.4) # Jitter
                    time.sleep(sleep_time)
                    continue

            # 🕵️ HUMAN JITTER: Se estiver em modo stealth, espera um pouco entre requisições
            if getattr(session, "stealth_mode", False):
                delay = random.uniform(0.5, 1.8)
                time.sleep(delay)

            _record(session, method, path, payload, r, elapsed)
            
            # Salva no cache se habilitado
            if use_cache and cache:
                cache.set(method, path, r, payload, params)
                
            return r

        except httpx.RequestError as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(_BACKOFF_BASE * (2 ** attempt))

    raise last_exc  # type: ignore[misc]



def get(session, path="/", params=None, payload=None, retries=_DEFAULT_RETRY, headers=None, use_cache=True):
    return _request(session, "GET", path, payload=payload, params=params, retries=retries, headers=headers, use_cache=use_cache)

def post(session, path="/", payload=None, params=None, form=False, retries=_DEFAULT_RETRY, headers=None, use_cache=False):
    """POST nunca cacheia por padrão — evita tokens obsoletos em re-auth."""
    return _request(session, "POST", path, payload=payload, params=params, form=form, retries=retries, headers=headers, use_cache=use_cache)

def put(session, path="/", payload=None, params=None, form=False, retries=_DEFAULT_RETRY, headers=None, use_cache=False):
    """PUT/PATCH/DELETE nunca cacheiam por padrão — operações mutantes."""
    return _request(session, "PUT", path, payload=payload, params=params, form=form, retries=retries, headers=headers, use_cache=use_cache)

def patch(session, path="/", payload=None, params=None, retries=_DEFAULT_RETRY, headers=None, use_cache=False):
    return _request(session, "PATCH", path, payload=payload, params=params, retries=retries, headers=headers, use_cache=use_cache)

def delete(session, path="/", params=None, retries=_DEFAULT_RETRY, headers=None, use_cache=False):
    return _request(session, "DELETE", path, params=params, retries=retries, headers=headers, use_cache=use_cache)

def request(session, method, path, payload=None, params=None, form=False, headers=None, use_cache=None):
    """Generic wrapper — herda a política de cache do método (GET cacheia, resto não)."""
    return _request(session, method, path, payload=payload, params=params, form=form, headers=headers, use_cache=use_cache)


# ── fuzzing assíncrono ────────────────────────────────────────

async def _async_fuzz(
    session: Session,
    wordlist: list[str],
    base_path: str = "/",
    max_concurrency: int = 20,
) -> list[tuple[str, int, int, str]]:
    semaphore = asyncio.Semaphore(max_concurrency)

    async def probe(client: httpx.AsyncClient, word: str):
        full = f"{base_path.rstrip('/')}/{word.lstrip('/')}"
        async with semaphore:
            # 🕵️ ASYNC JITTER: Pequeno delay aleatório para mimetismo
            await asyncio.sleep(random.uniform(0.2, 0.8))
            start = time.perf_counter()
            try:
                r = await client.get(full)
                elapsed = time.perf_counter() - start
                if r.status_code != 404:
                    # Registra a descoberta para alimentar o motor de inteligência
                    _record(session, "GET", full, None, r, elapsed)
                    return (full, r.status_code, len(r.content), r.text[:60])
            except Exception:
                pass
        return None

    async with make_async_client(session) as c:
        tasks   = [probe(c, w) for w in wordlist]
        results = await asyncio.gather(*tasks)

    return [r for r in results if r is not None]


def fuzz(
    session: Session,
    wordlist: list[str],
    base_path: str = "/",
    max_concurrency: int = 20,
) -> list[tuple[str, int, int, str]]:
    return asyncio.run(_async_fuzz(session, wordlist, base_path, max_concurrency))


# ── race condition ─────────────────────────────────────────────

async def _gather_normal(session, path, payload, n):
    async with make_async_client(session) as c:
        tasks     = [c.post(path, json=payload) for _ in range(n)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
    return [
        (r.status_code, r.text) if not isinstance(r, Exception) else (-1, str(r))
        for r in responses
    ]


async def _gather_synchronized(session, path, payload, n):
    gate = asyncio.Event()

    async def worker(client):
        await gate.wait()
        try:
            r = await client.post(path, json=payload)
            return r.status_code, r.text
        except Exception as exc:
            return -1, str(exc)

    async with make_async_client(session) as c:
        tasks = [asyncio.create_task(worker(c)) for _ in range(n)]
        await asyncio.sleep(0.05)
        gate.set()
        results = await asyncio.gather(*tasks)

    return list(results)


def race(
    session: Session,
    path: str,
    payload: Any,
    n: int = 10,
    synchronized: bool = False,
) -> list[tuple[int, str]]:
    if synchronized:
        return asyncio.run(_gather_synchronized(session, path, payload, n))
    return asyncio.run(_gather_normal(session, path, payload, n))


# ── batch assíncrono genérico ─────────────────────────────────

async def async_batch_request(
    session: Session,
    method: str,
    paths: list[str],
    payloads: list[Any] | None = None,
    max_concurrency: int = 20,
) -> list[httpx.Response | Exception]:
    """
    Dispara múltiplas requisições concorrentes.
    Todas as respostas passam por _record() → intel e histórico funcionam em brute/fuzz async.
    """
    semaphore = asyncio.Semaphore(max_concurrency)

    async def _sem_req(client, path, payload):
        async with semaphore:
            start = time.perf_counter()
            try:
                if method.upper() == "GET":
                    r = await client.get(path)
                else:
                    r = await client.request(method, path, json=payload)
                elapsed = time.perf_counter() - start
                # ── Registra no histórico e alimenta o intel ──
                _record(session, method, path, payload, r, elapsed)
                return r
            except Exception as e:
                return e

    async with make_async_client(session) as client:
        tasks = [
            _sem_req(client, p, payloads[i] if payloads and i < len(payloads) else None)
            for i, p in enumerate(paths)
        ]
        return await asyncio.gather(*tasks)
