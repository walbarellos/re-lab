# Auditoria Técnica — CTFLab v5.6

**Veredicto: 8.7/10** — Arquitetura sólida, totalmente funcional, sem bugs críticos pendentes.

## Histórico de versões

| Versão | Nota | Status |
|--------|------|--------|
| v5.2   | 7.2  | Não subia (ctflab.cli ausente no ZIP) |
| v5.5   | 7.6  | Subia, mas POST cacheava, async bypssava _record, rules faltando |
| v5.6   | 8.7  | Todos os bugs confirmados corrigidos e testados |

---

## Fixes aplicados na v5.6

### Fix 1 — POST/PUT/PATCH/DELETE com use_cache=False (CRÍTICO)
`http.py`: helpers mutantes agora defaultam `use_cache=False`.
O `_request()` já tinha a lógica correta (`None → GET-only`), mas os wrappers
sobrescreviam com `use_cache=True`. Tokens obsoletos em re-auth estão corrigidos.

### Fix 2 — async_batch_request registra no histórico (ALTO)
`async_batch_request._sem_req()` agora chama `_record()` após cada resposta.
Intel e histórico funcionam em brute force e fuzz async.
Removido o `return` duplicado (dead code após `async with`).

### Fix 3 — Fingerprinter singleton (MÉDIO)
`Fingerprinter()` e `Target()` eram instanciados dentro de `_record()` com
lazy imports a cada chamada. Agora são singleton no topo do módulo.
Em fuzzing de 5k requests: 5k instâncias → 1 instância.

### Fix 4 — DependencyResolver com mapa exato de nomes (MÉDIO)
O resolver só funcionava para `reconnaissance_fuzzer` (único com prefixo correto).
`sqli_detection` e `header_injection` tinham prioridade 99 (unknown).
Adicionado `SCANNER_PRIORITY` com lookup exato por nome registrado + fallback por
prefixo de domínio. Testado: `reconnaissance_fuzzer → sqli_detection → header_injection → forge`.

### Fix 5 — Rules YAML (BAIXO)
Criados `xss_detection.yaml`, `traversal_detection.yaml`, `idor_detection.yaml`.
RuleEngine carrega 4 regras. XSS eval testado.

### Fix 6 — pyproject.toml + setup.cfg (ALTO para usabilidade)
O projeto não tinha nenhum arquivo de packaging. Qualquer usuário novo
deparava com `ModuleNotFoundError` sem saber o porquê.
Agora: `pip install -e .` resolve tudo sem symlinks.

### Fix 7 — SQLi payloads expandidos: 17 → 39
Adicionados: ORDER BY column detection, UNION enumeration, error-based (MySQL),
time-based blind (MySQL/PG/MSSQL), stacked queries, SQLite-specific (sqlite_master).

### Fix 8 — XSS payloads expandidos: 6 → 21
Cobertura: reflected, attribute injection, DOM/URI, filter bypass (case/space/encode),
cookie exfil template.

### Fix 9 — SSTI payloads expandidos: 8 → 18
Cobertura: Jinja2/Python (incluindo RCE via __subclasses__), Twig/PHP,
Freemarker/Java, Pebble/Java, Mako/Python.

### Fix 10 — JWT secrets expandidos: ~15 → 48
Adicionados: defaults de frameworks (Express/Django/Flask/Spring), CTF-style
strings, hashes, comprimentos fixos em hex.

---

## O que ainda pode melhorar (v5.7+)

| # | Item | Esforço |
|---|------|---------|
| 1 | `idor.py` e `traversal.py` como BaseScanner (além do menu interativo) | Médio |
| 2 | `Fingerprinter.analyze()` salvar techs na sessão (não só logar) | Pequeno |
| 3 | `ProfileManager` respeitar timeout/threads do scanner (hoje carrega mas não usa) | Médio |
| 4 | Regras YAML conectadas a `ScanResult` via `RuleEngine.evaluate()` no sqli_scanner | Pequeno |
| 5 | Report HTML incluir vulnerabilidades (hoje só notas e flags) | Médio |
| 6 | `server11.py` — XXE challenge (xmlrpc ou SOAP) | Pequeno |
| 7 | `server12.py` — Path Traversal com LFI | Pequeno |
