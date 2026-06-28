# CTFLab v5.6

Plataforma de treinamento em reverse engineering e pentest web.

## Instalação

```bash
cd ctflab_package
pip install -e .
```

Ou sem instalação (adicionar o diretório pai ao PYTHONPATH):

```bash
export PYTHONPATH=/caminho/para/ctflab_package:$PYTHONPATH
cd ctflab_package/ctflab
python main.py
```

## Servidores de desafio

| Servidor | Vulnerabilidade | Flag |
|----------|----------------|------|
| server6.py  | Mass Assignment (PUT /me) | CTF{m4ss_4ss1gnm3nt_0wn3d} |
| server7.py  | SSTI Jinja2            | - |
| server8.py  | SSTI filtro bypassado  | - |
| server9.py  | Hidden params          | - |
| server10.py | JWT HS256 secret fraco | CTF{jwt_secrets_should_not_be_guessable} |

Rodar qualquer servidor: `python server6.py` → `http://localhost:1337`

## Changelog v5.6

- POST/PUT/PATCH/DELETE nunca cacheiam por padrão (tokens obsoletos corrigidos)
- async_batch_request registra no histórico (brute/fuzz async alimenta intel)
- Fingerprinter singleton (sem instância por chamada)
- DependencyResolver com lookup exato de nomes de scanner
- Rules YAML: xss_detection, traversal_detection, idor_detection adicionados
- pyproject.toml — instalação via pip agora funciona
- SQLi payloads: 17 → 39 (blind, error-based, UNION, SQLite)
- XSS payloads: 6 → 21 (filter bypass, DOM, cookie exfil)
- SSTI payloads: 8 → 18 (Jinja2 RCE, Twig, Freemarker, Mako)
- JWT secrets: ~15 → 48 (frameworks, CTF-style, hashes)
