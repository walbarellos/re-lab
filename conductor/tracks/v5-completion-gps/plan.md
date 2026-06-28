# GPS Implementation Plan: Path to 9.5+

## Priority 1: Critical Blockers (The "Tool doesn't run" fixes)
- [ ] 1.1. CLI Package Check: Ensure `cli/` exists and is properly structured.
- [x] 1.2. Module-Level Shims (`core/payloads.py`): Add `load`, `save`, `list_available` shims.
- [x] 1.3. Wordlist Alignment: Convert `params.txt` to `params.yaml` or add fallback.
- [x] 1.4. Missing Wordlists: Create `xss.yaml`, `traversal.yaml`, `paths.yaml`, etc.

## Priority 2: System Intelligence (Connecting the dots)
- [x] 2.1. Intel Integration: Call `intel.analyze()` within `http._record()`.
- [x] 2.2. Scanner Capabilities: Fill `capabilities` lists in all DDD scanners.
- [x] 2.3. Severity Propagation: Pass `best_rule.severity` from `analyze` to `Vulnerability`.
- [x] 2.4. Cache Integration: Implement `ResponseCache` lookups in `http._request()`.

## Priority 3: Exploit Refinement (Precision Engineering)
- [x] 3.1. SSTI Default Update: Set `cycler` bypass as the primary template.
- [x] 3.2. Redirect Headers Fix: Ensure `redirect.py` propagates session headers.
- [x] 3.3. Real Dependency Sorting: Implement `sort_by_dependency` in `WorkflowEngine`.

## Priority 4: Resilience and Testing
- [x] 4.1. Standardize Server Concurrency: Add `ThreadingMixIn` to all server scripts.
- [ ] 4.2. Base Unit Tests: Create `tests/` for `intel`, `scoring`, and `rules`.

## Priority 5: v5.7 Final Polish (Modernization)
- [x] 5.1. DDD Scanners: Implement `IDORScanner` and `TraversalScanner`.
- [x] 5.2. Profile Propagation: Scanners now respect `timeout`, `threads` and `delay`.
- [x] 5.3. Reporting Upgrade: HTML generator now renders vulnerabilities.

