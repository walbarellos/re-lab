# Implementation Plan: CTFLab v5.4 Arsenal Expansion

## Priority 1: Weaponry Expansion
- [x] 1.1. SQLi Payloads: Add aggressive union, time-based, and bypass payloads to `payloads/sqli.yaml`.
- [x] 1.2. Dynamic Baseline Fuzzer: Update `ParameterFuzzer` with stateful baseline detection.
- [x] 1.3. New Module - Header Injection: Implement `HeaderInjectionScanner`.

## Priority 2: Infrastructure Optimization
- [x] 2.1. Lru Cache: Implement `OrderedDict` based memory bounding in `core/cache.py`.


## Priority 4: v5.8 Autonomous Discovery (Natural Recon)
- [ ] 4.1. JS Spidering: Automatically scan .js files for endpoints in `core/intel.py`.
- [ ] 4.2. Proactive Fuzzing: Autopilot now triggers `reconnaissance_fuzzer` on barren roots.
- [ ] 4.3. Unified Context: Scanners now share discovered endpoints via `session.ctx`.

