# CTFLab v6.1 Stabilization Plan

## Priority 1: Critical Operational Fixes
- [ ] 1.1. JS Spider Deduplication: Implement `seen_js` set in `core/intel.py`.
- [ ] 1.2. Classifier Feedback Loop: Feed discovered routes into `ResponseClassifier` in `core/autopilot.py`.
- [ ] 1.3. Fuzzer Determinism: Separate baseline request from async loop in `domains/reconnaissance/fuzzer.py`.
- [ ] 1.4. Absolute Paths: Fix `RuleEngine` to use absolute paths for rules directory.

## Priority 2: Cognitive Integration (v6 Connection)
- [ ] 2.1. Unified State: Connect `KnowledgeBase` and `Session.ctx`.
- [ ] 2.2. Classifier Expansion: Add `SSRF` and `GraphQL` signals to `ResponseClassifier`.
- [ ] 2.3. Attack Graph population: Ensure the graph is built during execution.

## Priority 3: Arsenal Polish
- [ ] 3.1. Traversal Refinement: Remove broad `len > 100` threshold in `path_traversal`.
- [ ] 3.2. Plugin API Cleanup: Fix `H._make_client` in `plugins/xss.py`.
