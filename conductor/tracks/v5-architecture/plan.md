# Implementation Plan: CTFLab v5.0

## Epic 1: Foundations and Entities (Domain-Driven Design)
- [x] 1.1. Entity Layer (`core/models.py`): Create `Target`, `Vulnerability`, `ScanResult`, `Evidence`, `Finding` hierarchy.
- [x] 1.2. Session Refactoring (`core/session.py`): Integrate `evidences` and `vulnerabilities` lists.
- [x] 1.3. Directory Reorganization: Create `domains/reconnaissance`, `domains/detection`, etc.
- [x] 1.4. Dependency Injection (`core/context.py`): Create `Context` class.

## Epic 2: Scanning Engine and Plugins
- [x] 2.1. Base Scanner Class (`core/scanner.py`): Define standard contracts.
- [/] 2.2. Separation of Detection vs Exploitation (In-progress: SQLi refactored).
- [x] 2.3. Capability System.
- [x] 2.4. Automatic Registry and Discovery (`core/registry.py`).
- [x] 2.5. Plugin Sandbox (Exception handling/events).

## Epic 3: Event-Driven Architecture
- [x] 3.1. Message Bus (`core/bus.py`).
- [x] 3.2. Event Catalog (`core/events.py`).
- [x] 3.3. Dependency Graph.

## Epic 4: Persistence and Telemetry
- [x] 4.1. Abstract Persistence Layer (`core/repository.py`).
- [x] 4.2. Professional Logging (`logs/`).
- [ ] 4.3. Replay Mode.
- [x] 4.4. Smart Cache (`core/cache.py`).
- [x] 4.5. Metrics System (`core/metrics.py`).

## Epic 5: Intelligence, DSLs, and Automation
- [x] 5.1. Fingerprinting Engine (`core/fingerprint.py`).
- [x] 5.2. YAML Payload Engine (`payloads/`).
- [x] 5.3. Knowledge/Rules Machine (DSL).
- [x] 5.4. Execution Profiles (`profiles/`).
- [x] 5.5. Declarative Workflows (`workflows/`).

## Epic 6: Reporting and UX
- [x] 6.1. Severity and Scoring System.
- [x] 6.2. Reporting Engine (`reports/`).
- [ ] 6.3. Local Web Dashboard.
- [ ] 6.4. Internal Versioning (Diffing).
- [ ] 6.5. Resource Manager & Documentation Generator.

## Epic 7: Structural Integrity (Ops)
- [ ] 7.1. Unit Tests (`tests/`).
- [x] 7.2. Layered Configuration (`ctflab.yaml`).
- [ ] 7.3. Feature Flags.
- [x] 7.4. Concurrency Refactoring (Async Batch Requests).
