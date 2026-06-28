# CTFLab v5.0 Architecture - Specification

## Overview
Transform CTFLab from a collection of organized scripts into a robust, event-driven, capability-based pentesting framework suitable for long-term maintenance and professional use.

## Objectives
- Implement Domain-Driven Design (DDD) with a clear Entity Layer.
- Decouple modules using an Event-Driven architecture (Message Bus).
- Standardize scanning via a `BaseScanner` class and Capability system.
- Implement persistent storage and comprehensive reporting.
- Remove hardcoded configurations and implement layered YAML config.

## Core Frameworks
- **Language**: Python 3.10+
- **Architecture**: Domain-Driven Design (DDD), Pub/Sub (Event Bus).
- **Core Entities**: `Target`, `Evidence`, `Finding`, `Vulnerability`, `ScanResult`.
