# SentinelRAG Architecture Decisions

## ADR-001 — Build from scratch

SentinelRAG will be implemented independently rather than copying Droid-LLM-Hunter code.

Droid-LLM-Hunter may be studied as a reference architecture and behavior reference.

---

## ADR-002 — Deterministic analysis before LLM reasoning

The system will first identify candidate vulnerabilities using deterministic analysis.

The LLM will reason over collected evidence rather than independently scanning the entire APK.

---

## ADR-003 — Evidence-grounded findings

Every final finding must contain concrete evidence from the APK.

---

## ADR-004 — Vulnerability existence is separate from exploitability

A vulnerable code pattern does not automatically imply external exploitability.

The system will separately represent vulnerability presence and reachability.

---

## ADR-005 — LLM provider abstraction

The scanner must not be tightly coupled to one LLM provider.

The application will communicate through an LLMProvider interface.

---

## ADR-006 — Canonical finding schema

All vulnerability detectors will produce a common finding structure.

---

## ADR-007 — Prototype-first development

Week 1 focuses on a complete vertical slice rather than implementing the complete production architecture.