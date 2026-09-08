# SentinelRAG Architecture Decisions

## ADR-001 — Build from Scratch

SentinelRAG will be implemented independently rather than copying Droid-LLM-Hunter or another Android security scanner.

Existing projects may be studied for architectural ideas, comparison, research, and evaluation.

---

## ADR-002 — Deterministic Analysis Before LLM Reasoning

The system will first identify security-relevant candidates using deterministic analysis.

The LLM will reason over collected evidence rather than independently scanning the APK and deciding whether vulnerabilities or malware exist.

```text
Static Analysis
    ↓
Evidence
    ↓
RAG Context
    ↓
LLM Reasoning
```

---

## ADR-003 — Evidence-Grounded Findings

Every final finding must contain concrete evidence derived from the analyzed APK.

Retrieved security knowledge cannot substitute for APK evidence.

Evidence may include:

* manifest declarations
* permissions
* Java/Kotlin source
* Smali
* API calls
* source/sink relationships
* strings
* resources
* configuration
* code locations
* component metadata

---

## ADR-004 — Vulnerability Presence Is Separate From Exploitability

A vulnerable code pattern does not automatically imply external exploitability.

SentinelRAG will distinguish:

```text
vulnerability presence
reachability
attack surface
exploitability
```

These concepts must not be collapsed into a single boolean result.

---

## ADR-005 — LLM Provider Abstraction

SentinelRAG must not be tightly coupled to a single LLM provider.

The application will eventually communicate through an `LLMProvider` abstraction so providers can be changed independently of the analysis pipeline.

---

## ADR-006 — Canonical Finding Schema

Deterministic detectors will produce structured candidate objects rather than unstructured text.

A finding should preserve information such as:

```text
rule ID
finding type
location
source
sink
evidence
severity
confidence
description
```

The schema may evolve as behavior analysis is introduced.

---

## ADR-007 — Prototype-First Development

The first milestone prioritizes a complete working vertical slice rather than production-scale analysis.

Advanced capabilities such as complete inter-procedural data-flow analysis, dynamic instrumentation, distributed workers, and large-scale malware classification are deferred.

---

## ADR-008 — Separate Vulnerability Rules From Malware Behavior Rules

SentinelRAG will support two deterministic rule categories.

```text
Vulnerability Rules
```

identify insecure programming or Android configuration patterns.

Examples:

```text
SQLI-001
SECRET-001
WEBVIEW-001
EXPORT-001
INTENT-001
```

```text
Malware Behavior Rules
```

identify security-relevant functionality frequently used by Android malware.

Examples:

```text
ACCESS-001
C2-001
NFC-001
LOADER-001
SCREEN-001
REMOTE-001
SMS-001
INJECT-001
PERSIST-001
```

These categories may share scanning infrastructure while remaining semantically distinct.

---

## ADR-009 — Malware Families Are Correlation Profiles, Not Primary Detection Rules

SentinelRAG will not treat malware-family names as simple static rules.

A family profile will correlate multiple independently observed behaviors.

For example:

```text
ACCESS-001
+
REMOTE-001
+
SCREEN-001
+
C2-001

→ Vultur-like behavioral correlation
```

One suspicious API, permission, string, or manifest entry is insufficient to identify a malware family.

Initial research profiles include:

```text
Mamont
Anatsa
NGate
Vultur
Triada
```

---

## ADR-010 — Behavior Detection Must Avoid Attribution Overclaiming

Static analysis should use language proportional to the available evidence.

Preferred:

```text
Vultur-like behavior
behavior consistent with known Vultur techniques
suspicious accessibility automation
```

Avoid without sufficient evidence:

```text
This APK is Vultur.
Confirmed Vultur infection.
```

Malware attribution requires stronger evidence than detecting individual techniques.

---

## ADR-011 — Explicit Evidence States

SentinelRAG will distinguish:

```text
OBSERVED
INFERRED
CORRELATED
NOT_VERIFIABLE_FROM_APK
```

### OBSERVED

Directly present in the analyzed APK.

Example:

```text
AccessibilityService declared in AndroidManifest.xml
```

### INFERRED

Derived deterministically from one or more observed artifacts.

Example:

```text
Accessibility APIs appear to automate UI interaction
```

### CORRELATED

Observed/inferred behavior resembles documented security techniques or malware-family behavior.

Example:

```text
Detected behavior is consistent with Vultur-like remote-control techniques
```

### NOT_VERIFIABLE_FROM_APK

A conclusion requiring evidence unavailable through static APK analysis.

Examples:

```text
successful credential theft
actual ATM cash-out
live attacker control
firmware compromise outside the analyzed APK
```

---

## ADR-012 — Threat Intelligence Provides Context, Not Proof

RAG may retrieve:

* OWASP guidance
* CWE information
* Android security documentation
* MITRE ATT&CK techniques
* malware research
* vendor threat intelligence

Retrieved documents are contextual knowledge.

They cannot independently prove that behavior exists in an APK.

The relationship remains:

```text
APK evidence = proof of observation

Threat intelligence = contextual knowledge
```

---

## ADR-013 — Behavior Rules Should Be Reusable Across Malware Families

A behavior should be modeled independently from malware-family attribution.

For example:

```text
ACCESS-001
```

may contribute evidence toward multiple malware families.

This avoids duplicating detection logic inside:

```text
vultur.py
anatsa.py
mamont.py
...
```

and allows new malware profiles to reuse existing detectors.

---

## ADR-014 — Confidence and Severity Are Separate

Severity describes the potential security impact of a finding.

Confidence describes how strongly the available evidence supports the conclusion.

For example:

```text
Severity: HIGH
Confidence: LOW
```

is valid when a potentially dangerous behavior is detected using weak evidence.

Similarly:

```text
Severity: MEDIUM
Confidence: HIGH
```

may represent a strongly verified but lower-impact issue.

---

## ADR-015 — Rule Completion Requires Regression Evidence

A detector is not considered complete merely because it works on one code example.

Prototype rule completion requires:

```text
positive unit test
+
negative test
+
structured evidence validation
+
representative or real APK validation
```

SQLI-001 establishes the first implementation of this quality gate.

---

## ADR-016 — Static Analysis Must Acknowledge Its Boundaries

SentinelRAG must not claim that static APK inspection can establish facts that require:

* runtime observation
* network capture
* backend visibility
* victim-device telemetry
* firmware acquisition
* memory analysis
* infrastructure intelligence

Those conclusions must be represented as requiring additional validation.
