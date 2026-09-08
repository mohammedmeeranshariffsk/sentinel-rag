# SentinelRAG

**Evidence-grounded Android security and malware-behavior analysis using deterministic static analysis, security RAG, and LLM reasoning.**

> 🚧 Prototype under active development

## What is SentinelRAG?

SentinelRAG is a from-scratch Android security analysis platform for analyzing APKs using a hybrid architecture that combines deterministic static analysis with evidence-grounded AI reasoning.

The project is designed around a fundamental principle:

> **Deterministic analysis discovers evidence. RAG provides security knowledge. The LLM reasons over evidence.**

SentinelRAG does not rely on an LLM to independently decide whether an APK is malicious or vulnerable.

```text
APK
 ↓
APK Inspection
 ↓
Apktool + JADX
 ↓
Manifest + Decompiled Code Analysis
 ↓
┌──────────────────────────────┐
│ Deterministic Rule Engine    │
├──────────────────────────────┤
│ Vulnerability Rules          │
│ Malware Behavior Rules       │
└──────────────────────────────┘
 ↓
Evidence Extraction
 ↓
Behavior Correlation
 ↓
Security RAG
 ↓
LLM Reasoning
 ↓
Evidence Validation
 ↓
Confidence + Severity
 ↓
Structured Findings
 ↓
JSON / HTML Report
```

## Detection Architecture

SentinelRAG uses two complementary classes of deterministic detectors.

### Vulnerability Rules

These identify insecure implementation patterns such as:

* `SQLI-001` — SQL Injection
* `SECRET-001` — Hardcoded Secrets
* `WEBVIEW-001` — Insecure WebView Configuration
* `EXPORT-001` — Exposed Android Components
* `INTENT-001` — Intent Redirection

### Malware Behavior Rules

These identify security-relevant behaviors commonly associated with Android malware without immediately assigning a malware-family name.

Planned behavior detectors include:

* `ACCESS-001` — Accessibility Service Abuse
* `C2-001` — Suspicious Command-and-Control Communication
* `NFC-001` — Suspicious NFC / Payment-Card Interaction
* `LOADER-001` — Dynamic Payload Loading
* `INSTALL-001` — Secondary APK Installation
* `SCREEN-001` — Screen Capture / Recording
* `REMOTE-001` — Remote Device-Control Behavior
* `SMS-001` — Suspicious SMS Interception
* `INJECT-001` — Process / Runtime Injection Indicators
* `PERSIST-001` — System or Firmware Persistence Indicators

## Malware-Family Correlation

SentinelRAG will correlate multiple independently detected behaviors against malware-family knowledge profiles.

Initial research profiles include:

* Mamont
* Anatsa
* NGate
* Vultur
* Triada

A malware profile is **not a signature detector**.

For example:

```text
Accessibility abuse
+
remote-control behavior
+
screen capture
+
C2 communication

        ↓

Vultur-like behavioral correlation
```

SentinelRAG should report:

```text
Vultur-like behavior observed
```

rather than:

```text
Confirmed Vultur infection
```

unless sufficient independent evidence exists to support such attribution.

## Evidence Model

Every finding should distinguish between different levels of knowledge:

```text
OBSERVED
    Directly visible in the APK.

INFERRED
    Derived from deterministic relationships between observed artifacts.

CORRELATED
    Behavior resembles a known vulnerability or malware technique/profile.

NOT_VERIFIABLE_FROM_APK
    Requires dynamic, device, firmware, network, or external analysis.
```

This prevents retrieved threat intelligence or LLM reasoning from being mistaken for APK evidence.

## Current Prototype Status

The following foundation is implemented:

* APK validation and SHA-256 fingerprinting
* Per-APK analysis workspace
* Apktool integration
* JADX integration
* Decompiled Java source discovery
* Smali discovery
* AndroidManifest.xml parsing
* Permission extraction
* Android application security flag extraction
* Activity, service, receiver, and provider extraction
* Explicit exported-component detection
* Intent-filter extraction
* Deep-link extraction
* Deterministic rule-engine framework
* Structured `SecurityCandidate` findings
* Java/Kotlin source scanner
* SQL Injection detector (`SQLI-001`)
* String concatenation SQL construction detection
* `StringBuilder` SQL construction detection
* `rawQuery()` sink detection
* `execSQL()` sink detection
* Source, sink, class, method, line, and code evidence extraction
* Real APK validation against AndroGoat
* Automated test suite

### Current Validation

The current test suite passes:

```text
12 passed
```

Real AndroGoat analysis currently identifies SQL injection candidates in:

```text
InsecureStorageSQLiteActivity.java
    EditText.getText().toString()
        ↓
    StringBuilder
        ↓
    SQLiteDatabase.execSQL()

SQLinjectionActivity.java
    EditText.getText().toString()
        ↓
    StringBuilder
        ↓
    SQLiteDatabase.rawQuery()
```

## Current Development Focus

The next milestone introduces the malware-behavior detection layer.

The first behavior rule will be:

```text
ACCESS-001 — Suspicious Accessibility Service Behavior
```

This will establish the architecture required for later behavior correlation and malware-family profiling.

## Design Principles

SentinelRAG follows several architectural principles:

1. Deterministic analysis happens before LLM reasoning.
2. Every final security finding requires concrete APK evidence.
3. Security RAG supplies knowledge, not proof.
4. The LLM contextualizes and reasons over evidence rather than replacing static analysis.
5. Vulnerability presence and exploitability are separate concepts.
6. Individual suspicious behaviors do not automatically identify a malware family.
7. Malware-family attribution requires correlation across multiple independent behaviors.
8. Confidence and severity are separate dimensions.
9. Static APK analysis must clearly identify conclusions that require dynamic or device-level verification.
10. The project is implemented independently from scratch.

## Planned Intelligence Layer

Later versions will add:

```text
Deterministic candidates
        +
Security / threat-intelligence RAG
        +
Behavior correlation
        +
LLM reasoning
        +
Evidence validator
        ↓
Evidence-grounded security assessment
```

The knowledge base is expected to include material from sources such as:

* OWASP MASVS
* OWASP MASTG
* CWE
* Android security documentation
* MITRE ATT&CK
* Android malware research
* Vendor threat-intelligence reports

## Roadmap

See [`PROJECT_PLAN.md`](PROJECT_PLAN.md).

## Current State

See [`PROJECT_STATE.md`](PROJECT_STATE.md).

## Architecture Decisions

See [`DECISIONS.md`](DECISIONS.md).

## Disclaimer

SentinelRAG is intended exclusively for authorized security testing, malware research, education, defensive security analysis, and security engineering research.

It is not intended for unauthorized access, exploitation, malware deployment, or malicious activity.
