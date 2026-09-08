# 2. Prototype Detection Scope

The SentinelRAG prototype will use two complementary deterministic
security-analysis tracks:

1. Vulnerability detection
2. Malware-behavior detection

The purpose of the prototype is not to implement a large signature
database or definitively classify malware families.

Instead, the system will demonstrate that independently observed APK
behaviors can be extracted as structured evidence and later correlated
with security and threat-intelligence knowledge.

## Track A — Vulnerability Rules

Initial vulnerability detectors include:

- SQLI-001 — SQL Injection
- SECRET-001 — Hardcoded Secrets
- WEBVIEW-001 — Insecure WebView Configuration
- EXPORT-001 — Exposed Android Components
- INTENT-001 — Intent Redirection

SQLI-001 is the first completed detector and has been validated
against the real AndroGoat APK.

## Track B — Malware Behavior Rules

Initial malware-behavior research targets include:

- ACCESS-001 — Suspicious Accessibility Service Behavior
- C2-001 — Suspicious Command-and-Control Communication
- NFC-001 — Suspicious NFC / Payment-Card Interaction
- LOADER-001 — Dynamic Payload Loading
- INSTALL-001 — Secondary APK Installation
- SCREEN-001 — Screen Capture / Recording
- REMOTE-001 — Remote Device Control
- SMS-001 — Suspicious SMS Interception
- INJECT-001 — Process / Runtime Injection Indicators
- PERSIST-001 — System / Firmware Persistence Indicators

Not all of these behaviors are required to be complete during the
initial prototype.

The immediate goal is to implement enough independent behaviors to
demonstrate evidence-based malware-family correlation.

## Initial Malware Research Profiles

The first threat-intelligence profiles will study:

- Mamont
- Anatsa
- NGate
- Vultur
- Triada

These are correlation profiles rather than primary malware signatures.

SentinelRAG should identify behaviors first and only then determine
whether the combination is consistent with a documented malware family.

Example:

ACCESS-001
+
SCREEN-001
+
REMOTE-001
+
C2-001
↓
Vultur-like behavioral correlation

Family correlation must not be represented as definitive attribution
unless sufficient independent evidence exists.