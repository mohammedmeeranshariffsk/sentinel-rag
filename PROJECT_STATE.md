# SentinelRAG Project State

## Current Phase

**Deterministic Security Analysis + Malware Behavior Detection Foundation**

## Current Milestone

Extend the existing deterministic vulnerability engine into a two-track detection architecture:

```text
Vulnerability Rules
        +
Malware Behavior Rules
        ↓
Evidence Extraction
        ↓
Behavior Correlation
```

The immediate implementation target is:

```text
ACCESS-001 — Suspicious Accessibility Service Behavior
```

---

# Completed

## Project Foundation

* [x] Public GitHub repository created
* [x] Python project structure created
* [x] Virtual environment configured
* [x] `pyproject.toml` configured
* [x] Typer CLI foundation created
* [x] Environment-based configuration created
* [x] Apktool path configured
* [x] JADX path configured
* [x] `.env` excluded from Git
* [x] `.env.example` created

## APK Inspection

* [x] `APKContext` implemented
* [x] APK file validation implemented
* [x] SHA-256 hashing implemented
* [x] APK file-size collection implemented
* [x] Per-APK workspace creation implemented
* [x] `sentinel inspect` command implemented

## Reverse Engineering

* [x] Apktool integration implemented
* [x] JADX integration implemented
* [x] Windows `.bat` execution supported
* [x] Partial JADX output supported
* [x] AndroidManifest.xml discovery implemented
* [x] Decompiled Java source discovery implemented
* [x] Smali discovery implemented
* [x] `sentinel decompile` command implemented

## Manifest Analysis

* [x] Package-name extraction
* [x] Version metadata extraction when present
* [x] SDK metadata extraction when present
* [x] Permission extraction
* [x] `android:debuggable` extraction
* [x] `android:allowBackup` extraction
* [x] `android:usesCleartextTraffic` extraction
* [x] Network security configuration extraction
* [x] Activity extraction
* [x] Service extraction
* [x] Broadcast receiver extraction
* [x] Content provider extraction
* [x] Explicit `android:exported` tracking
* [x] Intent-filter extraction
* [x] Deep-link extraction
* [x] `SecurityMetadata` model

## Deterministic Rule Engine

* [x] `SecurityRule` abstraction
* [x] `SecurityCandidate` model
* [x] `CodeLocation` model
* [x] Java/Kotlin `CodeScanner`
* [x] `RuleEngine`
* [x] Candidate deduplication

## SQL Injection — SQLI-001

* [x] Android UI source detection
* [x] `getText()` detection
* [x] `getText().toString()` detection
* [x] String-concatenation query detection
* [x] `StringBuilder` query-construction detection
* [x] `rawQuery()` detection
* [x] `execSQL()` detection
* [x] Source extraction
* [x] Sink extraction
* [x] Class extraction
* [x] Method extraction
* [x] Line-number extraction
* [x] Surrounding code evidence
* [x] Structured SQL injection candidate generation

## Testing

Current automated test status:

```text
12 passed
```

## Real APK Validation

Test APK:

```text
AndroGoat.apk
```

SHA-256:

```text
a47a8b0d0b8466a25ccc67d3d2cbb5d69ef2b0de4d4f278b6bee357c7ba5f63b
```

SQLI-001 successfully identifies two real candidates.

### Candidate 1

```text
InsecureStorageSQLiteActivity.java:78

Source:
username2.getText().toString()

Sink:
SQLiteDatabase.execSQL()

Method:
onClick
```

### Candidate 2

```text
SQLinjectionActivity.java:65

Source:
username2.getText().toString()

Sink:
SQLiteDatabase.rawQuery()

Method:
onClick
```

---

# Architecture Evolution

The original prototype focused only on generic Android vulnerability rules.

The architecture has now been expanded to support two deterministic analysis tracks:

```text
                 Rule Engine
                     │
          ┌──────────┴──────────┐
          │                     │
 Vulnerability Rules     Malware Behavior Rules
          │                     │
      SQLI-001              ACCESS-001
      SECRET-001            C2-001
      WEBVIEW-001           NFC-001
      EXPORT-001            LOADER-001
      INTENT-001            SCREEN-001
                            REMOTE-001
                            SMS-001
                            INJECT-001
                            PERSIST-001
```

Behavior candidates will later feed a correlation engine.

Initial malware research profiles:

```text
Mamont
Anatsa
NGate
Vultur
Triada
```

Family profiles will correlate behaviors rather than depend on malware names or simple signatures.

---

# Currently Working On

## ACCESS-001

Design and implement detection for suspicious Android Accessibility Service behavior.

Initial evidence categories will include:

```text
Manifest service declaration
android.permission.BIND_ACCESSIBILITY_SERVICE
AccessibilityService inheritance
AccessibilityEvent processing
AccessibilityNodeInfo interaction
performAction()
gesture execution
UI content inspection
```

The first version will produce behavior candidates rather than malware-family attribution.

---

# Next

After `ACCESS-001`:

* [ ] Add behavior-candidate data model
* [ ] Add malware behavior rule abstraction if separation from vulnerability rules is useful
* [ ] Add ACCESS-001 unit tests
* [ ] Validate ACCESS-001 against controlled APK/source samples
* [ ] Implement C2-001
* [ ] Implement LOADER-001
* [ ] Implement NFC-001
* [ ] Implement SCREEN-001 / REMOTE-001
* [ ] Build first behavior-correlation model
* [ ] Build Vultur research profile
* [ ] Add remaining generic vulnerability rules
* [ ] Build security/threat-intelligence RAG
* [ ] Add LLM reasoning layer
* [ ] Add evidence validator
* [ ] Add confidence scoring
* [ ] Add severity scoring
* [ ] Add JSON reporting
* [ ] Add HTML reporting
* [ ] Add evaluation metrics
* [ ] Add Arize Phoenix / OpenTelemetry observability

---

# Current Detection Philosophy

SentinelRAG distinguishes four evidence states:

```text
OBSERVED
INFERRED
CORRELATED
NOT_VERIFIABLE_FROM_APK
```

Examples:

```text
AccessibilityService declared
→ OBSERVED

Accessibility APIs are repeatedly used for UI automation
→ INFERRED suspicious behavior

Accessibility + remote control + screen capture resembles Vultur TTPs
→ CORRELATED

Attacker successfully controlled a real victim's banking session
→ NOT_VERIFIABLE_FROM_APK
```

---

# Known Limitations

The current prototype does not yet implement:

* full Android call graphs
* full inter-procedural taint analysis
* dynamic analysis
* runtime instrumentation
* network traffic analysis
* native-code semantic analysis
* firmware analysis
* definitive malware-family attribution
* large-scale malware classification
* exploit generation

Regex/context-based static detectors are intentionally being used first to establish the architecture before introducing more advanced program analysis.

---

# Current Quality Gate

A rule should not be considered complete until it has:

```text
deterministic detection
+
structured evidence
+
unit tests
+
negative tests
+
real or representative APK validation
```

SQLI-001 currently satisfies this prototype quality gate.
