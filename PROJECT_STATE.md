# SentinelRAG — Project State

## Current Status

**Phase:** Architecture pivot / Week-1 prototype

**Repository:** Existing SentinelRAG repository retained.

**Current direction:** Threat-informed evidence extraction + RAG + bounded agentic APK investigation.

---

# Current Baseline

The original deterministic-analysis foundation is functional.

Latest automated test result:

```text
22 passed in 0.66s
```

This is the baseline that must remain green during the architecture refactor.

---

# Implemented

## APK Inspection

Implemented:

* APK path validation
* SHA-256 calculation
* file size
* workspace generation

Primary modules:

```text
src/sentinel/apk/context.py
src/sentinel/apk/inspector.py
```

---

## Android Decompilation

Implemented:

* Apktool integration
* JADX integration
* manifest discovery
* Java source discovery
* Smali discovery
* partial JADX output tolerance

Primary module:

```text
src/sentinel/decompiler/pipeline.py
```

Real APK validation:

```text
AndroGoat.apk
```

decompiles successfully using both Apktool and usable JADX output.

---

## Manifest Analysis

Implemented parsing for:

* package
* version information
* SDK values
* permissions
* activities
* services
* receivers
* providers
* exported declarations
* component permissions
* intent filters
* deep-link data
* debuggable
* allowBackup
* usesCleartextTraffic
* networkSecurityConfig

Primary module:

```text
src/sentinel/manifest/analyzer.py
```

---

# Existing High-Confidence Rule Prototype

## SQLI-001

Status:

**WORKING**

Real AndroGoat findings:

```text
InsecureStorageSQLiteActivity.java
SQLiteDatabase.execSQL()

SQLinjectionActivity.java
SQLiteDatabase.rawQuery()
```

The implementation currently captures:

```text
user input
→ string construction
→ SQLite sink
```

This detector will remain as a high-confidence evidence sensor.

It is no longer intended to represent the primary SentinelRAG architecture.

---

# Existing Malware Behavior Prototype

## ACCESS-001

Implemented initial accessibility-behavior detector.

It supports:

* AccessibilityService source patterns
* AccessibilityNodeInfo
* performAction
* performGlobalAction
* getRootInActiveWindow
* node searching
* manifest accessibility-service correlation

During real AndroGoat testing it produced support-library false positives.

BehaviorEngine was subsequently changed to prefer application-package-owned source.

Latest BehaviorEngine tests pass.

Status:

**PROTOTYPE / NOT FINAL**

Decision:

Do not continue spending major Week-1 effort building increasingly complicated regex scoring for ACCESS-001.

Reuse relevant code as evidence/capability extraction where useful.

---

# Current Test Baseline

```text
22 passed
```

Baseline must remain green.

---

# Architecture Pivot

Previous emphasis:

```text
APK
↓
deterministic vulnerability rules
↓
malware behavior rules
↓
RAG
↓
LLM
```

Updated emphasis:

```text
APK
↓
static evidence extraction
↓
capability discovery
↓
threat-informed investigation seeds
↓
call/xref/data-flow context
↓
behavior slices
↓
APK retrieval + threat RAG
↓
bounded agentic investigation
↓
LLM analysis
↓
evidence validation
↓
final conclusion
```

Existing deterministic rules remain optional high-confidence sensors.

---

# Why the Architecture Changed

The rule-heavy approach creates an important limitation:

```text
unknown behavior
or
complex implementation
or
missed regex/data-flow pattern
      ↓
no rule finding
      ↓
behavior potentially missed
```

The new architecture separates:

```text
DISCOVERY
from
EVIDENCE COLLECTION
from
INTERPRETATION
```

Threat intelligence and generic capability knowledge determine what deserves investigation.

Program-analysis tools collect the actual APK evidence.

The LLM interprets the collected evidence.

---

# New Week-1 Priority

Do NOT add multiple new malware regex rules.

Immediate development priority:

```text
1. Evidence extraction
2. Capability catalog
3. Threat-intelligence model
4. Threat RAG
5. Behavior slices
6. LLM reasoning
7. bounded agent investigation
8. reporting
```

---

# Planned New Modules

```text
src/sentinel/
│
├── extraction/
│   ├── models.py
│   ├── api_extractor.py
│   ├── string_extractor.py
│   ├── method_extractor.py
│   └── capability_extractor.py
│
├── threat_intel/
│   ├── models.py
│   ├── loader.py
│   ├── normalizer.py
│   └── knowledge_base.py
│
├── retrieval/
│   ├── embeddings.py
│   ├── threat_retriever.py
│   └── models.py
│
├── program_analysis/
│   ├── xrefs.py
│   ├── call_context.py
│   └── behavior_slice.py
│
├── reasoning/
│   ├── models.py
│   ├── prompts.py
│   ├── analyzer.py
│   └── validator.py
│
└── investigation/
    ├── state.py
    ├── tools.py
    ├── planner.py
    └── investigator.py
```

---

# Current Evidence States

Existing:

```text
OBSERVED
INFERRED
CORRELATED
NOT_VERIFIABLE_FROM_APK
```

Architecture addition:

```text
SEMANTIC_SUSPECT
```

Meaning:

A security-relevant behavior or hypothesis identified through semantic/LLM analysis that still requires sufficient APK evidence.

---

# Current Repository Policy

KEEP:

* APK inspector
* APKContext
* decompiler
* manifest analyzer
* CLI
* SQLI-001
* behavior models
* useful ACCESS-001 extraction logic
* tests
* Git history

DO NOT DELETE:

* existing repository
* working implementation
* previous tests

REFACTOR gradually.

---

# Current Product Principle

> Threat intelligence determines where SentinelRAG should look; program analysis determines what is actually present; the LLM determines what the collected evidence most plausibly means.

---

# Immediate Next Task

Implement:

```text
src/sentinel/extraction/
```

starting with:

```text
models.py
api_extractor.py
string_extractor.py
capability_extractor.py
```

The first goal is:

```text
AndroGoat.apk
      ↓
APIs
Strings
Methods
Permissions
Capabilities
```

without yet assigning malicious conclusions.

---

# Week-1 Success Target

At the end of Week 1, one APK analysis must demonstrate:

```text
Threat knowledge
      ↓
investigation seed
      ↓
APK evidence/context
      ↓
RAG
      ↓
agent requests additional evidence
      ↓
LLM evidence-backed conclusion
```

This vertical slice is more important than broad vulnerability coverage.

---

# Known Technical Limitations

Current prototype limitations:

* JADX may return nonzero while still producing useful output
* package-root source filtering can miss unusual namespaces
* current ACCESS-001 detector is not production quality
* SQLI data flow is intentionally lightweight
* no complete call graph yet
* no interprocedural taint engine yet
* no code embeddings yet
* no automated threat-intelligence updater yet
* no RAG integration yet
* no agent implementation yet
* no production evidence validator yet

These limitations are acceptable for the current stage.

---

# Quality Gate

Before moving between major milestones:

```bash
pytest -q
```

must remain green.

Current baseline:

```text
22 passed
```
