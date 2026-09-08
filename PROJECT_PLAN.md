# SentinelRAG — Project Plan

## 1. Project Objective

SentinelRAG is an evidence-grounded, threat-informed Android security analysis platform that combines:

* Android static analysis
* continuously updated threat intelligence
* security-focused code/context extraction
* call-graph and data-flow analysis
* Retrieval-Augmented Generation (RAG)
* bounded agentic investigation
* LLM reasoning
* evidence validation
* malware behavior correlation

The goal is **not** to build another regex-heavy Android vulnerability scanner.

The goal is to build a system capable of using current Android malware/security knowledge to determine **where to investigate an APK**, automatically gather the relevant code context, and allow an LLM to reason over that evidence.

The system must distinguish:

> What threat intelligence suggests we should look for.

from:

> What the APK actually contains.

from:

> What the collected evidence most plausibly means.

---

# 2. Core Design Principle

SentinelRAG follows this principle:

> **Threat intelligence determines where SentinelRAG should look; program analysis determines what is actually present; the LLM determines what the collected evidence most plausibly means.**

A deterministic rule match is not required before semantic or agentic investigation can occur.

Likewise, an LLM hypothesis is not sufficient to claim malicious behavior without APK evidence.

---

# 3. Target Architecture

```text
                         INTERNET
                            │
                            ▼
                 Threat Research Pipeline
                            │
                  trusted Android sources
                            │
                            ▼
                Threat Intelligence Extraction
           ┌────────────────┼─────────────────┐
           │                │                 │
        APIs             Strings        Permissions
           │                │                 │
     Method names       Techniques       Components
           │                │                 │
           └────────────────┼─────────────────┘
                            │
                            ▼
                  Threat Knowledge Base
                ┌───────────┴───────────┐
                │                       │
         Structured Intel         Knowledge RAG
                │                       │
       techniques/APIs/etc.       reports/chunks
                │                       │
                └───────────┬───────────┘
                            │

==============================================================

                         NEW APK
                            │
                            ▼
                     APK Inspection
                            │
                            ▼
                      Decompilation
                   Apktool + JADX
                            │
                            ▼
                 Static Evidence Extraction
        ┌────────────┬────────────┬─────────────┐
        │            │            │             │
     Manifest      Strings      APIs        Methods/classes
        │            │            │             │
        └────────────┴──────┬─────┴─────────────┘
                            │
                            ▼
                  Capability Discovery
                            │
               Generic security catalog
                         +
                Current threat knowledge
                            │
                            ▼
                 Investigation Seed Set
                            │
                            ▼
                  Context Expansion
             ┌──────────────┼──────────────┐
             │              │              │
           Xrefs         Call graph     Data flow
             │              │              │
             └──────────────┼──────────────┘
                            │
                            ▼
                Security Behavior Slices
                            │
                  ┌─────────┴─────────┐
                  │                   │
                  ▼                   ▼
             APK Retrieval       Threat RAG
                  │                   │
                  └─────────┬─────────┘
                            │
                            ▼
                  Agentic Investigation
                            │
                 request more evidence
                            │
                     investigation loop
                            │
                            ▼
                       LLM Reasoning
                            │
                            ▼
                    Evidence Validator
                            │
                            ▼
                  Behavior Correlation
                            │
                            ▼
                       Final Report
```

---

# 4. Architectural Components

## 4.1 APK Inspection

Responsibilities:

* validate APK input
* calculate SHA-256
* determine file size
* create analysis workspace
* maintain analysis context

Existing implementation:

```text
src/sentinel/apk/
├── context.py
└── inspector.py
```

Status: IMPLEMENTED

---

# 4.2 Decompilation

Responsibilities:

* Apktool extraction
* AndroidManifest.xml recovery
* Smali recovery
* JADX Java source recovery
* tolerate partially successful JADX runs when usable source exists

Existing implementation:

```text
src/sentinel/decompiler/
└── pipeline.py
```

Status: IMPLEMENTED

---

# 4.3 Manifest Analysis

Responsibilities:

Extract objective Android application facts including:

* package
* permissions
* activities
* services
* receivers
* providers
* exported state
* intent filters
* deep links
* application flags
* network security configuration

Existing implementation:

```text
src/sentinel/manifest/
└── analyzer.py
```

Status: IMPLEMENTED

---

# 4.4 Static Evidence Extraction

This becomes a major Week-1 component.

Proposed structure:

```text
src/sentinel/extraction/
├── models.py
├── api_extractor.py
├── string_extractor.py
├── method_extractor.py
├── permission_extractor.py
└── capability_extractor.py
```

The extraction layer collects facts without declaring them malicious.

Examples:

```text
API_CALL
DexClassLoader

API_CALL
getRootInActiveWindow

STRING
/system/bin/sh

PERMISSION
android.permission.RECEIVE_BOOT_COMPLETED

METHOD
decryptPayload

COMPONENT
AccessibilityService
```

These become investigation evidence.

---

# 5. Security Capability Catalog

SentinelRAG maintains a generic security capability catalog.

Initial capabilities:

* Accessibility
* dynamic code loading
* reflection
* native code loading
* process execution
* networking
* cryptography
* SMS
* contacts
* notifications
* clipboard
* screen capture
* overlays
* WebView
* package installation
* filesystem operations
* device administration
* persistence
* IPC
* microphone
* camera
* location

Capabilities do not imply maliciousness.

They determine where deeper analysis may be valuable.

Example:

```text
DexClassLoader
      ↓
capability = DYNAMIC_CODE_LOADING
      ↓
investigation seed
```

not:

```text
DexClassLoader
      ↓
malware = true
```

---

# 6. Threat Intelligence Pipeline

SentinelRAG will maintain an independent threat-knowledge pipeline.

Its purpose is to continuously learn what Android malware and security research currently consider relevant.

Sources may eventually include:

* Android malware research
* security vendor reports
* OWASP MASVS / MASTG
* CWE
* Android security documentation
* MITRE ATT&CK
* public security research
* Android Security Bulletins
* trusted malware-analysis publications

Internet research must be separated from APK analysis.

The APK agent should analyze against a known threat-intelligence snapshot.

Example:

```text
Threat KB version:
2026-09-08
```

Benefits:

* reproducibility
* source provenance
* auditability
* reduced prompt-injection exposure
* controlled knowledge updates

---

# 7. Threat Intelligence Data Model

Threat reports should produce both:

1. original RAG chunks
2. structured threat intelligence

Example:

```json
{
  "family": "ExampleBanker",
  "platform": "android",

  "techniques": [
    "accessibility_abuse",
    "credential_collection",
    "dynamic_loading",
    "c2"
  ],

  "apis": [
    "getRootInActiveWindow",
    "performAction",
    "DexClassLoader"
  ],

  "permissions": [
    "android.permission.INTERNET",
    "android.permission.RECEIVE_BOOT_COMPLETED"
  ],

  "method_patterns": [
    "loadPayload",
    "decryptConfig"
  ],

  "strings": [],

  "behavior_relationships": [
    {
      "source": "AccessibilityNodeInfo.getText",
      "operation": "data_collection",
      "sink": "network"
    }
  ],

  "source_url": "...",
  "published_at": "...",
  "confidence": 0.90
}
```

Structured intelligence guides investigation.

Original source chunks provide RAG context.

---

# 8. Investigation Seed Generation

SentinelRAG must not depend exclusively on known malware indicators.

Seed selection uses:

```text
Generic Security Capability Catalog
                  +
Current Threat Intelligence
                  +
APK Observations
                  ↓
         Investigation Seeds
```

Example APK observations:

```text
DexClassLoader
Cipher.doFinal
BOOT_COMPLETED
OkHttpClient
```

Possible generated priorities:

```text
Dynamic loading          HIGH
Persistence              MEDIUM
Encrypted networking     MEDIUM
```

These are investigation targets, not findings.

---

# 9. Program Analysis

## Call Graph

Answers:

> Which methods call which methods?

Example:

```text
onAccessibilityEvent()
        ↓
collectText()
        ↓
encrypt()
        ↓
send()
```

---

## Cross References

Answers:

> Where is this API, method, string, field or class referenced?

Example:

```text
"/system/bin/sh"
       ↓
xrefs
       ↓
executeCommand()
```

---

## Data Flow

Answers:

> Where does information originate and where does it eventually go?

Example:

```text
AccessibilityNodeInfo.getText()
              ↓
          credential
              ↓
          encrypt()
              ↓
         requestBody
              ↓
          HTTP POST
```

Data flow is important because call relationships alone do not establish security impact.

---

# 10. Security Behavior Slice

A central SentinelRAG abstraction is the:

# Security Behavior Slice

A behavior slice contains the minimum relevant code context surrounding a suspicious capability.

Example:

```text
Seed:
getRootInActiveWindow()

Manifest:
BIND_ACCESSIBILITY_SERVICE

Caller:
onAccessibilityEvent()

Flow:
AccessibilityNodeInfo.getText()
      ↓
collect()
      ↓
encrypt()
      ↓
upload()

Strings:
"password"
"/device/update"

Network:
OkHttpClient
```

Instead of sending entire APK source code to the LLM, SentinelRAG sends bounded behavior slices.

Benefits:

* lower token usage
* less noise
* improved reasoning
* stronger evidence
* clearer reporting

---

# 11. Dual Retrieval Architecture

SentinelRAG uses two forms of retrieval.

## APK Retrieval

Searches evidence within the application:

```text
methods
classes
strings
API calls
xrefs
behavior slices
```

Example question:

> Where does text obtained from AccessibilityNodeInfo eventually flow?

---

## Threat Knowledge RAG

Searches external security knowledge:

```text
malware reports
OWASP
CWE
Android documentation
ATT&CK
research
```

Example question:

> How is Android Accessibility commonly abused by banking malware?

These two retrieval contexts are kept conceptually separate.

---

# 12. Agentic Investigation

The LLM does not directly invent APK evidence.

The agent can request tools such as:

```text
search_api()
search_string()
find_xrefs()
inspect_method()
find_callers()
find_callees()
trace_data_flow()
inspect_manifest_component()
search_apk_code()
retrieve_threat_intel()
retrieve_security_knowledge()
```

Example:

```text
Observation:
DexClassLoader detected

Agent:
What file is being loaded?

Tool:
trace argument provenance

Evidence:
payload.dex

Agent:
Who creates payload.dex?

Tool:
find writers/xrefs

Evidence:
downloadPayload()

Agent:
Where is payload downloaded from?

Tool:
trace network flow

Evidence:
HTTP response → payload.dex

Agent:
How is payload executed?

Tool:
inspect callees

Evidence:
DexClassLoader → reflection
```

The agent therefore performs bounded iterative investigation rather than simply producing a single LLM response.

---

# 13. LLM Responsibilities

The LLM may:

* interpret behavior
* prioritize hypotheses
* determine which evidence is missing
* select analysis tools
* correlate observations
* explain security significance
* compare behavior against malware intelligence
* produce remediation/explanation
* estimate confidence

The LLM must NOT:

* invent API usage
* invent methods
* invent permissions
* invent strings
* invent call relationships
* invent data flow
* declare malware solely because an API exists

---

# 14. Evidence Model

Initial evidence states:

## OBSERVED

Directly present in APK artifacts.

Examples:

```text
DexClassLoader referenced.
INTERNET permission declared.
URL string exists.
```

## INFERRED

Derived from deterministic program analysis.

Example:

```text
network response
→ file
→ DexClassLoader
```

## SEMANTIC_SUSPECT

LLM or semantic analysis identified suspicious behavior requiring additional validation.

## CORRELATED

Multiple independent APK observations correspond strongly to known malicious techniques or malware behavior.

## NOT_VERIFIABLE_FROM_APK

The claim requires runtime, network, device, firmware or external evidence.

---

# 15. Existing Deterministic Rules

Existing rules will not be deleted.

They become optional **high-confidence evidence sensors**.

Existing:

```text
SQLI-001
ACCESS-001 prototype
```

Examples of deterministic checks worth retaining:

* debuggable
* insecure exported components
* cleartext configuration
* high-confidence source → sink SQL injection
* obvious hardcoded secrets
* manifest misconfiguration

We will NOT spend Week 1 writing dozens of regex malware rules.

---

# 16. Malware Attribution Policy

SentinelRAG must avoid unsupported family attribution.

Do:

```text
Behavior resembles techniques documented for Vultur.
```

Do not automatically say:

```text
This APK is Vultur.
```

Family attribution requires multiple independent indicators and adequate supporting evidence.

Preferred states:

```text
Observed technique
Possible malicious behavior
Correlated malware behavior
Family-like behavior
Confirmed family
```

The final state requires substantially stronger evidence than static similarity.

---

# 17. One-Week Prototype Scope

The Week-1 objective is NOT a production malware scanner.

The objective is one compelling end-to-end vertical slice.

By the end of the week SentinelRAG should demonstrate:

```text
Threat knowledge
      ↓
security-relevant seed selection
      ↓
APK context extraction
      ↓
behavior slice
      ↓
RAG retrieval
      ↓
LLM analysis
      ↓
evidence-backed conclusion
```

---

# 18. Seven-Day Execution Plan

## Day 1 — Architecture Refactor + Evidence Extraction

Deliver:

```text
src/sentinel/extraction/
```

Implement:

* shared evidence models
* API extraction
* string extraction
* method extraction
* manifest evidence conversion
* capability catalog

CLI target:

```bash
sentinel extract sample.apk
```

Output:

```text
APIs
Strings
Permissions
Methods
Capabilities
```

Quality gate:

* existing tests remain green
* new extraction unit tests
* AndroGoat successfully extracts evidence

---

## Day 2 — Threat Intelligence Knowledge Model

Implement:

```text
src/sentinel/threat_intel/
├── models.py
├── loader.py
├── normalizer.py
└── knowledge_base.py
```

Use a small curated prototype corpus covering techniques such as:

* accessibility abuse
* dynamic loading
* C2
* persistence
* credential collection

Create structured records for several malware behaviors.

Quality gate:

```text
APK capability
→ matching threat knowledge
```

works locally.

---

## Day 3 — RAG Pipeline

Implement:

```text
src/sentinel/retrieval/
├── embeddings.py
├── threat_retriever.py
└── models.py
```

Pipeline:

```text
documents
↓
parse
↓
chunk
↓
metadata
↓
embeddings
↓
vector store
```

Initial vector store:

```text
Qdrant or existing selected store
```

Quality gate:

Security queries return relevant source chunks with metadata/provenance.

---

## Day 4 — Context Expansion / Behavior Slices

Implement first practical version of:

```text
src/sentinel/program_analysis/
├── xrefs.py
├── call_context.py
└── behavior_slice.py
```

Do NOT attempt perfect whole-program static analysis in Week 1.

Prototype should support:

* locate seed
* surrounding method
* references
* callers where feasible
* callees where feasible
* related strings
* related manifest context
* bounded source context

Quality gate:

Given a security-sensitive API, SentinelRAG produces a useful evidence bundle.

---

## Day 5 — LLM Security Reasoning

Implement:

```text
src/sentinel/reasoning/
├── models.py
├── prompts.py
├── analyzer.py
└── validator.py
```

Input:

```text
APK evidence
+
behavior slice
+
retrieved threat knowledge
```

Output schema:

```json
{
  "hypothesis": "...",
  "behavior": "...",
  "maliciousness": "...",
  "confidence": 0.0,
  "evidence_refs": [],
  "missing_evidence": [],
  "threat_context": [],
  "reasoning_summary": "..."
}
```

Every conclusion must reference APK evidence.

---

## Day 6 — Bounded Agentic Investigation

Implement:

```text
src/sentinel/investigation/
├── state.py
├── tools.py
├── planner.py
└── investigator.py
```

Initial tools:

* search API
* search string
* inspect method
* xrefs
* inspect manifest
* retrieve threat knowledge
* retrieve additional source context

Agent loop:

```text
Hypothesis
↓
Need more evidence?
├── yes → tool
│         ↓
│     update evidence
│         ↓
│     reconsider
│
└── no
    ↓
conclusion
```

Hard-cap number of investigation iterations.

LangGraph may be introduced here if justified, but the system must not depend on it prematurely.

---

## Day 7 — Integration + Report + Demo

CLI:

```bash
sentinel analyze sample.apk
```

Expected pipeline:

```text
APK
↓
extract
↓
threat match
↓
seed
↓
context expansion
↓
RAG
↓
agentic investigation
↓
LLM reasoning
↓
validation
↓
report
```

Deliver:

* JSON report
* readable terminal report
* README architecture
* demo screenshots/output
* tests
* clean Git history
* example AndroGoat analysis
* synthetic malicious behavior example if necessary

---

# 19. Week-1 Non-Goals

Do NOT attempt:

* perfect call graph
* perfect interprocedural taint analysis
* full malware-family classifier
* hundreds of deterministic rules
* production distributed workers
* cloud deployment
* complete live threat crawling
* dynamic sandbox analysis
* native-code reverse engineering
* firmware-level analysis
* full multi-agent architecture
* autonomous unrestricted internet browsing

These come after the vertical slice works.

---

# 20. Week-1 Definition of Done

SentinelRAG Week-1 prototype is successful when:

1. An APK can be inspected and decompiled.

2. Manifest, API, string and method evidence is extracted.

3. Security capabilities are identified.

4. Threat knowledge can influence investigation priority.

5. At least one suspicious capability produces a bounded behavior slice.

6. Relevant security/threat information is retrieved through RAG.

7. An LLM analyzes the APK evidence plus retrieved knowledge.

8. The LLM conclusion explicitly references APK evidence.

9. Missing evidence is acknowledged instead of hallucinated.

10. The agent can request at least one additional piece of APK context.

11. Existing SQLI detection remains functional.

12. All automated tests pass.

---

# 21. Post-Prototype Roadmap

After Week 1:

## Phase 2

* improved call graphs
* better xrefs
* data-flow analysis
* code embeddings
* APK semantic retrieval

## Phase 3

* automated threat-research pipeline
* source validation
* threat-intel versioning
* provenance tracking
* scheduled updates

## Phase 4

* malware behavior correlation
* multiple-family profiles
* ATT&CK mapping
* confidence calibration

## Phase 5

* evaluation framework
* malicious/benign APK benchmark corpus
* precision/recall measurement
* false-positive/false-negative analysis

## Phase 6

* production API
* FastAPI
* workers
* observability
* Phoenix/OpenTelemetry
* secure sandboxing

---

# 22. Final Product Vision

SentinelRAG should ultimately answer:

> Based on current Android security and malware knowledge, what areas of this APK deserve investigation?

Then:

> What does the APK actually do in those areas?

And finally:

> What security or malicious behavior is best supported by the collected evidence?

That is the core SentinelRAG mission.
