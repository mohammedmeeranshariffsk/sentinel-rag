# SentinelRAG

## 7-Day From-Scratch Android Security Intelligence Prototype

---

# 0. Project Goal

Build a working Android security analysis prototype from scratch, inspired by the problem that Droid-LLM-Hunter addresses, but with our own architecture and implementation.

The 1-week prototype must demonstrate a complete pipeline:

```text
APK
 ↓
APK ingestion
 ↓
Reverse engineering
 ↓
Manifest analysis
 ↓
Deterministic security rules
 ↓
Evidence extraction
 ↓
Security RAG
 ↓
LLM reasoning
 ↓
Evidence validation
 ↓
Confidence + severity
 ↓
Structured findings
 ↓
HTML + JSON report
```

The prototype will intentionally be small.

It is **not** our final product.

It is the foundation for the larger platform.

---

# 1. What We Are Building in One Week

The Week-1 system will answer:

> “Given an Android APK, can I automatically identify a small set of security issues, collect concrete evidence, retrieve relevant security knowledge, have an LLM reason over that evidence, validate the reasoning, and produce a professional security report?”

The answer should be:

**Yes.**

---

# 2. Week-1 Scope

We will implement exactly five primary vulnerability classes.

## Detector 1 — SQL Injection

Example:

```java
String query =
    "SELECT * FROM users WHERE username=" +
    username.getText().toString();

db.rawQuery(query, null);
```

Detect:

```text
source:
EditText.getText()

transformation:
string concatenation

sink:
SQLiteDatabase.rawQuery()
```

---

## Detector 2 — Hardcoded Secrets

Examples:

```java
String API_KEY = "sk_test_...";
String password = "admin123";
```

The prototype will identify suspicious secret-like literals using deterministic rules.

Important:

A hardcoded string match should be classified as:

```text
candidate
```

and then passed through contextual reasoning.

We should not claim every random string is a secret.

---

## Detector 3 — Insecure WebView

Examples:

```java
webView.getSettings().setJavaScriptEnabled(true);
```

combined with dangerous configurations or untrusted content where possible.

The initial detector will focus on dangerous WebView configuration patterns.

---

## Detector 4 — Exported Components

Analyze:

```xml
<activity>
<service>
<receiver>
<provider>
```

and determine:

```text
android:exported
intent-filter
permission
external entry point
```

Important:

We must distinguish:

```text
component exists
```

from:

```text
component is externally exposed
```

---

## Detector 5 — Intent Redirection

Look for patterns such as:

```java
Intent intent = getIntent();
Intent next = intent.getParcelableExtra("intent");
startActivity(next);
```

The first implementation will be pattern/context based.

Full inter-procedural taint analysis comes later.

---

# 3. Explicitly Out of Scope for Week 1

Do NOT spend Week 1 trying to implement:

```text
50 vulnerability rules
```

```text
full Android call graph
```

```text
full inter-procedural taint analysis
```

```text
perfect AST analysis
```

```text
automated exploit generation
```

```text
dynamic analysis
```

```text
Frida integration
```

```text
massive vector database
```

```text
multi-agent architecture
```

```text
Kubernetes
```

```text
large-scale distributed workers
```

```text
polished production dashboard
```

Those belong to later versions.

---

# 4. Prototype Architecture

The Week-1 architecture is:

```text
                         ┌─────────────────┐
                         │       APK       │
                         └────────┬────────┘
                                  │
                                  ▼
                       ┌─────────────────────┐
                       │   APK Ingestion     │
                       └──────────┬──────────┘
                                  │
                                  ▼
                       ┌─────────────────────┐
                       │ Reverse Engineering │
                       │ Apktool + JADX      │
                       └──────────┬──────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
          ┌─────────────────┐        ┌─────────────────┐
          │ Manifest        │        │ Decompiled Code │
          │ Analyzer        │        │ Analyzer        │
          └────────┬────────┘        └────────┬────────┘
                   │                          │
                   └──────────┬───────────────┘
                              ▼
                   ┌──────────────────────┐
                   │ Rule Engine          │
                   │                      │
                   │ SQLi                 │
                   │ Secrets              │
                   │ WebView              │
                   │ Exported Components  │
                   │ Intent Redirection   │
                   └──────────┬───────────┘
                              │
                              ▼
                   ┌──────────────────────┐
                   │ Evidence Extractor   │
                   └──────────┬───────────┘
                              │
                       ┌──────┴──────┐
                       ▼             ▼
              ┌────────────┐  ┌───────────────┐
              │ Security   │  │ LLM Reasoner  │
              │ RAG        │  │               │
              └──────┬─────┘  └───────┬───────┘
                     │                 │
                     └────────┬────────┘
                              ▼
                   ┌──────────────────────┐
                   │ Evidence Validator   │
                   └──────────┬───────────┘
                              ▼
                   ┌──────────────────────┐
                   │ Severity/Confidence  │
                   └──────────┬───────────┘
                              ▼
                   ┌──────────────────────┐
                   │ Finding Schema       │
                   └──────────┬───────────┘
                              ▼
                 ┌────────────┴────────────┐
                 ▼                         ▼
             JSON Report              HTML Report
```

---

# 5. Technology Stack for Week 1

Keep the stack intentionally small.

## Language

```text
Python 3.11+
```

## CLI

```text
Typer
```

## Configuration

```text
PyYAML
python-dotenv
```

## APK reverse engineering

```text
Apktool
JADX
```

## Parsing

```text
xml.etree.ElementTree
regex
pathlib
```

Do not introduce a complicated AST framework on Day 1.

---

## Data validation

```text
Pydantic
```

---

## RAG

Use:

```text
Qdrant
```

for the vector store.

For embeddings, use a practical embedding model available in the environment.

The exact model can be changed later.

---

## LLM

Create an abstraction:

```python
LLMProvider
```

so that the underlying provider can be switched.

For example:

```text
OpenRouter
Gemini
local model
```

The rest of the application should not care which provider is used.

---

## Reporting

```text
JSON
Jinja2 + HTML
```

---

# 6. Repository Structure

At the end of Day 1 the project should look approximately like:

```text
sentinel-rag/
│
├── README.md
├── LICENSE
├── pyproject.toml
├── .env.example
├── .gitignore
│
├── src/
│   └── sentinel/
│       ├── __init__.py
│       │
│       ├── cli/
│       │   ├── __init__.py
│       │   └── main.py
│       │
│       ├── config/
│       │   ├── __init__.py
│       │   └── settings.py
│       │
│       ├── apk/
│       │   ├── __init__.py
│       │   ├── context.py
│       │   └── inspector.py
│       │
│       ├── decompiler/
│       │   ├── __init__.py
│       │   └── pipeline.py
│       │
│       ├── manifest/
│       │   ├── __init__.py
│       │   └── analyzer.py
│       │
│       ├── rules/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── engine.py
│       │   ├── sql_injection.py
│       │   ├── hardcoded_secrets.py
│       │   ├── insecure_webview.py
│       │   ├── exported_components.py
│       │   └── intent_redirection.py
│       │
│       ├── evidence/
│       │   ├── __init__.py
│       │   └── extractor.py
│       │
│       ├── rag/
│       │   ├── __init__.py
│       │   ├── ingest.py
│       │   ├── retriever.py
│       │   └── store.py
│       │
│       ├── llm/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   └── provider.py
│       │
│       ├── validation/
│       │   ├── __init__.py
│       │   └── validator.py
│       │
│       ├── scoring/
│       │   ├── __init__.py
│       │   └── scorer.py
│       │
│       └── reporting/
│           ├── __init__.py
│           ├── json_report.py
│           └── html_report.py
│
├── rules/
├── knowledge/
├── reports/
├── workspace/
├── tests/
│   ├── unit/
│   └── integration/
│
├── templates/
│   └── report.html
│
└── examples/
```

---

# 7. Canonical Data Models

We establish these early so later components don't become tightly coupled.

## APKContext

```python
class APKContext:
    apk_path: str
    sha256: str
    package_name: str | None
    version_name: str | None
    version_code: str | None
    workspace: str
    manifest_path: str
    source_path: str
    smali_path: str
```

---

# 8. Candidate Finding

Every deterministic detector returns a candidate.

Example:

```json
{
  "rule_id": "SQLI-001",
  "status": "candidate",
  "file": "SQLinjectionActivity.java",
  "line": 126,
  "evidence": [
    "username.getText().toString()",
    "rawQuery(qry, null)"
  ],
  "source": "EditText.getText()",
  "sink": "SQLiteDatabase.rawQuery()"
}
```

The candidate is NOT automatically the final vulnerability.

---

# 9. Final Finding

After reasoning and validation:

```json
{
  "finding_id": "F-0001",
  "rule_id": "SQLI-001",
  "vulnerability": "SQL Injection",
  "status": "Vulnerable",
  "severity": "HIGH",
  "confidence": 0.94,

  "location": {
    "file": "...",
    "line": 126,
    "class": "SQLinjectionActivity",
    "method": "..."
  },

  "source": {
    "type": "user_input",
    "expression": "username.getText().toString()"
  },

  "sink": {
    "type": "SQLiteDatabase.rawQuery",
    "expression": "rawQuery(qry, null)"
  },

  "data_flow": [
    "EditText.getText()",
    "toString()",
    "string concatenation",
    "rawQuery()"
  ],

  "reachability": {
    "externally_reachable": false,
    "reason": "No external entry point confirmed"
  },

  "cwe": "CWE-89",
  "masvs": "MASVS-CODE-4",

  "evidence": [
    {
      "type": "code",
      "file": "...",
      "line": 126,
      "snippet": "..."
    }
  ],

  "attack_scenario": "...",
  "remediation": "...",
  "references": []
}
```

---

# 10. Day 1 — Foundation

## Goal

By the end of Day 1:

```text
APK
 ↓
APKContext
 ↓
workspace
 ↓
metadata
```

must work.

---

## Step 1 — Create repository

Create:

```text
sentinel-rag
```

Initialize Git.

---

## Step 2 — Python environment

Create a virtual environment.

Install only required foundational packages.

---

## Step 3 — CLI

Create:

```text
sentinel
```

with:

```text
sentinel --help
sentinel version
sentinel inspect app.apk
```

Initially `inspect` can return basic metadata.

---

## Step 4 — APK hash

Calculate SHA256.

Example:

```text
SHA256:
abcdef...
```

This will become the scan identifier.

---

## Step 5 — Workspace manager

Every APK gets:

```text
workspace/
└── <sha256>/
```

This prevents different scans from overwriting one another.

---

## Step 6 — APK metadata extraction

At minimum:

```text
filename
SHA256
file size
```

Later:

```text
package
version
SDK
certificate
```

---

## Day 1 acceptance test

This must work:

```cmd
sentinel inspect "C:\path\AndroGoat.apk"
```

Expected:

```text
APK: AndroGoat.apk
SHA256: ...
Size: ...
Workspace: workspace/...
```

### Do not proceed until:

The command works reliably for at least one APK.

---

# 11. Day 2 — Reverse Engineering + Manifest

## Goal

Transform:

```text
APK
```

into:

```text
Manifest
+
Java source
+
Smali
```

---

## Step 1 — Integrate Apktool

Run:

```text
apktool d app.apk
```

from Python.

Capture:

```text
stdout
stderr
exit code
execution time
```

---

## Step 2 — Integrate JADX

Run JADX against the APK.

Handle:

```text
success
partial failure
failure
```

JADX should not necessarily kill the entire scan.

---

## Step 3 — Create analysis workspace

Expected:

```text
workspace/<hash>/
├── original.apk
├── apktool/
├── jadx/
├── metadata.json
```

---

## Step 4 — Parse Manifest

Extract:

```text
package
activities
services
receivers
providers
permissions
exported
intent filters
debuggable
allowBackup
usesCleartextTraffic
networkSecurityConfig
```

---

## Step 5 — Attack surface object

Produce:

```json
{
  "activities": [],
  "services": [],
  "receivers": [],
  "providers": [],
  "deep_links": [],
  "permissions": []
}
```

---

## Day 2 acceptance test

Run:

```cmd
sentinel manifest AndroGoat.apk
```

and receive meaningful structured output.

For AndroGoat we should be able to identify items such as:

```text
package name
activities
receivers
deep-link configuration
exported configuration
debug/backup configuration
```

---

# 12. Day 3 — Rule Engine

## Goal

Create the deterministic detection framework.

---

## Step 1 — Rule interface

Every detector implements something conceptually like:

```python
class SecurityRule:
    rule_id: str
    name: str

    def analyze(self, context) -> list[Candidate]:
        ...
```

---

## Step 2 — Rule registry

The scanner should automatically discover enabled rules.

Example:

```yaml
rules:
  SQLI-001: true
  SECRET-001: true
  WEBVIEW-001: true
  EXPORT-001: true
  INTENT-001: true
```

---

## Step 3 — SQL Injection

Start with simple deterministic patterns.

Search for:

```text
rawQuery(
execSQL(
```

Then inspect nearby code for:

```text
+
String.format
concatenation
user input
EditText
Intent extras
```

The result should include code context.

---

## Step 4 — Hardcoded Secrets

Detect patterns such as:

```text
password =
api_key =
secret =
token =
authorization =
```

with suspicious literals.

---

## Step 5 — Insecure WebView

Detect:

```text
setJavaScriptEnabled(true)
loadUrl(...)
setAllowFileAccess(true)
```

and associated context.

---

## Step 6 — Exported Components

This is primarily manifest-based.

Detect:

```text
exported=true
```

and relevant intent filters.

---

## Step 7 — Intent Redirection

Search for:

```text
getParcelableExtra
getSerializableExtra
Intent
startActivity
startService
sendBroadcast
```

and suspicious combinations.

---

## Day 3 acceptance test

Run:

```cmd
sentinel rules --list
```

and see:

```text
SQLI-001
SECRET-001
WEBVIEW-001
EXPORT-001
INTENT-001
```

Then:

```cmd
sentinel scan AndroGoat.apk --stage rules
```

should produce candidates.

---

# 13. Day 4 — Evidence + Canonical Findings

## Goal

Turn raw matches into useful security evidence.

This is a critical day.

---

## Step 1 — Capture code snippets

For each finding:

```text
file
line
method
class
surrounding code
```

Do not store only:

```text
regex matched
```

---

## Step 2 — Source/Sink representation

Even though the first engine is simple, define proper concepts.

Example:

```text
Source:
username.getText()

Sink:
rawQuery()

Transformation:
String concatenation
```

---

## Step 3 — Finding builder

Convert candidates to canonical finding objects.

---

## Step 4 — Context extraction

For each candidate, extract perhaps:

```text
20–40 lines
```

around the suspicious code.

Do not send entire source files to the LLM.

---

## Step 5 — Manifest context

Attach relevant component information.

Example:

```json
{
  "component": "SQLinjectionActivity",
  "exported": false,
  "intent_filters": []
}
```

---

## Day 4 acceptance test

The SQL injection result should contain:

```text
file
line
source
sink
code snippet
component
manifest context
rule ID
```

At this stage the system already has legitimate static-analysis value.

---

# 14. Day 5 — RAG

## Goal

Give the analyzer Android security knowledge.

Do not build an enormous knowledge base.

Start with a small, high-quality corpus.

---

## Initial knowledge

Use material covering:

```text
OWASP MASVS
OWASP MASTG
CWE-89
CWE-798
CWE-79
Android WebView security guidance
Android component security guidance
Intent security guidance
```

---

## Step 1 — Knowledge format

Store documents under:

```text
knowledge/
├── masvs/
├── mastg/
├── cwe/
└── android/
```

---

## Step 2 — Chunk documents

Each chunk should have metadata:

```json
{
  "source": "OWASP",
  "document": "MASVS",
  "section": "...",
  "control_id": "MASVS-CODE-4"
}
```

---

## Step 3 — Embeddings

Generate embeddings.

---

## Step 4 — Qdrant

Store:

```text
embedding
text
metadata
document ID
```

---

## Step 5 — Retrieval

Given:

```text
SQL Injection
rawQuery
untrusted input
Android SQLite
```

retrieve relevant guidance.

---

## Step 6 — Test retrieval independently

Create:

```cmd
sentinel rag query "Android SQL injection rawQuery untrusted input"
```

Expected:

```text
Top results:
CWE-89
MASVS-CODE-4
Android SQL/security guidance
```

---

## Day 5 acceptance test

RAG must work **without the APK scanner**.

This lets us debug RAG separately.

---

# 15. Day 6 — LLM Reasoning + Validation

## Goal

Connect:

```text
Static Evidence
+
RAG Context
```

to:

```text
LLM
```

---

# 16. LLM Input

For SQL Injection, the model should receive something like:

```text
Vulnerability candidate:
SQL Injection

File:
SQLinjectionActivity.java

Code:
...

Source:
username.getText().toString()

Sink:
SQLiteDatabase.rawQuery()

Component:
SQLinjectionActivity

External reachability:
Not confirmed

Security guidance:
CWE-89
MASVS-CODE-4
...
```

---

# 17. Structured LLM Output

The model must return a schema like:

```json
{
  "is_vulnerable": true,
  "severity": "HIGH",
  "reason": "...",
  "attack_scenario": "...",
  "remediation": "...",
  "false_positive_analysis": "..."
}
```

Do not accept arbitrary free-form text as the primary output.

---

# 18. LLM Adapter

The architecture should look like:

```text
LLMProvider
   │
   ├── OpenRouterProvider
   ├── GeminiProvider
   └── FutureLocalProvider
```

The rest of SentinelRAG calls:

```python
llm.analyze(...)
```

It should not know which provider is underneath.

---

# 19. Evidence Validator

Now implement our first evidence validator.

Check:

```text
Does the referenced file exist?
Does the referenced line exist?
Does source exist in the code?
Does sink exist in the code?
Did LLM claim a data flow that isn't present?
```

Example:

LLM claims:

```text
Intent.getStringExtra() → rawQuery()
```

but static evidence cannot find that path.

Validator should flag:

```text
LLM claim not supported
```

---

# 20. Confidence Calculation

For Week 1 keep it simple.

Example:

```text
source detected          +0.20
sink detected            +0.20
suspicious flow evidence +0.25
manifest context         +0.10
RAG support              +0.10
LLM agreement            +0.15
```

Then clamp:

```text
0.0–1.0
```

This is a prototype scoring system, not a scientifically validated probability.

We will improve it later.

---

# 21. Severity

Initially use a combination of:

```text
LLM recommendation
+
rule-defined baseline severity
+
reachability modifier
```

Example:

```text
SQL injection base = HIGH
```

But:

```text
external reachability confirmed
```

may strengthen exploitability context.

---

# 22. Day 6 acceptance test

Run a complete scan:

```cmd
sentinel scan AndroGoat.apk
```

Pipeline:

```text
APK
 ↓
Decompile
 ↓
Manifest
 ↓
Rules
 ↓
Evidence
 ↓
RAG
 ↓
LLM
 ↓
Validator
 ↓
Findings
```

The output must contain at least one complete structured finding.

---

# 23. Day 7 — Reporting + Integration + Demo

## Goal

Turn everything into something we can actually showcase.

---

# 24. Final CLI

The primary command should be:

```cmd
sentinel scan AndroGoat.apk
```

Optional:

```cmd
sentinel scan AndroGoat.apk --output reports/
```

---

# 25. Final Scan Pipeline

Internally:

```text
ScanCommand
     ↓
APKInspector
     ↓
Decompiler
     ↓
ManifestAnalyzer
     ↓
RuleEngine
     ↓
EvidenceExtractor
     ↓
RAGRetriever
     ↓
LLMReasoner
     ↓
EvidenceValidator
     ↓
RiskScorer
     ↓
ReportGenerator
```

---

# 26. JSON Output

Produce:

```text
reports/<scan-id>.json
```

It should contain:

```text
scan metadata
attack surface
findings
evidence
RAG references
LLM reasoning
validation
severity
confidence
```

---

# 27. HTML Report

Create:

```text
reports/<scan-id>.html
```

Sections:

```text
Executive Summary
APK Information
Attack Surface
Severity Summary
Findings
Evidence
Source/Sink
Reachability
CWE
MASVS
Remediation
References
```

---

# 28. Example Finding Page

Show:

```text
SQL Injection
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Severity
HIGH

Confidence
94%

Status
Vulnerable

Location
SQLinjectionActivity.java:126


SOURCE
username.getText().toString()


SINK
SQLiteDatabase.rawQuery()


DATA FLOW
EditText
   ↓
getText()
   ↓
toString()
   ↓
String concatenation
   ↓
rawQuery()


REACHABILITY
Internal / external reachability not confirmed


CWE
CWE-89


MASVS
MASVS-CODE-4


WHY THIS WAS REPORTED
...


ATTACK SCENARIO
...


REMEDIATION
...


SECURITY REFERENCES
...
```

---

# 29. GitHub README

By the end of Day 7 the README should explain:

```text
What SentinelRAG is
Why it exists
Architecture
How it works
Installation
Usage
Example scan
Example finding
Technology stack
Current limitations
Roadmap
```

Do NOT claim:

```text
production-grade
full taint analysis
complete Android vulnerability coverage
zero false positives
```

Instead clearly call it:

> **Prototype / research-oriented security analysis platform**

Honesty makes the project stronger.

---

# 30. Week-1 Acceptance Criteria

The prototype is considered successful only if all of these work:

## A. APK ingestion

```text
✓ APK accepted
✓ SHA256 generated
✓ workspace created
```

## B. Reverse engineering

```text
✓ Apktool runs
✓ JADX runs or degrades gracefully
✓ source directory available
```

## C. Manifest

```text
✓ package identified
✓ components identified
✓ exported status identified
✓ intent filters identified
```

## D. Static rules

```text
✓ SQL Injection
✓ Hardcoded Secrets
✓ Insecure WebView
✓ Exported Components
✓ Intent Redirection
```

## E. Evidence

```text
✓ file
✓ line
✓ source/context
✓ sink/context
✓ code snippet
```

## F. RAG

```text
✓ documents ingested
✓ embeddings generated
✓ vector search works
✓ relevant security guidance retrieved
```

## G. LLM

```text
✓ structured output
✓ vulnerability reasoning
✓ severity
✓ remediation
✓ false-positive analysis
```

## H. Validation

```text
✓ source checked
✓ sink checked
✓ evidence checked
✓ unsupported LLM claims detected
```

## I. Reporting

```text
✓ JSON
✓ HTML
```

---

# 31. What We Should Be Able to Demonstrate on Day 7

The demo should be approximately:

```text
$ sentinel scan AndroGoat.apk
```

Then:

```text
[1/8] Inspecting APK...
[2/8] Decompiling...
[3/8] Analyzing manifest...
[4/8] Running security rules...
[5/8] Extracting evidence...
[6/8] Retrieving security knowledge...
[7/8] Validating LLM analysis...
[8/8] Generating report...

Scan complete.

Findings: 7

HIGH    SQL Injection
HIGH    Exported Component
HIGH    Intent Redirection
MEDIUM  Insecure WebView
MEDIUM  Hardcoded Secret

Report:
reports/<scan-id>.html
```

The exact number of findings will depend on what the test APK contains. We should never hardcode a result merely to make the demo look impressive.

---

# 32. Git Commits During the Week

Make the Git history itself tell the story.

Suggested commits:

```text
day1: initialize SentinelRAG project
day1: add APK context and workspace manager
day2: integrate Apktool
day2: integrate JADX
day2: add manifest analyzer
day3: implement security rule engine
day3: add SQL injection detector
day3: add hardcoded secret detector
day3: add WebView detector
day3: add exported component detector
day3: add intent redirection detector
day4: add evidence extraction
day4: add canonical finding schema
day5: add security knowledge ingestion
day5: add vector retrieval
day6: add LLM provider abstraction
day6: add structured vulnerability reasoning
day6: add evidence validator
day6: add confidence scoring
day7: add HTML reporting
day7: complete scan pipeline
day7: document prototype and roadmap
```

This will make the repository look much more authentic than one giant initial commit.

---

# 33. Testing Strategy for Week 1

We do not need hundreds of tests yet.

We need targeted tests.

## Unit tests

Test:

```text
SHA256 calculation
workspace creation
manifest parsing
SQLi detector
secret detector
WebView detector
exported-component detector
finding schema
confidence scorer
```

## Integration test

One end-to-end test:

```text
APK
 ↓
decompile
 ↓
manifest
 ↓
rules
 ↓
report
```

## RAG test

Query:

```text
SQL injection Android SQLite
```

and verify that an expected knowledge source appears in the top results.

---

# 34. Prototype Dataset

Use:

```text
AndroGoat
```

as the primary demonstration APK because it contains intentionally vulnerable examples.

Then create a tiny synthetic benign dataset.

For example:

```text
samples/
├── vulnerable_sql.java
├── safe_sql.java
├── vulnerable_webview.java
├── safe_webview.java
├── vulnerable_intent.java
└── safe_intent.java
```

This is enough to begin testing false positives.

---

# 35. Definition of “Prototype Quality”

A successful prototype is NOT:

```text
lots of code
```

It is:

```text
small
modular
repeatable
explainable
evidence-based
demonstrable
extensible
```

The important architectural property is:

```text
Every component has a clean boundary.
```

For example:

```text
RuleEngine
```

should not know:

```text
which LLM provider is being used
```

and:

```text
RAG
```

should not know:

```text
how Apktool works
```

and:

```text
ReportGenerator
```

should not perform vulnerability detection.

---

# 36. The Most Important Architectural Interfaces

We should create these interfaces early:

```text
APKInspector
Decompiler
ManifestAnalyzer
SecurityRule
EvidenceExtractor
KnowledgeRetriever
LLMProvider
EvidenceValidator
RiskScorer
ReportGenerator
```

Later versions can replace the internals without changing the entire system.

---

# 37. What Happens After Week 1

Week 1 gives us:

```text
                     PROTOTYPE
                         │
        ┌────────────────┼────────────────┐
        │                │                │
    Static Rules        RAG              LLM
        │                │                │
        └────────────────┼────────────────┘
                         │
                    Validation
                         │
                      Report
```

Then we grow it.

---

# 38. Week 2 — Make Static Analysis Better

Replace simplistic pattern matching with:

```text
AST parsing
method-level analysis
better source detection
better sink detection
data-flow tracking
```

Add:

```text
5–10 additional rules
```

---

# 39. Week 3 — Source/Sink Engine

Build:

```text
Source registry
Sink registry
Transformation registry
Data-flow representation
```

Then:

```text
source → transform → sink
```

becomes a first-class object.

---

# 40. Week 4 — Reachability

Introduce:

```text
call graph
entry points
intent paths
deep links
IPC
```

and distinguish:

```text
code vulnerable
```

from:

```text
externally reachable vulnerability
```

---

# 41. Week 5 — Better RAG

Expand knowledge:

```text
MASVS
MASTG
CWE
Android documentation
security bulletins
secure coding patterns
```

Add:

```text
metadata filtering
reranking
citation tracking
document versioning
```

---

# 42. Week 6 — Better LLM Reasoning

Add:

```text
structured output
multi-stage reasoning
contradiction checks
confidence calibration
better remediation
```

Potentially compare:

```text
LLM alone
vs
Static + LLM
vs
Static + RAG + LLM
vs
Static + RAG + validation
```

This comparison could become a very strong project experiment.

---

# 43. Week 7–8 — Evaluation

Build the benchmark.

Measure:

```text
precision
recall
F1
false-positive rate
per-rule performance
```

Create regression tests.

---

# 44. Week 9 — Observability

Add:

```text
Arize Phoenix
OpenTelemetry
```

Trace:

```text
APK
 ↓
decompiler
 ↓
rules
 ↓
retrieval
 ↓
LLM
 ↓
validation
 ↓
report
```

---

# 45. Week 10 — Showcase

Add:

```text
FastAPI
dashboard
SARIF
Docker
CI/CD
benchmark visualizations
architecture documentation
demo video
```

---

# 46. Scope Ladder

The whole project should now be thought of as:

```text
LEVEL 0
Empty repository

        ↓

LEVEL 1
APK scanner

        ↓

LEVEL 2
5-rule security scanner

        ↓

LEVEL 3
Evidence-grounded scanner

        ↓

LEVEL 4
RAG + LLM security analyst

        ↓

LEVEL 5
Source/sink analysis

        ↓

LEVEL 6
Reachability analysis

        ↓

LEVEL 7
Evaluation framework

        ↓

LEVEL 8
Production platform
```

**Week 1 only requires us to reach LEVEL 4.**

That is the key to keeping the project manageable.

---

# 47. Daily Working Discipline

Each day follows the same loop:

```text
1. Understand the day's component

2. Design the smallest useful interface

3. Implement it

4. Run it on AndroGoat

5. Inspect the output

6. Add a test

7. Commit to Git

8. Record what we learned
```

We should avoid spending an entire day reading documentation without building anything.

---

# 48. Daily “Stop Conditions”

## Day 1 stop when:

```text
sentinel inspect app.apk
```

works.

## Day 2 stop when:

```text
sentinel manifest app.apk
```

works.

## Day 3 stop when:

```text
sentinel scan app.apk --stage rules
```

finds candidates.

## Day 4 stop when:

Each candidate has real evidence.

## Day 5 stop when:

```text
sentinel rag query "..."
```

returns relevant security knowledge.

## Day 6 stop when:

Static evidence → RAG → LLM → validator works.

## Day 7 stop when:

```text
sentinel scan app.apk
```

creates a usable HTML report.

---

# 49. What We Do When Something Goes Wrong

The project has a strict debugging hierarchy.

If a finding is wrong:

```text
1. Check APK/decompilation
2. Check manifest
3. Check deterministic rule
4. Check evidence
5. Check RAG
6. Check LLM
7. Check validator
8. Check scoring
```

We do not immediately change the LLM prompt when the real problem is a broken static detector.

Likewise, we do not change the RAG system when the actual issue is missing source evidence.

---

# 50. The Golden Rule

Whenever something goes wrong, ask:

> **Which layer introduced the error?**

For example:

```text
Incorrect vulnerability
        ↓
Was candidate wrong?
        ↓
Was evidence wrong?
        ↓
Was RAG wrong?
        ↓
Was LLM reasoning wrong?
        ↓
Was validation wrong?
        ↓
Was scoring wrong?
```

This mindset will be important throughout the project.

---

# 51. Final Week-1 Deliverables

At the end of the week we should have:

```text
✓ GitHub repository
✓ Python package
✓ CLI
✓ APK ingestion
✓ SHA256 identification
✓ workspace management
✓ Apktool integration
✓ JADX integration
✓ Manifest analyzer
✓ Attack-surface basics
✓ 5 vulnerability detectors
✓ Evidence extraction
✓ Canonical finding schema
✓ Security knowledge base
✓ Qdrant retrieval
✓ LLM abstraction
✓ Structured LLM output
✓ Evidence validator
✓ Confidence scoring
✓ JSON report
✓ HTML report
✓ Unit tests
✓ End-to-end test
✓ README
✓ Example scan
```

---

# 52. What We Should NOT Optimize During Week 1

Do not optimize:

```text
speed
massive scale
perfect accuracy
beautiful UI
50 rules
multi-agent systems
cloud deployment
GPU infrastructure
```

Optimize:

```text
working pipeline
clean architecture
correct evidence
reproducibility
understandable code
```

---

# 53. Week-1 Success Metric

The most important metric is:

```text
Can someone clone the repository,
install the dependencies,
provide an APK,
run one command,
and receive an evidence-backed security report?
```

If yes:

**Week 1 succeeded.**

---

# 54. Final Demo Story

The first GitHub demo should tell this story:

```text
I give SentinelRAG an Android APK.

SentinelRAG decompiles the application.

It analyzes the manifest and identifies the attack surface.

It runs deterministic security rules to find suspicious code.

For each candidate, it collects concrete source and sink evidence.

It retrieves Android security guidance from a curated knowledge base.

An LLM reasons over the evidence and security context.

A separate validation stage checks whether the LLM's claims are actually supported by the APK.

Finally, SentinelRAG produces a structured security report with severity,
confidence, evidence, CWE/MASVS mappings, and remediation.
```

That is the **Week-1 prototype**.

---

# 55. Exact Target

Our immediate target is:

```text
                     7 DAYS
                       │
                       ▼
              ┌─────────────────┐
              │   SentinelRAG   │
              │    Prototype    │
              └────────┬────────┘
                       │
         ┌─────────────┼──────────────┐
         │             │              │
       STATIC         RAG            LLM
       ANALYSIS       KNOWLEDGE      REASONING
         │             │              │
         └─────────────┼──────────────┘
                       ▼
                 VALIDATION
                       │
                       ▼
                  REPORTING
```

After that, we **do not restart the project**.

We evolve the exact same codebase:

```text
Week 1
Prototype

        ↓

Weeks 2–3
Stronger static analysis

        ↓

Weeks 4–5
Data flow + reachability

        ↓

Weeks 6–7
Better RAG + evaluation

        ↓

Weeks 8–9
Observability + API

        ↓

Week 10+
Dashboard + production hardening
```

# 56. Estimated Time

For the initial prototype:

### 3–5 focused hours/day

**7 days**

### 1–2 focused hours/day

**10–14 days**

### 6+ focused hours/day

**4–6 days**, but I would still recommend keeping the seven-day structure so we do not sacrifice architecture and testing.

For the larger project:

```text
Week 1       Prototype
Weeks 2–4    Strong static analyzer
Weeks 5–6    RAG + LLM improvements
Weeks 7–8    Evaluation + validation
Weeks 9–10   Productionization + showcase
```

So our immediate commitment is **not “build the final SentinelRAG.”**

It is:

> **Build a complete SentinelRAG vertical slice in 7 days, then grow that exact prototype into the larger system.**

That is the path we should follow whenever the project starts getting too large: **return to the Week-1 acceptance criteria, finish the vertical slice, and only then expand the scope.**
