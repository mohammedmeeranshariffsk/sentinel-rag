SentinelRAG

Threat-informed, evidence-grounded Android malware and security analysis using static program analysis, RAG and bounded agentic AI.

SentinelRAG investigates Android APKs by combining current threat knowledge with evidence extracted directly from application code.

Rather than relying exclusively on static signatures or asking an LLM to inspect an entire application, SentinelRAG identifies security-relevant capabilities, expands those observations into focused behavior context, retrieves relevant threat intelligence and lets an AI investigator reason over the evidence.

Why SentinelRAG?

Traditional rule-based Android scanners are strong at detecting patterns they already know.

They may struggle with:

new malware behavior
obfuscation
indirect implementation
reflection
dynamic payloads
uncommon execution paths

Pure LLM analysis has the opposite problem:

large APKs exceed practical context
findings may be inconsistent
evidence can be hallucinated
analysis is difficult to reproduce

SentinelRAG combines the strengths of both approaches.

Threat Intelligence
       +
Static Program Analysis
       +
RAG
       +
Agentic Investigation
       ↓
Evidence-grounded conclusions
Core Principle

Threat intelligence determines where SentinelRAG should look; program analysis determines what is actually present; the LLM determines what the collected evidence most plausibly means.

Architecture
                   Threat Intelligence Sources
                              │
                              ▼
                    Threat Research Pipeline
                              │
                              ▼
                    Threat Knowledge Base
                      ┌───────┴───────┐
                      │               │
                Structured Intel   RAG Corpus
                      │               │
                      └───────┬───────┘
                              │

==========================================================

                           APK
                            │
                            ▼
                    APK Decompilation
                            │
                            ▼
                 Static Evidence Extraction
                 ┌─────┬─────┬─────┬─────┐
                 │     │     │     │
               APIs strings methods manifest
                 │     │     │     │
                 └─────┴──┬──┴─────┘
                          │
                          ▼
                  Capability Discovery
                          │
              generic security knowledge
                         +
                 current threat intel
                          │
                          ▼
                Investigation Seeds
                          │
                          ▼
                  Context Expansion
               ┌──────────┼──────────┐
               │          │          │
             Xrefs     Call graph  Data flow
               │          │          │
               └──────────┼──────────┘
                          ▼
                 Security Behavior Slice
                          │
               ┌──────────┴──────────┐
               │                     │
               ▼                     ▼
          APK Retrieval          Threat RAG
               │                     │
               └──────────┬──────────┘
                          ▼
                 Agentic Investigation
                          │
                          ▼
                     LLM Analysis
                          │
                          ▼
                  Evidence Validation
                          │
                          ▼
                     Final Report
Example

SentinelRAG observes:

DexClassLoader

That alone does not mean the application is malicious.

It becomes an investigation seed.

The analysis system may investigate:

What dex file is loaded?
        ↓
Where does that file originate?
        ↓
Who writes it?
        ↓
Was it downloaded?
        ↓
Is it decrypted first?
        ↓
What code is invoked after loading?

Possible resulting evidence:

HTTP response
    ↓
decrypt()
    ↓
payload.dex
    ↓
DexClassLoader
    ↓
reflection
    ↓
payload method invocation

Only after collecting this context does the reasoning layer evaluate the behavior.

Security Behavior Slices

SentinelRAG avoids sending entire decompiled applications to the LLM.

Instead it constructs focused Security Behavior Slices.

Example:

Seed
----
getRootInActiveWindow()

Manifest
--------
BIND_ACCESSIBILITY_SERVICE

Call context
------------
onAccessibilityEvent()
    ↓
collectText()
    ↓
encrypt()
    ↓
upload()

Related APIs
------------
AccessibilityNodeInfo.getText()
Cipher.doFinal()
OkHttpClient

Relevant strings
----------------
"password"
"/device/update"

This gives the reasoning model focused, evidence-rich context.

Threat-Informed Analysis

SentinelRAG maintains structured knowledge such as:

malware techniques
Android APIs
permissions
method patterns
interesting strings
behavior relationships
source/sink patterns
known malware characteristics

This intelligence determines where the analyzer should invest additional effort.

Threat intelligence is treated as guidance, not proof.

RAG

SentinelRAG uses retrieval in two distinct ways.

Threat Knowledge Retrieval

Sources may include:

Android malware research
OWASP MASVS / MASTG
CWE
Android documentation
security research
ATT&CK
APK Retrieval

Searches:

methods
source code
strings
API usage
call relationships
behavior slices

Together these give the AI investigator both:

What security research says

and:

What this APK actually does
Agentic Investigation

The AI investigator may call controlled analysis tools such as:

search_api()
search_string()
find_xrefs()
inspect_method()
find_callers()
find_callees()
trace_data_flow()
inspect_manifest_component()
retrieve_threat_intel()

Example:

Hypothesis
    ↓
Need additional evidence?
    ↓
request analysis tool
    ↓
collect evidence
    ↓
re-evaluate hypothesis
    ↓
final conclusion

The agent is bounded by explicit tools and evidence requirements.

Evidence Model

SentinelRAG differentiates:

OBSERVED
Direct evidence from APK artifacts.

INFERRED
Derived through program analysis.

SEMANTIC_SUSPECT
AI-discovered hypothesis requiring validation.

CORRELATED
Multiple observations support a higher-level behavior.

NOT_VERIFIABLE_FROM_APK
Requires runtime or external evidence.
Existing Foundation

Currently implemented:

APK inspection
SHA-256 workspace model
Apktool integration
JADX integration
AndroidManifest.xml analysis
Java source analysis
SQL injection prototype
malware behavior prototype
CLI
automated tests

Current test baseline:

22 passed
Deterministic Rules

SentinelRAG retains deterministic analysis where it provides strong value.

For example:

SQL injection source → sink
debuggable configuration
exported components
cleartext settings

However deterministic rules are not gatekeepers.

A new or complex malicious behavior may still be investigated even when no existing rule detects it.

Current Development Goal

The immediate goal is a one-week end-to-end prototype demonstrating:

APK
 ↓
evidence extraction
 ↓
security capability
 ↓
threat-informed investigation seed
 ↓
behavior slice
 ↓
RAG
 ↓
agentic investigation
 ↓
LLM conclusion
 ↓
evidence validation

The emphasis is depth and evidence quality rather than broad vulnerability coverage.

Repository Direction

Planned architecture:

src/sentinel/
├── apk/
├── decompiler/
├── manifest/
├── extraction/
├── program_analysis/
├── threat_intel/
├── retrieval/
├── investigation/
├── reasoning/
├── correlation/
├── rules/
├── reporting/
└── cli/
Project Philosophy

SentinelRAG is not intended to be:

APK → LLM → "malicious"

Nor is it intended to be:

APK → hundreds of regex signatures

Instead:

Current threat knowledge
          ↓
Where should we investigate?
          ↓
Program analysis
          ↓
What does the APK actually do?
          ↓
RAG + agentic reasoning
          ↓
What conclusion is supported by evidence?

That is the SentinelRAG approach.