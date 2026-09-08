FILE: DECISIONS.md
SentinelRAG — Architecture Decisions
ADR-001 — Retain Existing Repository

Decision: Keep and refactor the current SentinelRAG repository.

Rationale

Existing implementation already provides:

APK inspection
decompilation
manifest parsing
CLI
deterministic SQL injection prototype
behavior analysis prototype
22 passing tests

Deleting the repository would remove useful implementation and development history without providing architectural benefit.

ADR-002 — Deterministic Rules Are Sensors, Not Gatekeepers

Decision: A deterministic finding is not required before an APK area can be investigated.

Reason

Rule-based systems can miss:

obfuscated implementations
indirect API invocation
reflection
dynamic loading
uncommon malware behavior
complicated control flow
behaviors not represented by existing rules

Therefore:

no deterministic match

must NOT mean:

no malicious behavior

Existing rules remain useful because they provide inexpensive, reproducible, high-confidence evidence.

ADR-003 — Shift from Rule-Heavy Detection to Capability-Driven Investigation

Decision: Do not build hundreds of Android malware regex rules as the primary project architecture.

Instead identify security-relevant capabilities.

Examples:

Accessibility
Dex loading
Reflection
Networking
Process execution
Screen capture
SMS
Overlay
Package installation
Native code
Persistence

Capabilities create investigation seeds.

They do not automatically create malicious findings.

ADR-004 — Threat Intelligence Guides Investigation

Decision: SentinelRAG will maintain security/threat knowledge describing what APIs, strings, permissions, behaviors and relationships are relevant to current Android threats.

Threat intelligence can influence:

seed selection
investigation priority
RAG retrieval
malware behavior correlation

Threat intelligence does NOT prove that the APK is malicious.

ADR-005 — Generic Capabilities Remain Independent of Threat Intel

Decision: SentinelRAG must maintain a generic Android security capability catalog in addition to malware-specific knowledge.

Reason

A newly discovered malware family may not yet exist in the threat database.

Therefore:

Generic capabilities
+
Current threat intelligence

must jointly drive investigation.

This reduces overfitting to known families.

ADR-006 — Separate Internet Research from APK Analysis

Decision: Threat-intelligence collection occurs through a separate research/update pipeline.

APK analysis consumes a versioned knowledge snapshot.

Reasons
reproducibility
provenance
lower latency
reduced prompt-injection exposure
easier evaluation
deterministic experiment replay
security

Future model:

Threat Research Agent
        ↓
Threat KB snapshot
        ↓
APK Analysis Agent
ADR-007 — Store Both Structured and Unstructured Threat Knowledge

Decision: Threat sources produce:

structured intelligence
original text chunks for RAG

Structured intelligence may include:

families
techniques
APIs
permissions
method-name indicators
interesting strings
source/sink relationships
behavioral sequences
provenance
publication date
confidence

RAG chunks preserve source context and explanation.

ADR-008 — LLM Does Not Directly Create APK Evidence

Decision: The LLM determines what should be investigated and interprets evidence, but analysis tools determine what exists.

Principle:

LLM decides what evidence it needs. Program-analysis tools retrieve the evidence.

The LLM must not invent:

methods
API calls
permissions
strings
call relationships
data flows
ADR-009 — Use Bounded Behavior Slices

Decision: Do not send entire decompiled APKs to the LLM.

Create Security Behavior Slices around investigation seeds.

Possible context:

seed API
surrounding method
callers
callees
xrefs
related strings
manifest component
data origin
data destination

Benefits:

smaller context
lower token cost
lower noise
stronger evidence grounding
ADR-010 — Call Graph Alone Is Insufficient

Decision: SentinelRAG should eventually support data-flow relationships as well as call relationships.

Call graph:

A → B → C

Data flow:

sensitive data
→ transform
→ network sink

For security analysis, the second relationship may be substantially more meaningful.

Week-1 implementation may use simplified local flow analysis.

ADR-011 — Separate APK Retrieval and Threat Retrieval

Decision: Treat these as different retrieval systems.

APK Retrieval

Retrieves:

code
methods
strings
xrefs
behavior slices
Knowledge Retrieval

Retrieves:

malware research
OWASP
CWE
Android documentation
threat intelligence

Both contexts can be supplied to the investigation agent.

ADR-012 — Evidence States

Supported evidence states:

OBSERVED

Directly present in APK.

INFERRED

Derived using program analysis.

SEMANTIC_SUSPECT

LLM/semantic system believes behavior deserves investigation.

CORRELATED

Multiple independent observations support a higher-level behavior.

NOT_VERIFIABLE_FROM_APK

Cannot be established from static APK evidence.

ADR-013 — Malware Family Attribution Must Be Conservative

Do not automatically convert behavioral similarity into malware-family identification.

Prefer:

Vultur-like behavior

over:

Confirmed Vultur

unless sufficiently strong independent evidence supports attribution.

ADR-014 — Agentic Analysis Must Be Bounded

The analysis agent may iteratively request evidence.

However it must operate within:

allowed tools
limited investigation depth
limited iteration count
controlled retrieval
structured state
evidence requirements

The goal is controlled security investigation, not unrestricted autonomous behavior.

ADR-015 — LangGraph Is an Orchestration Tool, Not Core State

APKContext remains ordinary application state.

LangGraph may later orchestrate investigation if useful.

Do not tightly couple extraction and security-analysis models to LangGraph.

ADR-016 — Existing Rules Remain Useful

SQLI-001 and similar high-confidence rules remain.

Their new role:

high-confidence evidence sensor

rather than:

mandatory first-stage detector
ADR-017 — Week-1 Priority Is Vertical Integration

Do not optimize for the number of vulnerabilities detected.

Optimize for demonstrating:

knowledge
→ seed
→ context
→ retrieval
→ investigation
→ evidence-backed conclusion

A single convincing end-to-end example is more valuable than dozens of incomplete detectors.

ADR-018 — Central SentinelRAG Principle

Threat intelligence determines where SentinelRAG should look; program analysis determines what is actually present; the LLM determines what the collected evidence most plausibly means.