# SentinelRAG Project State

## IMPLEMENTED — integrated static investigation prototype

The CLI connects APK inspection, decompilation coverage, manifest parsing, evidence extraction, raw threat matching, deterministic behavior qualification, investigation seeds, source ownership, bounded per-behavior graphs, graph-aware RAG, structured reasoning, deterministic validation and JSON/Markdown reporting.

* `BehaviorInvestigation` packages each qualified behavior's graph, context, retrieval, untrusted reasoning, validation and findings.
* `BehaviorContext` distinguishes LOCAL facts, APK-wide facts, source relationships, local flows, unresolved relationships and coverage limitations.
* A versioned 35-behavior starter catalog supplements existing JSON threat records.
* Raw behavior matches remain preserved even when qualification rejects an investigation.
* Source/sink labels are separate from proven flows.
* Broad, rejected, duplicate and unselected seed evidence remains reportable.
* Optional Gemini/RAG failure does not suppress deterministic findings.
* `--no-llm --no-rag` supports fully offline reports.
* Exact structured claims are validated against canonical IDs, values and graph edges.
* Free-form LLM prose remains untrusted and does not set severity, evidence state or family identity.
* JSON/Markdown reports include coverage, matches, qualification, investigations, findings, unresolved relationships, limitations and evidence references.

## CURRENT — precision calibration

Estimated portfolio-v1 completion: **~70%**.

The complete pipeline exists. Current work is focused on improving analytical precision rather than adding major new subsystems.

Behavior qualification now follows:

```text
RAW INDICATOR
    ↓
BEHAVIOR HYPOTHESIS
    ↓
QUALIFICATION
    ↓
INVESTIGATION
```

Qualification permits investigation; it does not prove behavior, malicious intent or family identity.

### AndroGoat

The deterministic positive flow remains:

```text
ip2.getText().toString()
    ↓
StringBuilder command construction ("ping ")
    ↓
Runtime.getRuntime().exec(ip1)
```

Expected result:

* Evidence State: `OBSERVED`
* Severity: `MEDIUM`

Runtime reachability, shell interpretation, confirmed command injection, exploitability and malicious intent remain unverified.

Qualification reduced unrelated generic behavior investigations while preserving this flow.

### SpyNote

SpyNote is the primary real-malware precision regression.

Strong investigation areas currently include:

* Accessibility Service behavior
* Accessibility-driven UI automation
* Screen Capture / MediaProjection
* Location Collection
* Credential/UI Collection
* Device Admin operations
* Overlay/Phishing
* Foreground-Service Persistence
* Boot Persistence
* Installed-App Enumeration
* Process Execution capability
* Dynamic Code Loading
* Runtime Receiver Registration
* Package/Launcher Hiding

Remaining qualification areas needing tightening:

* Encryption / Crypto — generic `getInstance` must not qualify.
* Device/System Reconnaissance — generic `getSystemService` must not qualify.
* Scheduled Persistence — generic `schedule` / `enqueue` must not qualify.
* Root Detection — `Runtime.exec` alone must not qualify.
* Reflection — generic method names require reflection-specific API/type context.

`Dynamic Code Loading` and `DEX/JAR Loading` currently overlap and should later be modeled through cleaner behavior taxonomy rather than duplicate conclusions.

### TrickMo

TrickMo remains the incomplete-artifact regression case.

Expected behavior:

* analysis remains `PARTIAL` when coverage requires it;
* encrypted/unreadable DEX remains an explicit limitation;
* partial JADX and failed Apktool remain visible where observed;
* missing application implementation source creates uncertainty;
* weak generic evidence such as `Ycrispwall.performAction` remains weak/unselected without corroboration.

Missing source must never be interpreted as behavior absence.

## PARTIAL — analysis capability

* Java source resolution remains bounded and conservative.
* Ownership may remain `APPLICATION_CANDIDATE` or `UNKNOWN` when evidence is insufficient.
* The deterministic flow recognizer currently handles a narrow local command-construction pattern.
* Parameters, returns, fields, callbacks and broad interprocedural flows are not yet generally supported.
* Coverage describes recovered artifacts, not complete behavior visibility.
* Reflection, dynamic loading, Kotlin, ambiguous dispatch and hidden/loaded code remain important uncertainty sources.
* Profile outcomes remain indicator/co-occurrence reviews unless deterministic relationships are verified.
* Generic runtime intent, exploitability and malware-family attribution are not automatically verified.
* The starter catalog still needs per-behavior citations, labeled examples and false-positive calibration.
* RAG remains primarily per-run/in-memory.
* External-tool isolation, caching, timeout/resource controls and production telemetry remain incomplete.

## PLANNED — ordered

1. Finish qualification precision using positive and negative controls.
2. Introduce declarative relationship-aware **Behavior Rule Engine v2**.
3. Add deterministic-first **cross-behavior correlation**.
4. Expand source/sink and bounded interprocedural analysis.
5. Add semantic retrieval over recovered APK implementation code.
6. Add DEX-level fallback when Java recovery is incomplete.
7. Build labeled FP/FN evaluation and benchmark artifacts.
8. Complete portfolio-v1 case studies and documentation.

## Portfolio readiness

Approximate current capability status:

| Area                           | Completion |
| ------------------------------ | ---------: |
| APK inspection / workspace     |        95% |
| Decompilation / coverage       |        90% |
| Evidence extraction            |        85% |
| Threat matching / knowledge    |        75% |
| Ownership / seeds              |        85% |
| Behavior qualification         |        70% |
| Behavior graphs                |        75% |
| Deterministic source/data flow |        35% |
| Threat RAG                     |        75% |
| Structured reasoning           |        75% |
| Deterministic validation       |        80% |
| Findings / reporting / CLI     |        85% |
| Cross-behavior correlation     |        10% |
| APK semantic retrieval         |        10% |
| DEX fallback                   |        10% |
| Evaluation / benchmarking      |        20% |

Overall portfolio-v1 estimate: **~70%**.

The project can become job-application ready before every planned enhancement is complete. The target application checkpoint is approximately **80–85%**, after qualification stabilizes, Behavior Rule Engine v2 exists, initial correlation/source-sink improvements are implemented and an initial benchmark is available.

## Regression contract

* **AndroGoat:** preserve `OBSERVED / MEDIUM` local input → command construction → `Runtime.exec`.
* **SpyNote:** preserve strong source-backed malware investigations while reducing qualification from generic indicators.
* **TrickMo:** preserve partial-coverage semantics and weak generic-seed handling.

Current development mode:

```text
real report
  ↓
highest-impact analytical error
  ↓
root cause
  ↓
smallest generalized fix
  ↓
positive + negative regression tests
  ↓
rerun
```
