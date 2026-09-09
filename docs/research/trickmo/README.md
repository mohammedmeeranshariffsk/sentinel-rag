# TrickMo research inventory — first collection pass

Collected 2026-09-09. Status: research material and database-design input only.

This directory is not read by SentinelRAG's runtime. No binaries were downloaded or executed; no malware infrastructure was contacted. It contains a partial public-source inventory, not a claim to cover all TrickMo variants or all published research.

## Read these files

- [catalog.json](catalog.json): source registry, report cohorts, typed indicators, behavior observations, selected sample metadata and explicit gaps.
- [extraction-profile.json](extraction-profile.json): concrete permissions, APIs, strings, commands, components, files, and structural checks for APK extraction. Every entry states whether it is reported fact or an analyst search target.
- [extraction-profile.md](extraction-profile.md): readable view of the extraction profile and the evidence bundles that should seed call-graph verification.
- [reported-network-indicators.csv](reported-network-indicators.csv): 24 historical values transcribed from the publisher's public list. `false` in `verified_live` means not checked; it does not mean inactive.
- [verification-templates.json](verification-templates.json): explicit APK investigation and relationship requirements for all nine collected behavior observations.
- [Database template proposal](../../malware-knowledge-schema.md): proposed reusable structure, validation requirements and future matching semantics.

## Source register

| ID | Source | Coverage and access |
|---|---|---|
| cleafy-2024 | [Cleafy, September 10, 2024](https://www.cleafy.com/cleafy-labs/a-new-trickmo-saga-from-banking-trojan-to-victims-data-leak) | Primary report; body reviewed. Linked code/manifest images failed retrieval and were not transcribed. |
| zimperium-2024 | [Zimperium, October 11, 2024](https://zimperium.com/blog/expanding-the-investigation-deep-dive-into-latest-trickmo-samples) | Primary report; body and technique table reviewed. |
| threatfabric-c | [ThreatFabric variant report](https://www.threatfabric.com/blogs/new-trickmo-variant-device-take-over-malware-targeting-banking-fintech-wallet-auth-app) | Primary report; body and appendix reviewed. Exact publication date unverified. |
| mitre-s0427 | [MITRE ATT&CK S0427](https://attack.mitre.org/software/S0427/) | Curated secondary record, version 1.1; modified April 25, 2025. |
| ibm-2020 | [Original IBM citation](https://securityintelligence.com/posts/trickbot-pushing-a-2fa-bypass-app-to-bank-customers-in-germany/) | Redirected to a generic page. Not treated as independently read. |
| zimperium-iocs | [Publisher IOC directory](https://github.com/Zimperium/IOC/tree/master/2024-10-TrickMo) | Directory and [network list](https://github.com/Zimperium/IOC/blob/master/2024-10-TrickMo/domains.csv) read; APK/dropper CSV fetches failed. Revision not pinned. |

## What the collection tells us about the schema

The critical unit is a **source-backed observation scoped to a report cohort or sample**, not a family-wide array of suspicious names.

1. Keep exact tokens apart from prose descriptions and analyst search suggestions. Missing implementation details remain unknown.
2. Separate Android API calls, class names, app-defined methods, command strings, permissions, assets and network indicators. They require different extractors and matching rules.
3. Keep report cohorts separate until sample evidence justifies merging. A report date is not a malware version.
4. Store declared capability separately from demonstrated use. Negative observations are bounded to the researcher's inspected stages, not proof of permanent absence.
5. Preserve the original source chain. MITRE referencing IBM is not independent corroboration; neither is one vendor repeating another vendor's recap.
6. Store report-derived behavior relationships as research claims. They are future verification targets, not call edges observed in a new APK.

## Coverage matrix

| Category | Collected state |
|---|---|
| Behavior descriptions | Nine scoped observations across the selected reports |
| Strings, assets, packages, classes, libraries, commands | Typed records with report section locators |
| Method names | One exposed name; no invented declaring class or signature |
| Exact API invocations | Incomplete; a class mention is not an invocation |
| Exact manifest permissions | Unverified in this pass; do not manufacture a list from described capabilities |
| Intents | Short names retained as reported; no silent full-name expansion |
| Network IOCs | Historical source values only; no assertion of current ownership/activity |
| Sample hashes | One selected published module hash; no local sample examination |
| Call graph / data flow | No sample graph collected; relationship verification remains future work |

## Why this is not a complete dataset yet

The missing manifest/code figures and sample lists should be recovered from their publishers before promotion into a production knowledge base. The available reports do not expose every implementation detail. Add a reviewed manifest and decompiled-code inventory for each authorized sample when sample analysis becomes the agreed next task.

The corpus also needs a systematic bibliography expansion, immutable source snapshots where permitted, source hashes/revisions, independent review, and benign-app comparison data. No numeric family-attribution weights are assigned before that calibration.

Generic signals can occur in legitimate apps. Even a distinctive token is an investigation lead unless corroborated within the analyzed APK. Never use an unrelated app's command construction as evidence for a family simply because a research report contains a similar word.

## Example: what the APK analyzer would do

Run this draft profile explicitly:

```text
sentinel analyze sample.apk --profile docs/research/trickmo/extraction-profile.json --output-json reports/trickmo-review.json
```

The JSON report includes `profile_analyses` with exact artifact matches, behavior
bundle outcomes, required relationships, missing evidence, profile version and
profile status. Repeat `--profile` to review the same APK against more profiles.

For `verify:trickmo:credential-overlay:v1`, `SaveHtml`, `getAndroidID`, a WebView, or overlay capability can create a seed. The behavior is supported only if bounded APK analysis establishes all of these relationships in compatible code/content:

```text
target package or unlock context
             ↓ selects/triggers
deceptive credential/unlock UI
             ↓ collects
user-entered secret
             ↓ data_flows_to
remote request
```

If the APK contains `getAndroidID` and a WebView but the page is remote and unavailable, the outcome is `PARTIAL_RELATIONSHIP` or `NOT_VERIFIABLE`, not credential theft. Even `RELATIONSHIP_SUPPORTED` supports the behavior; TrickMo family attribution remains a separate, stricter decision.
