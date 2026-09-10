# Investigation seeds and bounded APK graphs

Existing threat/profile matches remain the evidence inventory. Seed conversion
does not match new malware behaviors or make family decisions. Every candidate
has a `selected_for_investigation` flag: weak and generated candidates remain
in JSON even when expansion is declined. `matched_indicators` preserves the
original threat matches and profile analyses retain their artifact inventory.

Priority is located APPLICATION, APPLICATION_CANDIDATE, UNKNOWN, THIRD_PARTY,
then unlocated APK evidence. FRAMEWORK and GENERATED candidates remain reportable
but are excluded from primary recursive investigation. Application package prefixes
include subpackages. Exact recovered manifest components can establish application
ownership outside that prefix. Other namespaces remain UNKNOWN unless explicit
library recognition or corroborated ownership signals apply.

Ownership is separate from evidence state and artifact coverage. Candidate ownership
uses application-resource references plus a package literal, or an already resolved
call from application/candidate code into an otherwise unknown source class. Call
propagation is limited to two hops and never crosses unresolved calls or relabels
recognized framework/library/generated code. These are ownership hints, not authorship
proof or behavior evidence. JSON retains confidence, reasons and source references.

Generic method names require local context. APK-wide permissions cannot make
an unrelated library call local Accessibility evidence. Comments and string
contents cannot establish API call sites. Quality and match strength are
deterministic investigation heuristics, not probabilities of malicious behavior.

The Java source index masks comments and literals before locating methods and
calls. It supports a single top-level class per file and separately identifies
anonymous callback methods. It does not treat registering a callback as invoking
its body. Kotlin expansion, named nested classes, reflection, inheritance dispatch,
and ambiguous overloads remain outside this resolver. The existing Accessibility
resolver remains available under its compatibility report.

Expansion follows direct callers and callees to depth **1** by default (configurable
0–3), with 40-method and 500-node budgets and visited-method cycle protection.
Same-class targets must be private, static or final. Local helper receivers must
be freshly allocated with an exact declared type; ambiguous targets stay unresolved.
These are syntactic source relationships, not a whole-program reachability graph.

Eligible seeds are grouped by behavior, origin, containing method/class, indicator
type, API action and provenance. Representatives retain all grouped references;
duplicates and budget-rejected candidates remain in JSON. Builder settings default
to 12 representatives per behavior, 8 expanded methods per behavior, 24 new nodes
per expanded method and 2 third-party methods overall. Expansion prioritizes ownership
and balances behaviors within a provenance tier. The 40-method/500-node hard limits
remain authoritative. Framework calls are terminal boundary nodes; their implementation
bodies are not traversed. Boundary does not imply that an unresolved receiver is known
to be a framework API; `target_provenance` is separate from call-site ownership.

`CALLS` to an `api_call` node establishes a call expression in a method. An edge
to another `method` requires local resolution. `CONTAINS` a string does not prove
it reaches any API. `PASSES_TO` is emitted only for flows returned by the existing
bounded local-flow validator, whose prototype limitations still apply.

The generic graph maps Accessibility service declarations and source-resolved
callback ownership. It does not blindly promote the legacy graph's edges. Legacy
unsupported relationships and coverage limitations remain explicit. Coverage is
separate from evidence states. A partial graph must not be interpreted as proof
that missing behavior is absent.

JSON adds `investigation_seeds`, `matched_indicators` and optional `behavior_graph`.
`source_ownership` records classification for recovered sources, independently of the
coverage analyzer's unchanged application-package counts. Graph nodes carry call-site
provenance, boundary metadata and explicit truncation limits.
Existing report fields, profile outcomes, RAG inputs and LLM schemas are preserved.
The CLI selects the highest-priority qualified API location for its existing
reasoning path, while graph expansion can include other selected seed types.
