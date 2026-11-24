# Ariadne contract integration

Date 2026-11-24. Contract revision **1.0.0-draft.1**. The contract is pinned to Ariadne commit `d08678c` (merge of tswierszcz/ariadne#150). Ariadne ships `research index` and `research query`; Tekmerion's adapter is [internal/ariadne](../internal/ariadne/adapter.go).

## 1. Ownership and package

[Ariadne](https://github.com/tswierszcz/ariadne) owns the research interface contract at `docs/research-interface/CONTRACT.md`. The implementation guide is `docs/research-interface/INTEGRATION.md`. Tekmerion owns the experiment, hypothesis, threat-model and report formats described in [IMPLEMENTATION_PLAN.md](../IMPLEMENTATION_PLAN.md).

The local copy under [contracts/ariadne/v1](../contracts/ariadne/v1/contract.schema.json) contains the exact schema, validation helper and conformance fixtures from Ariadne. [PIN.json](../contracts/ariadne/PIN.json) records their upstream location, revision and file hashes. The pin has status `upstream-commit` and names the Ariadne commit that contains this exact package; the vendored files are byte-identical to that commit's `docs/research-interface/v1`.

The authoritative schema namespace is `urn:ariadne:research:contract:1`. Resolve it from the local schema package. The schema defines `Manifest`, `Identity`, `Request`, `Response`, `Record` and the nested evidence structures. Draft readers accept the pinned revision exactly.

## 2. Data flow

```text
Pinned source + build recipe + threat model
    -> Built library and resolved classpath
    -> Ariadne frozen analysis bundle
    -> API/call discovery and source context
    -> Tekmerion hypotheses
    -> Exact method targets and batched Ariadne queries
    -> Raw static evidence in the Tekmerion ledger
    -> API-level tests and independent security assertions
    -> Review, reduction, replay and report
```

The calls are `ariadne research index` and `ariadne research query`. Indexing is performed once per artifact/configuration/root scenario. Queries reuse the frozen graph and its assumptions.

## 3. Request construction

Every request identifies `analysis_id`, `request_id`, `schema_version` and an operation. Tekmerion maps request and target ids to its `run_id` and `hypothesis_id` and saves the raw request.

| Operation | Purpose |
|---|---|
| `entries` | Public API/framework entry records for context and candidate selection |
| `methods` | Exact method identities, instances and available source locations |
| `calls` | Declared calls, including external/JDK operations with unavailable bodies |
| `callers`, `callees` | One-hop graph context with edge provenance |
| `reachability` | Batched targets with path, entry and model-gap evidence |

Target by `method_id` or by a selector containing instance, binary class name, JVM method name and full descriptor. The two forms are mutually exclusive. A batch has 1–256 distinct target ids. A discovery filter using a method name alone can find overloads; the reachability target must resolve an exact signature.

Use indexed roots or an explicit subset of indexed root node ids. Querying a different scenario requires a new bundle. A subset search retains the graph prepared for the larger indexed root set and exposes that basis.

Discovery responses have stable pagination. A continuation binds the original analysis, operation, filters and effective record limit. Tekmerion preserves these parameters when using the cursor.

## 4. Independent assessment axes

| Axis | Values | Consumer interpretation |
|---|---|---|
| Target resolution | `matched`, `missing`, `ambiguous`, `shadowed` | Can this method identity be assessed in this selected code universe? |
| Graph search | `found`, `not_found`, `not_evaluated`, `incomplete` | Was a witness found or the available search completed? |
| Model assessment | `complete_under_declared_model`, `incomplete`, `undetermined` | What recorded limitations affect the target assessment? |

An `ok` response may contain a missing target or incomplete search. `not_found` with an incomplete model remains a combined uncertainty in Tekmerion's ledger. A budget cutoff before a witness stays `incomplete`. A positive witness discovered before a cutoff remains `found` with incomplete entry coverage.

The independent experiment assessment records whether its own security assertion was observed. Both a broken implementation and its property-preserving control may reach the same method. The ledger keeps these outcomes separately.

## 5. Evidence to retain

- Exact selected method, class/component identities and available content hashes.
- Entry ids, path node ids, edge ids and copied evidence records.
- Every edge's basis, character, rule and individual site conditions.
- Framework traversal pass, client/supplied-dispatch dependence and specialized receivers.
- Global and relevant gap information, relevance-rule version and uncertain scope.
- Limits, work completeness, omitted entries and truncated paths.
- Tool/model versions, provenance, source bindings and raw machine response.

The evidence characters are `jvm_rule`, `library_model`, `input_declaration`, `heuristic` and `unclassified`. These describe the source of a claim. An unclassified character remains visible in the report.

Source paths and line tables can be hints. The source-binding field distinguishes verified build correspondence, a declaration and unavailable information. CodeQL adapters must record their own source/database/query identities and matching assumptions.

## 6. Process and validation handling

The adapter starts a new attempt record, invokes Ariadne and verifies exit status, fresh output, schema, analysis id, request id, operation and target order. It retains stderr and command/environment identities while excluding secrets.

| Outcome | Adapter handling |
|---|---|
| Exit 0 and validated `ok` response | Persist independent static assessment axes |
| Exit 2 | Record invalid request/schema/operation/binding with the producer error code |
| Exit 1 | Record bundle, I/O or execution failure |
| Missing output or interrupted process | Record failed/inconclusive attempt and invocation diagnostics |
| Schema/hash/correlation failure | Reject evidence consumption and retain raw bytes for diagnosis |

Named error codes include `INVALID_REQUEST`, `UNSUPPORTED_SCHEMA`, `UNSUPPORTED_OPERATION`, `UNSUPPORTED_FILTER`, `ANALYSIS_MISMATCH`, `INVALID_CURSOR`, `ROOTS_OUTSIDE_INDEX`, `BUNDLE_CORRUPT`, `INCOMPATIBLE_BUNDLE`, `IO_ERROR`, `INTERNAL_ERROR` and `CANCELLED`. Retry only when the recorded error is retryable and the run budget permits it. Method absence is a successful domain result.

Consumers must enforce semantic invariants beyond JSON Schema. Examples include missing targets with no path, complete adjacency between path nodes/edges, valid root subsets, analysis binding, record references and preservation of frozen evidence.

## 7. Limits

The pinned draft defaults to 100 discovery records, 20 entries per target, 100 displayed nodes per path and 1,000,000 deterministic work units per query. Successful responses echo effective limits. Budget accounting and root-sensitive model assumptions are part of the revisioned producer semantics.

Tekmerion separately controls wall time, memory, LLM calls/cost and test execution. Truncated presentation remains distinct from a graph-search cutoff. A hard worker cancellation can leave no valid producer result and is recorded as an execution failure.

## 8. Developing with fixtures

[cases.json](../contracts/ariadne/v1/cases.json) describes the expected shape and semantic outcome of each fixture. [The sample bundle](../contracts/ariadne/v1/fixtures/bundle/manifest.json) contains synthetic metadata for public `extract`, private `writeEntry` and private `unused`, plus an unresolved reflection gap. It identifies its provenance as `fixture` and ships no executable JAR.

A fixture adapter matches complete recorded requests to recorded responses. Unknown inputs produce a fixture-adapter error. Reports retain fixture provenance. Real-library pilot acceptance requires an actual Ariadne binary and graph bundle.

The validation helper requires Node.js with AJV 8 and `ajv-formats` available to CommonJS module resolution.

```sh
node contracts/ariadne/v1/validate.mjs
```

The helper validates the schema package, bundle hashes, references and positive/negative examples. Its role is contract-data conformance. Runtime algorithm acceptance is additional work.

## 9. Adapter

`internal/ariadne` is the Go adapter.

- `Index` runs `ariadne research index`. It always passes `-roots` and can pass `-scope reachable`; it refuses to run without roots and checks that the published bundle records the requested roots and scope. Indexing is offline and never overwrites a bundle.
- `CLI.Query` runs `ariadne research query` against one bundle. Each attempt gets its own evidence directory with `request.json` (the bytes sent), `response.json` (written by Ariadne itself), `stderr.txt` and `attempt.json` (argv, binary hash, exit, outcome, hashes).
- `Check` accepts a response only when the exit status matches it (0 result, 2 invalid request, 1 bundle/I/O/internal failure) and `schema_version`, `contract_revision`, `request_id`, `analysis_id`, `operation` and the order of reachability targets match the request. A mismatch is recorded as `unusable` and the raw bytes are kept.
- `Fixture` replays the conforming request/response pairs of `cases.json` and marks every result `provenance = fixture`. An unrecorded request is an error.
- A reachability request holds at most 256 targets. Each query process loads the bundle again, so `Batches` fills batches up to that limit.

In a bundle indexed with `-scope reachable`, a method neither reached from the roots nor part of the input resolves as `missing`. Example: the unused method of the selected dependency copy (case g of Ariadne's control library). Interpret `missing` against the bundle's scope before concluding that a method does not exist.

```sh
go test ./...                                   # contract pin, fixture mode, checks
(cd ../ariadne && go build -o bin/ariadne ./cmd/ariadne)
ARIADNE_SRC=../ariadne go test ./internal/ariadne -run Ariadne -v   # real binary, control library
```

The integration test indexes `testdata/research` in Ariadne with the producer default scope and with `-scope reachable`, then checks the cases of its `EXPECTED.MD`, discovery of JDK `Files` calls, exit 2 for invalid requests and exit 1 for a corrupted bundle. `ARIADNE_BIN` overrides the binary.

## 10. Implementation checklist

1. TM0 reads the pinned schemas and fixtures, validates them and records raw correlated evidence.
2. TM1 prepares a pinned source/build manifest and integrates real RI1–RI2 indexing when available.
3. TM2 discovers hypotheses from API/source context. TM3 submits exact targets using RI3 and the required RI4 operations.
4. TM4 executes API-level experiments. TM5 evaluates independent property assertions and replay evidence with RI5.
5. TM6 qualifies one real-library pilot. Optional runtime observations follow RI6.

Contract tests also need duplicate JSON members, invalid JVM descriptors, class conflicts, receiver specializations, conditional edges, multiple pages, cursor mismatches and interruption/retry behavior. The first hand-off includes representative fixtures and a list of required implementation cases in the authoritative contract.

## 11. Updating the pin

Review the upstream specification/schema/fixture changes as one revision. Copy the complete version package, regenerate all file hashes in `PIN.json`, run conformance checks and update consumer tests before changing the pinned revision. Record an actual upstream source commit after publication. Required migrations are part of the consumer change.

The ledger, manifest and report work of TM0 remain tracked in the implementation plan.
