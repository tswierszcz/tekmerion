# Tekmerion implementation plan

Date 2026-11-24. Status PLANNED. The [Ariadne contract package](docs/ARIADNE_CONTRACT.md) is pinned to an upstream commit, and the Ariadne adapter (fixture replay and the real `research index`/`query`) is implemented in `internal/ariadne`. TM1 target preparation (controlled build, run manifest, source index, real `research index`) is implemented; see [Target preparation](docs/TARGET_PREPARATION.md). TM0 now includes a SQLite-backed fixture ledger and deterministic fixture Markdown/JSON exports; budget admission/accounting and offline model-cost estimates are implemented; the full research ledger and final research report remain planned. This document specifies implementation and the acceptance evidence for each increment.

## Current implementation priority (2026-11-25)

The [Recon → Hunt → Validate plan](docs/RESEARCH_HARNESS_IMPLEMENTATION_PLAN.md) refines the next TM0–TM6 increments. Start with strict adapter evidence acceptance (RH-T0) and persistent state (RH-T1), then Recon and hypothesis discovery. It records the Cloudflare source revision, adaptation policy, independent verification and the H0–H5 coordination milestones with Ariadne. Existing implementation status is unchanged by this planning update.

Implementation started (2026-11-25): the first RH-T0 increment adds strict response-schema and evidence validation to the Tekmerion adapter, hash-bound bundle checks and regression tests. Fixture and real Ariadne full/reachable integration tests pass. The follow-up adds graph-wide selected-class/method ownership and canonical/receiver-specialization checks, schema validation of all bundle records and regressions for hash-valid invalid graphs. All 28 contract cases and `go vet` pass. The listed Tekmerion graph checks are implemented; shared H0 acceptance against the separate Ariadne RH-A0 changes remains pending. See the harness plan for scope and evidence. RH-T1 has started: SQLite run/task/attempt/artifact storage, expiring exclusive leases, immutable attempt history and fixture-only audit/resume/status/report commands are implemented. The follow-up adds state schema 2 with version-1 migration, fixed-point budget configuration, atomic paid-task/request admission, protected stage reserves, uncertain-charge retention and idempotent settlement. Status/report expose the durable accounting; `audit -fixture` accepts an optional budget file. State schema 3 adds one-shot dispatch fencing and saved forecasts. Offline `estimate` and explicit bounded `infer` use a replaceable OpenRouter adapter with role-specific inputs, local structured-output checks, usage/cost recording and reserved retries. They are tested with synthetic/local HTTP only. RH-T2 now connects prepared source/API context to strict Recon output and immutable initial coverage, with offline/replay modes and an optional bounded model path. New preparations retain original project bytes for reliable hash verification. The first RH-T3 increment now adds bounded per-unit Hunt, strict source/authority/anchor validation, exact root-cause fingerprints with multiple entry occurrences, bundle-validated static triage and append-only coverage events in state schema 5. Offline/replay/model queues resume accepted output without another paid request, preserve partial results on budget exhaustion and report static uncertainty separately from defect/reproduction/novelty. Real Ariadne control tests use a local synthetic model. The first RH-T4 increment (2026-11-26) runs a checked-in Java harness against the original pinned library in a bounded sandbox (systemd user scope for memory/tasks, prlimit for CPU/file size/open files, bubblewrap for a read-only system, no network and a cleared environment). A capability probe verifies every limit before target code runs. Trusted host code evaluates the file-confinement assertion on the terminated worker's writable directories and records an immutable reproduction axis in state schema 6. On the control library the `Extractor#writeEntry` candidate is reproduced, and a modified target invalidates the result. Generated harnesses, corrective-patch copies, Jazzer, independent Validate, richer context expansion, cross-run coverage reconciliation, catalogue refresh and calibration remain planned.

## 1. Objective

Given a pinned open-source JVM library and a declared threat model, discover candidate security properties, generate concrete vulnerability hypotheses, assess API reachability, and produce reproducible experiments that support or refute those hypotheses.

The initial user input may contain zero hypotheses. Discovery is a required stage. A successful pilot can end with rejected or unresolved hypotheses when the evidence warrants those outcomes.

The first pilot covers one library, one revision, one execution scenario, and one vulnerability class. A small local archive-extraction fixture is proposed as the control target because it supports a clear file-confinement property. Selection of a real pilot library follows a reproducible build and available documentation.

## 2. Repository responsibilities

| Component | Owner |
|---|---|
| JVM bytecode, class selection, components, call graph, API roots | Ariadne |
| Static paths, edge provenance, model gaps, graph scenarios | Ariadne |
| Runtime identity correlation and optional target trace configuration | Ariadne |
| Repository checkout, build recipe and run manifest | Tekmerion |
| Documentation and source context, threat model, security properties | Tekmerion |
| LLM hypothesis generation and evidence review | Tekmerion |
| CodeQL adapter, JUnit harnesses and Jazzer campaigns | Tekmerion |
| Experiment execution, input reduction and security assertions | Tekmerion |
| Findings ledger, known-issue comparison and research report | Tekmerion |

The companion Ariadne plan is `RECOMMENDATION/RESEARCH_INTERFACE_IMPLEMENTATION_PLAN.MD` in [tswierszcz/ariadne](https://github.com/tswierszcz/ariadne). Its phases are RI0–RI6. This plan uses TM0–TM6.

Proposed implementation language is Go, consistent with the repository's initial tooling and the Ariadne ecosystem. Start with a CLI, JSON files, subprocess adapters, and a replaceable LLM HTTP adapter whose first live integration is OpenRouter (`https://openrouter.ai/api/v1`, credential via `OPENROUTER_API_KEY`). Recon, Hunt and Validate select explicit model identifiers independently. Tool versions and the tested execution environment are pinned in each run. Additional infrastructure follows measured needs from the pilot.

## 3. Inputs and run identity

A versioned project manifest contains the following fields.

| Group | Required content |
|---|---|
| Target | Repository URL, immutable revision, library coordinates, module and source roots |
| Build | Execution image or environment identity, JDK, build command, resolved dependencies and artifact paths |
| Threat model | Attacker-controlled values, trusted configuration, API usage assumptions, expected security boundaries |
| Scenarios | Root mode, API exclusions, framework configuration, target Java and classpath/JPMS scenario |
| Research scope | Selected property families/CWEs, package scope and prioritized API areas |
| Budgets | Wall time, memory, LLM requests/tokens/cost and experiment limits |
| Providers | Ariadne binary identity, LLM endpoint/model identity, optional CodeQL and Jazzer identities |

Secrets are referenced through the execution environment and excluded from saved manifests and model context. The manifest records the presence and purpose of a required secret without its value. Build dependencies and tool downloads happen in a preparation stage whose inputs and results are recorded.

`run_id` identifies an execution. Artifact hashes, source revision, configuration and analysis identifiers determine whether work can be reused. A retry receives an attempt identifier and preserves the preceding attempt's evidence. State is committed atomically after each stage.

The planned input extension accepts a supplied binary, pinned source and optional CVE package (identifier alone, references, corrective commit/patch or reproducer). Goals are `discovery`, `confirm_cve` and `confirm_and_find_variants`, with separate confirmation, variant and broader-discovery budgets. Binary/source correspondence, cached evidence provenance and manifest migration are specified in the [harness plan](docs/RESEARCH_HARNESS_IMPLEMENTATION_PLAN.md#research-inputs-and-cve-guided-investigation). These fields are not accepted by the current strict project schema.

## 4. Results and evidence model

Use a versioned JSON ledger and a Markdown report generated from that ledger. Each candidate has a stable `hypothesis_id`, revision history and evidence references.

| Record | Content |
|---|---|
| Property | The expected invariant, its documented or inferred basis, scope and assumptions |
| Hypothesis | Code locations, API entries, attacker-controlled input, suspected mechanism, preconditions, proposed experiment |
| Static assessment | Ariadne request/response, target resolution, paths, edge evidence, model gaps, optional CodeQL data-flow result |
| Experiment | Harness hash, input hash, commands, runtime/configuration, exit result, resource observations, coverage and assertions |
| Review | Supporting and contradicting evidence, applicability, root cause, impact and reasons for the conclusion |
| Novelty assessment | Known/advisory match, no match found, or undetermined, with sources and lookup date |

Keep these assessment axes independent.

- Defect assessment uses `candidate`, `supported`, `refuted`, `undetermined`.
- Reachability retains the original Ariadne target-resolution, path-search and model-completeness axes.
- Security-effect reproduction uses `not_run`, `observed`, `not_observed`, `inconclusive`.
- Stage execution uses `pending`, `running`, `completed`, `failed`, `budget_exhausted`, with a reason and attempt history.

An execution failure remains attached to the candidate. A crash or method entry needs an evaluated security assertion before the report claims an observed security effect. Conditions configured by the harness are listed explicitly. A known-issue lookup with no match leaves novelty unestablished.

The run summary lists source/build identity, analyzed API areas, property families, hypotheses by outcome, gaps, skipped work, coverage, resource cost and reproduction instructions. A zero-finding report includes the scope and unresolved work.

The planned final export contains `report.md`, versioned `report.json` and a hash-linked evidence/reproducer tree. It covers known-CVE applicability, variant relationships, independent assessment axes, controls/replay, coverage limits and budget reconciliation; see the [final report contract](docs/RESEARCH_HARNESS_IMPLEMENTATION_PLAN.md#final-report-contract). Reports regenerate from saved state without paid LLM calls.

## 5. Discovering hypotheses from an empty input

Discovery is driven by a property catalogue maintained in this repository. Each catalogue entry specifies a property family, candidate API operations, relevant context, counterexamples and suggested observations.

For the first property, file confinement, context includes public extraction methods, path transformations, output-directory checks, file creation calls, documented overwrite/link behavior and existing tests. Sources of candidates include the following patterns.

1. Data is validated and then transformed before use.
2. The checked object differs from the object eventually used.
3. Similar API methods apply different checks.
4. Failure or fallback paths change an enforcement decision.
5. A library crosses a resource, filesystem, network or trust boundary.
6. Existing tests leave a relevant boundary case unexplored.

Construct context from the pinned source tree, documentation, tests and Ariadne entries/calls. Link every excerpt to source hash and location. JVM method references retain descriptor, instance and bytecode identity when available. Optional debug metadata is handled explicitly. LLM-requested context expansion is bounded and logged.

The LLM returns structured candidate records with citations, an invariant, controlled input, a suspected mechanism, a falsifiable prediction, existing protections and arguments against the hypothesis. Validate cited locations and method selectors against the actual input. Malformed records receive bounded corrective retries and remain diagnosable on failure.

Deduplicate by root-cause location and mechanism while preserving different scenarios. Prioritize candidates by supported input control, relevant API exposure, specificity of the defect and experimental feasibility. A model gap changes evidence quality and remains visible during prioritization. It cannot establish that a path is impossible.

An optional second review asks what evidence would refute each candidate. Experiments then provide new context for revision of the hypothesis. The model's proposed invariant retains its origin as an inference until checked against the library's contract.

## 6. Ariadne integration contract

Ariadne owns the authoritative bundle, query and response schemas. Tekmerion pins a compatible schema version, binary identity and contract-fixture revision. Shared schema fixtures are consumed at a pinned revision, with recorded hashes, by the Tekmerion adapter tests.

| Operation | Tekmerion use |
|---|---|
| `research index` | Build one graph bundle per artifact/configuration/root scenario |
| `entries`, `methods`, `calls` | Discover API and operations before generating hypotheses |
| `callers`, `callees` | Expand bounded source context |
| `reachability` | Evaluate candidate methods in batches, including methods in the library itself |
| Later `trace-config` / `correlate` | Bind observations to candidate methods and analyzed class identities |

The adapter preserves raw requests and responses and validates `analysis_id`, schemas, target identity and truncation. A missing target, a shadowed copy or an incomplete search produces the corresponding evidence state. Root selections follow the indexed graph's restrictions. CodeQL source-level results and Ariadne bytecode-level results retain their separate evidence bases and matching assumptions.

Ariadne is the initial static evidence backend required by the real JVM pilot. Its adapter supplies reusable, independently inspectable graph facts. Incomplete static evidence leaves an explicit gap; experiment assertions and final vulnerability decisions belong to Tekmerion.

During RI0 development, a fixture adapter may implement the agreed contract. Its responses explicitly identify fixture provenance. The real pilot requires the actual Ariadne CLI. Contract changes receive a migration example and consumer tests before updating the pinned dependency.

## 7. Execution and verification

Builds and generated harnesses run in a controlled worker environment with an immutable source checkout, explicit mounts, a disposable output directory and enforced resource limits. Network availability is declared per stage. Local files, loopback services and marker values provide reproducible observations for the initial property tests. Tool credentials and unrelated host files stay outside the worker inputs.

The initial harness enters through public API with documented configuration. Record any API overrides, provider objects, feature flags or unusual caller behavior. Instrumentation can record method execution, while an independent assertion checks the property. Tests include a normal input, the candidate input and a control variant.

JUnit provides deterministic reproduction. Jazzer campaigns follow a working harness and retain corpus, seeds, coverage, timeout/OOM classification and reduced failures. A resource-exhaustion candidate requires repeated, bounded measurements that distinguish normal rejection, worker limits and input-dependent growth.

For a supported candidate, minimize the input and harness while preserving the observation. Replay in a fresh worker and preserve contradicting results. Where a scoped corrective patch is available, run the same test on original and corrected code. Both may reach the same target method while their property assertions differ.

## 8. Implementation increments

| Phase | Deliverable | Dependency | Acceptance |
|---|---|---|---|
| TM0 | Schemas, CLI skeleton, state ledger, Ariadne fixture adapter | Ariadne RI0 | Validate examples and persist a complete fixture-backed run |
| TM1 | Build preparation, manifest, source index and real bundle adapter | Ariadne RI1–RI2 for real indexing | Rebuild pinned fixture and bind source/artifact/bundle hashes |
| TM2 | Property catalogue and LLM discovery | TM1, RI4 discovery operations as needed | Produce evidence-linked hypotheses from an empty candidate list |
| TM3 | Static triage, batched reachability and optional CodeQL adapter | TM2, Ariadne RI3 and needed RI4 | Preserve positive, negative, missing-target and incomplete evidence states |
| TM4 | Worker runner, JUnit harness generation, optional Jazzer adapter | TM3 | Reproduce target execution and evaluate an independent property assertion |
| TM5 | Refutation review, reduction, fresh replay and report | TM4, Ariadne RI5 integration | Explain supported, refuted and unresolved cases with artifacts |
| TM6 | Real-library pilot and quality/cost measurement | TM5, completed Ariadne RI4–RI5 | Reproduce the pilot from the manifest and account for all attempted hypotheses |

### TM0 — first implementation PR

- Establish the manifest, hypothesis, experiment and ledger JSON schemas.
- Add a minimal CLI for validating a manifest and starting/resuming a run.
- Implement the fixture Ariadne adapter and validate the RI0 contract examples.
- Store raw evidence, hashes, stage outcomes and attempt records.
- Add a report for the fixture run with explicit fixture provenance.
- Verify a restart, malformed data and an exhausted budget with useful failures.
- Add preflight budget estimates, bounded calibration, atomic request reservations and uncertain-charge reconciliation as specified in RH-T1a–RH-T1b. Preserve validation/reporting reserves across resume.

### TM1 — reproducible target preparation

- Accept an existing source checkout at a verified revision and a recorded build recipe.
- Build the proposed control library and a property-preserving control variant.
- Resolve and record the actual classpath used by the harness.
- Build a source index and map candidate method references to source where possible.
- Integrate real `research index` when RI1–RI2 are available.

### TM2 — discovery

- Implement the file-confinement property entry and context selection.
- Implement the OpenRouter adapter behind a replaceable interface, with per-role models, structured output validation, usage/cost recording and bounded retries.
- Supply a deterministic replay provider for tests and optional paid/live execution for explicit research runs.
- Verify candidate citations, selectors and assumptions, then deduplicate and prioritize.
- Assess the empty-hypothesis starting case on the control library.

### TM3 — static triage

- Query exact method targets in batches on a reused bundle.
- Preserve method ownership, path characters, caller-supplied dispatch and gaps.
- Add a CodeQL adapter for the first property when source data flow is needed. Record query/model/database identities and assumptions.
- Persist hypothesis revisions after new evidence, including reasons for rejection or uncertainty.

### TM4–TM5 — controlled experiments

- Execute a simple checked-in harness before enabling generated harnesses.
- Generate a normal API client, compile it, run it and collect independently defined assertions.
- Classify compile failures, target exceptions, worker errors and budget exhaustion separately.
- Reduce and replay candidate inputs. Review against the public contract and supplied configuration.
- Add Jazzer after deterministic JUnit reproduction works.
- Render the evidence ledger into a report and a minimal reproduction package.

### TM6 — pilot and evaluation

- Select one buildable real library and a property matching its purpose.
- Run discovery from an empty hypothesis list under an explicit budget.
- Record every candidate and outcome, including unresolved cases and tool failures.
- Replay supported cases in a fresh worker and review the required attacker control.
- Report cost, relevant coverage, time to reproduction and reasons for rejected findings.

## 9. Evaluation and tests

The control set includes a vulnerable fixture, a property-preserving variant, an unreachable sensitive helper, a missing/ambiguous method, a model gap and an intentionally unsafe documented API. The harness must distinguish a broken invariant from documented caller authority.

Contract tests cover Ariadne schema versions, hashes, pagination, truncation and error semantics. Workflow tests cover fresh starts, retries, interruption, resume, concurrent writes, malformed model output and budget accounting. A reused graph must match the source, artifacts and scenario of its experiment.

Measure discovery and reproduction separately. Report hypotheses proposed, citation-valid candidates, rejected/unresolved hypotheses, observed effects, fresh replays, examined API areas, relevant coverage and wall-time/LLM cost. A regression set should contain held-out cases with original/corrected versions and explicit expected properties. Known historical cases measure the workflow's behavior. Novelty of live findings has its own assessment.

## 10. Cross-repository milestones

| Milestone | Ariadne | Tekmerion | Reviewable result |
|---|---|---|---|
| M0 | RI0 | TM0 | Agreed schema fixtures and evidence semantics |
| M1 | RI1–RI2 | TM1 | Reproducible build and advisory-independent graph bundle |
| M2 | RI3, required RI4 | TM2–TM3 | Generated hypotheses with static evidence |
| M3 | RI5 | TM4–TM5 | Public-API experiment and property-preserving control |
| M4 | RI4–RI5 completed | TM6 | Real-library pilot with complete evidence and cost ledger |
| M5 | RI6 | Follow-up to TM4–TM5 | Runtime observations correlated with the candidate targets |

Both repositories record their own phase status and link the counterpart PR/commit when an integration milestone is met. Initial implementation starts with RI0 and TM0, then RI1 and TM1. Discovery and execution work can use contract fixtures while the real graph interface is implemented.

## 11. First-release acceptance

A user supplies a pinned library, build recipe, threat model and budget with zero hypotheses. Tekmerion prepares the target, discovers evidence-linked candidates, evaluates them through the real Ariadne interface and runs a controlled API-level experiment. The final ledger and report account for every candidate and tool failure, distinguish static reachability from the observed property result, and include a minimal fresh-worker reproduction for supported findings.

The first release includes one real-library pilot and the control suite. Broader CWE catalogues, multi-library campaigns and additional worker/provider integrations follow measured pilot needs. Optional runtime correlation follows Ariadne RI6.
