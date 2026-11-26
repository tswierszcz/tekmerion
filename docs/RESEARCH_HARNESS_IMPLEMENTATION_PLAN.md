# Recon, Hunt and Validate implementation plan

Date 2026-11-25. Status PLANNED. This plan refines TM0–TM6 using the current implementation and selected ideas from Cloudflare's security-audit workflow.

## 1. Baseline and references

The reviewed Tekmerion implementation is `34f08b4`, merged by `76729ac`. It has real/fixture Ariadne adapters, controlled target preparation, manifests and source mapping. The run ledger, hypothesis generation, independent verification and final research reporting remain implementation work.

References are [Build your own vulnerability harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness/) and [security-audit-skill pinned to c1c8a8c1471069fb0e188eeaff69b8e8db6564a8](https://github.com/cloudflare/security-audit-skill/tree/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8). The companion producer plan is `RECOMMENDATION/RESEARCH_HARNESS_IMPLEMENTATION_PLAN.MD` in [Ariadne](https://github.com/tswierszcz/ariadne).

Adapt prompts and evidence principles through a reviewed, versioned change. Keep the upstream revision and the source file/block for every adapted instruction. Substantial copied material retains the upstream MIT license and copyright notice in the repository. Changes to those instructions receive a local prompt revision and evaluation record.

## 2. First deliverable

One pinned JVM library, one file-confinement property, a bounded research budget and zero supplied hypotheses enter the process. Recon discovers the relevant interfaces and assumptions. Hunt produces falsifiable candidates. An independent Validator reviews source and experiments. Every candidate, failure and uncovered area appears in persistent state and the final report.

The local control set contains a broken implementation, a property-preserving variant, an unreachable helper, a model gap and a deliberately powerful documented API. The same write method can be reachable in both broken and preserving variants.

### Research inputs and CVE-guided investigation

Support a supplied JVM binary plus a source repository pinned to an immutable revision, with an optional CVE evidence package and explicit budget. The two research goals are confirming a known vulnerability in the supplied artifact/configuration and discovering previously unknown defects, including variants of known mechanisms. Keep these goals and their evidence separate.

| Input | Required handling |
|---|---|
| Binary | Local artifact, SHA-256, coordinates/version when known, runtime and dependency/classpath scenario |
| Source | Repository URL or local checkout, resolved commit, relevant source roots and optional reproducible build recipe |
| CVE package | Optional identifier, advisory/technical references, fix commit or patch, reproducer/test and user notes |
| Scope | Threat model, intended API usage/configuration, property families and permitted source-context disclosure |
| Budget | Overall money/token/request/time limits and allocations for confirmation, variant hunting and broader discovery |

A CVE identifier alone is a valid starting hint. Fetch and snapshot its available record and references in a bounded preparation step, retaining original URLs, retrieval time, content hashes and extraction provenance. User-supplied local documents and cached packages support offline use. An unavailable reference is a recorded gap. Advisory statements and supplied reproducers remain claims to verify. Process downloaded code in the controlled worker used for experiments.

Prepare one reusable, versioned evidence package containing affected-version claims, prerequisites, suspected mechanism, cited locations and corrective changes. Link extracted facts to their source and distinguish them from model inference. Reuse its hash across tasks to avoid repeated retrieval and interpretation. Refreshes produce new revisions rather than silently changing the input of a resumed run.

Record the relationship between the supplied binary and source as declared, build-verified, unavailable or conflicting, with supporting checks. Match exact class/artifact identities where possible. A version string or source link alone cannot establish correspondence. Keep the supplied binary as the authoritative target of binary-level confirmation; rebuilding the source produces a separate artifact and experiment. Source-only discoveries require subsequent verification against the supplied binary before being attributed to it. Missing source or build/configuration facts allow bounded initial analysis but must limit the resulting claims.

Offer planned `discovery`, `confirm_cve` and `confirm_and_find_variants` goals. Discovery accepts zero hypotheses and no CVE. CVE confirmation evaluates applicability, public-API reachability and observed security effect independently. Variant hunting searches alternate API paths, similar implementations and incomplete fixes, giving each distinct root cause its own candidate identity. A combined run proceeds through separately budgeted confirmation, variant hunting and optional broader discovery; confirmation failure does not silently spend the discovery allocation or establish absence of variants. Broader work requires an explicit goal/allocation.

Supplying a CVE can reduce hypothesis-discovery work; a technical advisory, patch and reproducer can narrow it further. Reproduction and independent validation remain required. Estimate each research stage separately, recording supplied evidence and acquisition cost. Measure savings with paired CVE-guided and unguided runs on held-out known cases, with the same artifacts, settings and budget accounting. Report quality and work completed alongside cost; do not promise a fixed saving or treat CVE-guided historical evaluation as unknown-vulnerability discovery.

The following YAML is a conceptual input sketch, not an accepted current CLI manifest. The implemented `tekmerion-project-1` manifest rejects unknown fields. Introduce a versioned schema and migration example before accepting supplied binaries or CVE fields; canonical JSON remains the initial machine interchange format. YAML support is optional follow-up work.

```yaml
target:
  binary: ./library.jar
  source:
    repository: https://github.com/example/library
    revision: "<immutable commit>"
research:
  goal: confirm_and_find_variants
  cve:
    id: CVE-YYYY-NNNNN
    references:
      - https://example.org/security/advisory
    fix_commit: "<optional corrective commit>"
    patch_file: ./evidence/fix.patch
    reproducer: ./evidence/reproducer
    notes: "Optional configuration and prerequisites"
budget:
  max_llm_cost_usd: 10
```

All CVE package fields except the identifier may be omitted in an identifier-only investigation; the whole package is optional for discovery. Budget splits, tool settings and threat-model fields are omitted from this sketch, not from the planned full schema. Prices and model access follow RH-T1a–RH-T1b through OpenRouter.

Implementation allocation: RH-T1 persists input/package identity and per-stage budgets; RH-T2 acquires and grounds the evidence package; RH-T3 generates linked confirmation/variant candidates; RH-T4–RH-T5 reproduce and independently assess them; RH-T6 exports the results. Supplied-binary ingestion and correspondence checks extend TM1. Acceptance includes identifier-only and offline packages, missing references, conflicting version claims, binary/source mismatch, a matching known defect, a corrected control, a distinct variant and an inconclusive experiment. Migration must preserve existing manifests.

### Ariadne's role in the JVM workflow

Ariadne is the initial static evidence backend for JVM API discovery, exact class/method identity, call paths, edge provenance and model gaps. Reuse its pinned graph bundle across tasks and record queries and bounded context requests. These facts help prioritize hypotheses and relate experiments to the analyzed code. Measure the benefit through query cost, context volume, candidate quality and time to reproduction.

The first real JVM pilot requires actual Ariadne integration. Keep the adapter boundary so a future backend can supply equivalent evidence without coupling orchestration to Ariadne internals. An unavailable target, incomplete graph or unresolved dispatch remains an explicit static-assessment gap. It does not refute a defect. A controlled reproduction may establish an effect while the static axis remains unresolved. Ariadne paths alone cannot establish a vulnerability or novelty. Tekmerion owns threat assumptions, experiment assertions, independent review and final findings.

## 3. Implementation increments

| Phase | Existing plan | Deliverable | Acceptance |
|---|---|---|---|
| RH-T0 | TM0, TM3 | Strict adapter acceptance and evidence preservation | Invalid schema, contradictory states and broken path proofs are rejected |
| RH-T1 | TM0 | Persistent state, OpenRouter access and budget control | Preflight estimates and crash/retry/resume preserve evidence, cost reservations and ownership |
| RH-T2 | TM2 | Recon and a property/coverage catalogue | Starting with zero hypotheses creates grounded research units |
| RH-T3 | TM2–TM3 | Bounded Hunt tasks and static triage | Every candidate cites source, attacker control, a property and a falsifiable prediction |
| RH-T4 | TM4 | Controlled experiments and artifact collection | A checked-in and then generated harness can establish a bounded property result |
| RH-T5 | TM5 | Independent adversarial verification | A separate task can confirm, refute or retain a precise blocker |
| RH-T6 | TM5–TM6 | Deterministic reports and a real-library pilot | All outcomes, gaps, reproductions and costs are accounted for |
| RH-T7 | Follow-up | Measured scaling and optional integrations | Each addition resolves an observed pilot bottleneck |

## 4. RH-T0 — close the adapter acceptance gap first

Implementation progress (2026-11-25): the first RH-T0 increment is implemented in Tekmerion. `Check` validates the complete pinned response shape before projecting fields, rejects duplicate JSON members, checks search/model/path/limit consistency and preserves nullable entry counts. `CLI` and `Fixture` additionally verify bundle identity/dataset hashes, frozen copied records, provenance, requested method identity and indexed root membership. Attempts record `validation_scope` (`response` or `bundle`); invalid responses remain `unusable` with raw evidence and diagnostics.

The implementation embeds the pinned schema and uses a dependency-free validator limited to its response vocabulary, rejecting unsupported validation keywords. It introduces no general-purpose JSON Schema API or new module dependencies. Regression tests consume every response case in `cases.json` and add schema corruption, duplicate members, changed evidence/origin, missing proofs, limits, nullable counts and post-witness budget exhaustion. `ARIADNE_SRC=/opt/src/ariadne go test ./...` passes against the existing Ariadne binary `v0.0.0-20261124120556-07806cc59e68`, covering full and reachable bundles and target preparation. Ariadne source was not modified.

Continuation (2026-11-25): graph-wide validation now checks every bundle record against the pinned `Record` schema, selected class uniqueness/references, method instance/class-hash ownership, access flags, canonical methods and receiver specializations, synthetic/external node rules, source ranges and edge/root/call/gap references. Specializations must retain their canonical method identity. JSONL rows reject duplicate members, invalid UTF-8 and trailing documents. Response checks also validate omitted-entry flags and global gap counts against the bundle. Integer validation uses exact arithmetic to reject fractions that floating-point conversion would round to integers.

Regression tests include schema-valid contradictory graphs, valid shadowed/external/synthetic/specialized nodes, and hash-valid bundles with invalid hidden records. These attempts become `unusable` and retain response hashes and diagnostics. Acceptance run: `ARIADNE_SRC=/opt/src/ariadne go test ./...`, `go vet ./...`, and `node contracts/ariadne/v1/validate.mjs` all pass, including real full/reachable bundles, target preparation and all 28 positive/negative contract conformance cases.

The previously listed Tekmerion graph checks are implemented. Joint H0 acceptance against the separately developed Ariadne RH-A0 changes remains pending; the current pin and producer source are unchanged. RH-T1 persistence progress is recorded below; budget control and RH-T2–RH-T6 remain implementation work.

The baseline progress review found that `internal/ariadne.Check` accepted the existing contract cases `invalid-missing-with-path.json` and `invalid-path-shape.json`. Correlation checks alone leave contradictory evidence consumable.

1. Validate the full pinned response schema before decoding a convenient projection. Reject duplicate members, unknown/missing fields and unsupported values. Choose a Go schema implementation only after checking support for the pinned schema features and dependency policy.
2. Enforce cross-field invariants for target resolution, path states, complete/incomplete searches, model states, limits, root membership and counts.
3. Verify path continuity, node/edge references, target endpoints, selected instances and source identities. Validate records against the bundle when a real bundle is available. Record the validation scope for fixture playback and partial responses.
4. Preserve nullable values, especially unknown `total_entry_count`. Avoid converting unknown counts into zero in the public adapter result.
5. Preserve all raw bytes, source provenance, validation errors and invocation outcomes. An invalid response produces an unusable attempt and contributes no accepted research evidence.
6. Turn all applicable negative contract fixtures into adapter regression tests. Add missing evidence, modified edge, wrong origin, truncated path and post-witness budget cases.

Acceptance requires the contract conformance suite, adapter unit tests and actual Ariadne integration for full/reachable bundles. Coordinate with producer RH-A0.

## 5. RH-T1 — persistence before parallel execution

Use SQLite for the initial durable store, with an external artifact directory for immutable, hash-addressed evidence. Select and pin a Go driver after checking its build/toolchain requirements. JSON remains the interchange and report-export format.

Implementation progress (2026-11-25): the first RH-T1 persistence increment is implemented in `internal/state` and `internal/audit`. The driver is pinned to `github.com/mattn/go-sqlite3 v1.14.32` in `go.mod`/`go.sum`; its upstream Go 1.19 module minimum fits this repository's Go 1.24 minimum. CGO and a C compiler are required; both are present in the tested environment. Driver requirements and SQLite connection options were checked against the [pinned upstream documentation](https://github.com/mattn/go-sqlite3/blob/v1.14.32/README.md).

`tekmerion-state-1` uses SQLite WAL, FULL synchronization, foreign keys, a busy timeout and immediate write transactions. One state directory owns one run. Run and task input identities are immutable. Attempt starts and terminal results are separate append-only records, enforced by SQL triggers; task status and the terminal run projection change in the same transaction as result delivery. Lease tokens fence old workers; expired work appends an interrupted result and a new attempt identity. Exact duplicate delivery is idempotent and conflicting delivery fails. Leases can be renewed only by the current unexpired owner.

Artifacts are published using a complete, synced temporary file and an atomic no-overwrite link before database registration; reads verify regular-file type, size and hash. An interrupted publication can leave an unreferenced artifact, never a committed partial file. The state directory is controller-owned; target-worker output promotion remains RH-T4 work. Initialization refuses an existing directory and unsupported state versions are rejected. Run creation commits the full initial queue atomically; an interruption before that first commit may leave an incomplete initialization directory, which is diagnosed rather than silently reused.

Implemented CLI scope is explicit fixture replay: `audit -fixture -state NEW_DIR [-contract DIR]`, `resume -state DIR`, `status -state DIR`, and `report -state DIR [-format markdown|json]`. The fixture run saves its contract pin, complete request bytes, original responses and validation outcomes. It has nine deterministic static tasks and makes zero model calls. Resume checks the saved pin and never reruns completed tasks. Fixture leases last one minute. Status does not claim tasks; report regeneration verifies evidence, works without the original contract directory and is deterministic for an unchanged snapshot. These are fixture ledger exports, not final RH-T6 research reports. See the README for commands and evidence layout.

Tests cover rollback of initial queue/result commits, restart with a live/expired lease, two independent SQLite clients claiming one task, renewal, interrupted retry, stale-owner rejection, duplicate/conflicting results, history immutability, changed artifact/pin, unsupported schemas and repeated report generation. The CLI smoke run completes nine tasks with nine attempts and 28 saved artifacts; a second resume leaves its JSON report byte-identical. Acceptance passes `ARIADNE_SRC=/opt/src/ariadne go test ./...`, `go test -race ./internal/state ./internal/audit`, `go vet ./...` and the 28-case contract conformance helper.

Budget continuation (2026-11-25): `tekmerion-state-2` adds an atomic migration from version 1, immutable `tekmerion-budget-1` configuration, paid-task fencing, request reservations, authoritative charge receipts, uncertain-charge observations and persistent discrepancy halts. `ClaimRequest` reserves the first bounded request in the same transaction as the task claim; rejection rolls back the attempt and lease. `ReserveRequest` handles subsequent bounded requests. Money uses fixed-point billionths of USD with decimal-string JSON, exact configuration parsing and conservative provider-charge rounding. Request, token and wall-time caps apply independently.

Admission requires hash-verified prompt/request evidence and an unexpired saved `tekmerion-request-price-bound-1` for the exact model/provider. This increment supports explicitly configured conservative ceilings; an unknown/stale route or a cheaper substituted bound is rejected. It does not infer catalogue rates or cache savings. Protected Validate/Report allocations transfer disjointly into active reservations; unused protected credit returns to its stage after a known settlement. Lease expiry and task completion do not release money. Timeouts/missing costs retain the ceiling, retries need distinct identities, and missing token usage retains the token ceiling.

Known-zero costs, late receipts, duplicate/conflicting delivery and unique namespaced provider generation identities have explicit settlement behavior. Any observed charge/token overrun remains saved and halts new paid admission, while local reporting stays available. Snapshot/Markdown/JSON output includes costs, unresolved reservations, protection, remaining funds, tokens/requests, deadline and discrepancy/observation history. Admission failures leave tasks pending for a future scheduler to classify as deferred; this increment does not implement the full research scheduler's terminal/stop-reason policy.

The CLI accepts optional `audit -fixture -budget FILE` with a documented example at `testdata/budget/fixture.json`. Static fixture tasks remain local and spend zero. The smoke run preserves the USD 10 limit, USD 3 protection and USD 7 available across resume; its reports remain byte-identical. Unit/race tests cover competing workers for the last affordable request, crash/lease expiry with an unsettled charge, uncertain retry, known zero versus missing cost, duplicate receipts/generations, protected-fund transfers/refunds, underpriced/unknown/expired routes, independent caps, overrun halts, prompt corruption, immutable budgets and version-1 history migration.

Estimator/gateway continuation (2026-11-25): `internal/pricing` implements offline `estimate` from `tekmerion-estimate-plan-1` and `tekmerion-pricing-1`. Plans record target/scope, assumptions, separate role routes, low/base/high workloads and finite request/input/output caps including retries. Pricing records source, retrieval/validity times, currency and exact per-token/request rates. Exact rational arithmetic supports sub-nanodollar rates; totals and admission ceilings round upward. Cache savings stay separate from the cache-miss bound. An optional normalized total cache-write input rate can raise the input ceiling; it replaces the input rate for that bound rather than being added to it. Stale/unknown/incomplete pricing produces gaps and unavailable monetary bounds unless a fresh explicit manual ceiling is recorded. Full workload affordability includes unused protected stage allocations and independent request/token caps; local compute, taxes and credit fees are excluded.

`estimate -state DIR` saves plan/snapshot/report artifacts and append-only forecast history. The plan target must equal the run manifest hash; a conflicting immutable budget is rejected. `status` exposes forecast references and `report` compares a matching forecast with settled/outstanding costs by stage/model/provider. Same inputs and supplied estimate timestamp regenerate the same report; live admission independently uses the actual clock. Synthetic example values are USD 0.0067 / 0.0213 / 0.0478 with a USD 0.086 finite ceiling (15 requests, 70,000 tokens).

`internal/llm` defines the replaceable role/request/result interface. `internal/openrouter` implements one bounded, non-streaming request with explicit model/provider, capped output, `only` routing, disabled fallback and required parameter support. Credentials come from the environment at CLI construction and remain out of saved inputs/headers/logs. Echoed credentials are redacted in evidence. The adapter preserves raw usage/response metadata, normalizes prompt/completion/total tokens without adding cache/reasoning details twice, separates reported cost from upstream breakdowns, and preserves missing versus zero cost. It handles redirects without forwarding auth, HTTP failures, HTTP-200 error envelopes, malformed/duplicate output, missing identities/choices, route changes, truncation, timeout and response byte limits. Stage-specific validators plug into `internal/gateway` after local JSON-object checking.

`tekmerion-state-3` migrates version 1/2 state and adds append-only one-shot dispatch markers and forecast history. `internal/gateway` commits a dispatch marker before HTTP, performs no implicit replay of an uncertain request, and uses new reservations for bounded retries. Saved attempt counts, run/request deadlines, price validity and budget limits survive resume. Known receipts settle even when output validation fails; unknown charges remain reserved. Unknown returned routes or token-dimension overruns halt paid admission. `infer -request FILE -prices FILE -budget FILE -state NEW_DIR` explicitly runs one bounded model task; `resume`, `status` and `report` support these model ledgers as well as fixtures. The model ledger is not a vulnerability decision or a full research report.

Acceptance: the full `ARIADNE_SRC=/opt/src/ariadne go test -race ./...` suite passes, including real Ariadne full/reachable bundles, target preparation, exact offline estimates, local HTTP adapter/controller cases, one-shot restart fencing and immutable forecast history. CLI smoke tests cover deterministic offline estimates, matching-target forecast persistence, budget preservation and identical reports after repeated estimate/resume. All provider responses are synthetic/local; no paid OpenRouter call was made. API fields were checked against the official overview, Chat Completions, provider-routing, usage-accounting and error documentation listed below.

RH-T1 remains partial: automatic catalogue acquisition/normalization, bounded live calibration, priced multi-route fallback, prepared-target/source/build ingestion into model runs, and complete coverage/candidate/assessment/blocker records remain implementation work. The next research increment is RH-T2 grounded Recon on prepared source/API evidence, with a versioned output schema and no supplied hypotheses.


| Entity | Minimum content |
|---|---|
| Run | Pinned project/build, analysis ids, scope, prompt/catalogue versions, budget and terminal status |
| Task | Stage, input evidence hashes, assigned role, model/configuration, status, lease and retry history |
| Attempt | Command/provider request, timestamps, exit/outcome, costs, diagnostics and evidence references |
| Coverage unit | Stable identity, surface, boundary, subsystem, property class, scope and attempt links |
| Candidate | Root-cause fingerprint, hypothesis revisions, control assumptions and linked units |
| Assessment | Independent defect, static reachability/model, reproduction and novelty axes |
| Blocker | Exact missing fact/tool/environment, affected task and concrete resumption condition |
| Artifact | Content hash, producing attempt, media type, source/build identity and retention metadata |

Store state changes transactionally. Use an append-only attempt history, exclusive task claims and expiring leases. Resume an interrupted task without overwriting completed attempts or double-finalizing a candidate. A lost provider response records an uncertain outcome and conservative cost reservation before a retry. Provider idempotency support is used where available.

Reserve validation and reporting budget before assigning Hunt work. Account for tokens, monetary cost, wall time and invocation limits. The run can terminate as completed-with-declared-coverage, incomplete, failed or cancelled. Resource exhaustion keeps existing evidence and unattempted work visible.

Proposed CLI operations are `audit`, `resume`, `status` and `report`, alongside existing `prepare`/`locate`. Their exact flags are finalized with the state schema. A deterministic replay provider supports CI without paid model calls.

Acceptance covers interruption after each stage transition, a stale task lease, two workers claiming one task, duplicate result delivery, a provider error inside a nominally successful HTTP response, budget exhaustion and report regeneration from saved state.

### RH-T1a — initial LLM gateway: OpenRouter

The initial live LLM integration uses [OpenRouter](https://openrouter.ai). Implement a Go HTTP adapter behind a replaceable internal interface, initially calling `https://openrouter.ai/api/v1/chat/completions`. Read the credential from `OPENROUTER_API_KEY`; exclude credentials and authorization headers from manifests, logs and evidence exports. CI uses local HTTP fixtures and deterministic replay.

Configure explicit OpenRouter model identifiers independently for Recon, Hunt and Validate. Record requested and returned model identities, available upstream-provider metadata, request/generation identifiers, prompt revision, generation parameters and routing policy for each attempt. Model prices and names are configuration data. Provider/model fallbacks must be explicitly allowed, included in the price bounds and recorded when observed. Reject an unsupported required capability instead of silently dropping it. Fresh verification context remains required when roles use the same model.

Use bounded requests with explicit output limits, deadlines and retry counts. Validate structured output locally even when provider-side structured output is enabled. Handle HTTP failures, rate limits, malformed output and error payloads returned with HTTP 200. An uncertain delivery or timeout is an unsettled attempt; a retry receives a separate reservation. Do not assume the gateway guarantees idempotency or cancels upstream billing when the local connection closes.

Preserve the raw usage object and normalize prompt/completion, cache and reasoning details when present. Record provider-reported `usage.cost` separately from estimates and any upstream cost breakdown. Zero is a valid reported cost; missing cost is unknown. Avoid adding token subcategories or cost breakdowns to totals that already include them. Reconcile duplicate responses once using the recorded request/generation identity.

OpenRouter communication belongs to the Tekmerion controller. Target experiment workers retain their declared network policy. Submit only the source excerpts and evidence permitted by the run's context policy. This research integration introduces no OpenRouter dependency into Ariadne's graph interface.

Implementation references: [API overview](https://openrouter.ai/docs/api_reference/overview), [usage accounting](https://openrouter.ai/docs/cookbook/administration/usage-accounting), [model catalogue and pricing](https://openrouter.ai/docs/api/api-reference/models/list-all-models-and-their-properties) and [error handling](https://openrouter.ai/docs/api_reference/errors-and-debugging). Verify the supported fields and capture representative responses when implementing the adapter.

### RH-T1b — estimation, calibration and spending limits

Add a proposed `estimate` CLI operation before paid research. Its input is the pinned project/scope, expected coverage units, per-role model/routing configuration, context/output limits, task/retry limits, experiment limits and a timestamped pricing snapshot. An offline estimate uses a supplied snapshot; refreshing catalogue metadata is separate from inference. Report missing inputs and pricing freshness explicitly.

Return a low/base/high forecast with task-count and token assumptions, a conservative admission bound for the configured finite workload where available, and a breakdown by Recon, Hunt, Validate and reporting. These are scenario estimates, not statistical confidence intervals. Candidate counts are unknown before Hunt, so expose their assumed rates and the effect of additional validation work. Keep local build/graph/experiment time and resource limits separate from LLM charges; attach a compute price only when the user supplies one. Distinguish inference spend from credit-purchase fees or taxes.

Store the pricing source, retrieval time, model/provider route, currency, token units and snapshot hash. Use exact decimal or fixed-point money arithmetic with conservative rounding. Cover applicable input/output/cache/reasoning and per-request charges without double counting. Forecast cache savings separately; admission must remain safe on a cache miss. When a billable dimension or allowed route has no reliable upper price bound, label the monetary bound unavailable and require a configured conservative bound before enabling strict monetary admission. A stale snapshot must be refreshed or explicitly accepted with a recorded conservative bound.

An optional bounded calibration runs Recon and a small Hunt sample, charges them to the same run budget, then revises the forecast from observed context sizes, output usage, retry rates and candidate yield. Save the original estimate and every revision. Calibration cannot silently increase the configured budget.

Reserve a configured amount for validation and reporting before admitting Hunt work. Atomically claim a task and reserve its next request's maximum priced cost, including the complete prompt, capped output and applicable charges. Bound tool loops and retries; each subsequent request needs its own reservation. Available money equals the run limit minus settled charges, outstanding request reservations and protected stage reserves. Keep protected stage reserves disjoint from active reservations when transferring funds to validation/reporting. Concurrency and restart must preserve this invariant.

On settlement, replace the reservation with the reported charge once. Keep missing or uncertain charges reserved until reconciled; releasing a task lease does not release its money. Record any unexpected charge above the bound, stop further paid admission and retain the discrepancy in the report. Local admission limits constrain requests under recorded price bounds; they cannot guarantee the final external bill when upstream pricing or billing differs. Token, request and wall-time caps apply independently. Exhaustion stops new paid work and preserves deterministic local report generation and deferred coverage.

`estimate` reports assumptions, expected range, priced bounds and stage allocation. `status` shows settled spend, active/unsettled reservations, protected reserves, available funds and the latest forecast. `report` compares estimates with actual usage and lists unresolved charges, retries, cache effects and deferred units. All CLI names and flags remain proposed until the state schema is implemented.

Acceptance uses synthetic prices and recorded OpenRouter-shaped responses: two workers competing for the last affordable request; crash/restart with a reservation; timeout followed by retry; duplicate settlement; missing versus zero cost; HTTP-200 error payload; cache miss; changed or unknown route pricing; and a budget too small for Recon plus protected reserves. No paid API calls are required for these checks.

## 6. RH-T2 — Recon and coverage from an empty hypothesis list

Implementation progress (2026-11-25): the initial RH-T2 path is implemented in `internal/recon`. `recon -work DIR -ariadne BIN -state NEW_DIR -offline` consumes a verified TM1 `api`-root preparation, performs bounded static discovery and creates a deterministic source/API baseline without model calls. `-replay FILE` validates a local response; `-model FILE -prices FILE -budget FILE` uses the existing bounded gateway with explicit source-context permission. Model configuration declares role-specific route/token/attempt/time limits; tests inject a local provider and make no paid calls.

`prepare.Verify` rechecks source, successful recipe steps, artifact/classpath, source-index and bundle identity. New `project_original` bytes fix the old embedded-JSON whitespace/hash mismatch; legacy preparations retain an explicit gap for their unavailable original file bytes. Context reads are bounded regular members under the prepared root, reject static symlinks, and are reverified after collection. `sourceindex.Parse` consumes already-verified bytes without reopening the index. Full selected source documents, source index, preparation, bundle metadata, raw query responses and invocation metadata are hash-addressed artifacts.

Context limits cover exact API surfaces, discovery pages, UTF-8 source ranges, common docs/tests and total bytes. API method discovery is filtered to the enumerated roots. Source excerpts include limited declaration/comment context; missing/conflicting mappings become blocked work. Graph coverage/fixed-point limits, unknown authority, absent documentation and deferred inputs remain gaps. Full graph datasets/bytecode stay in the prepared directory with their hashes; copied evidence does not claim a standalone RH-T6 export. The context identity binds source/API/scenario, selected content, declarations and prompt/catalogue while excluding invocation timing; replay against a different context fails.

The original `recon-1` prompt and `file-confinement-1` catalogue retain reviewed source-block/revision metadata for upstream Recon 1b/1c, deterministic coverage and resource/file handling. No upstream agent orchestration is executed and no substantial prompt text is copied. Typed `tekmerion-recon-result-1` validation enforces exact source/path/hash/range and method selectors, origin labels, unchanged declared assumptions, retained input gaps, bounded summary and complete accounting for supplied surfaces. Model-inferred claims remain inferences; a citation is not independent proof. Only initial planned/blocked/deferred/out-of-scope coverage is accepted; no checked coverage, hypotheses or accepted findings are produced.

`tekmerion-state-4` migrates earlier ledgers and adds immutable initial coverage batches/units. Canonical unit IDs hash lossless repository/surface/boundary/subsystem/property/lifecycle/scenario tuples; source/class/artifact identity remains separate. Collisions fail. Projection and attempt/task/run completion share one transaction; missing artifacts or conflicting delivery cannot partially commit. Recon completion before projection can resume entirely from saved evidence, without original preparation or another model request. Reports expose architecture, controls, assumptions, gaps, provenance and initial unit states.

Acceptance covers zero supplied hypotheses, actual Ariadne/control-source integration, bounded/deferred surfaces, source/index/binary/bundle tampering, unknown citations/selectors, authority inflation, changed context, pagination loops, symlink/path escapes, legacy input hashes, model corrective retries, interrupted projection and idempotent resume. Unit/race tests and real Ariadne acceptance use no paid model requests. Follow-up work is richer source/context expansion and cross-run coverage reconciliation, then RH-T3 hypotheses and static triage; the current baseline does not claim code-execution coverage or semantic vulnerability discovery.


Adapt the questions in upstream `RECONNAISSANCE.md` and the relevant parts of `ATTACK-CLASSES.md`. Begin with a bounded Recon task and expand only for a distinct source-grounded question. Agent counts follow the declared budget and target scope.

Inputs include source/documentation/test indexes from TM1, the declared threat model and deterministic Ariadne API/call discovery. Recon returns principals, normal caller authority, protected resources, lower-trust inputs, transformations, existing controls and candidate property families.

Assumptions retain origin as user-declared, model-inferred or experimentally checked. A model-inferred threat model cannot silently broaden the caller's capabilities or redefine documented library behavior. Contradictions become explicit questions or blockers.

Coverage is organized by entry surface × trust boundary × subsystem × property/attack class, with lifecycle where relevant. Use stable source/API identities rather than line numbers alone. Store human labels separately from canonical keys. Detect identity collisions. Actual method identities retain artifact/class hashes.

Suggested coverage states are planned, running, checked, candidate, blocked, deferred and out_of_scope. A checked unit stores examined paths, invariant, method of checking and observations. It describes completed work under assumptions. Prior rejected claims suppress only the unchanged claim. Source changes reopen relevant work. Preserve earlier attempts when reassigning a unit.

The first catalogue entry covers file confinement and points to the relevant upstream resource/file-handling material. Include intended path semantics, normalization, links, output creation and parallel API paths. Broader classes follow the real pilot's interfaces.

Acceptance begins with zero hypotheses and yields a bounded architecture summary, explicit assumptions and deterministic coverage units, including scope exclusions and unavailable facts.

## 7. RH-T3 — Hunt and static evidence

Implementation progress (2026-11-25): the first bounded Hunt increment is implemented in `internal/hunt`, with `hunt` CLI, explicit derived-run budgeting and saved parent provenance. Each selected planned unit receives a finite Hunt task followed by local static triage. Offline mode only defers semantic work; replay and optional gateway model mode validate the same versioned source-grounded output. Context is capped at 64 KiB, 16 exact-class methods and 80 lines per method. Complete target-method excerpts and unique exact anchors support conservative root-cause fingerprints; cross-class/context expansion remains a documented limitation.

Candidates preserve origin-tagged authority/conditions, citations, controls/counterarguments and falsifiable predictions/experiment proposals. Exact causes merge across entry paths while per-entry occurrences retain all claims and static evidence. Triage uses that entry's root subset, archives raw Ariadne invocation documents and retains full independent resolution/search/model/path/dispatch data. Unavailable or rejected graph evidence leaves candidates open with explicit static blockers and no accepted axes. No runtime reproduction, novelty lookup or independent defect confirmation occurs.

State schema 5 migrates prior ledgers and adds immutable candidate/occurrence batches and coverage events. Initial Recon rows remain unchanged. Per-unit publication and task completion are atomic; identical replay is idempotent and contradictory/source-mismatched delivery fails. Completed model output is revalidated on resume without another request. Earlier accepted units survive later budget exhaustion. Markdown and JSON expose saved history, with parent spend separately linked rather than charged again.

Acceptance implemented: source/selector/context/authority/anchor validation, exact dedup across API paths, atomic rollback, v4 migration, no-model offline deferral, bounded retries with zero-cost synthetic responses, interruption before triage, partial budget stop, actual Ariadne positive/negative paths, rejected graph attempts and missing-preparation blockers. All model responses are local synthetic fixtures. Full cross-class context requests, dedicated Hunt-level CHA/missing-method qualification, controlled experiments and independent verification remain follow-up work; this increment is not full H2–H4 acceptance.


Assign one focused unit or small related group per Hunt task. Its context contains a pinned source snapshot, relevant documentation, the unit's invariant, selected upstream/local instruction blocks and bounded Ariadne evidence. Expand context through logged requests rather than loading an entire repository into every prompt.

The structured candidate includes affected principal/resource, attacker-controlled input, API entry, suspected root cause, source citations, required conditions, existing controls, falsifiable prediction, proposed experiment and potential counterarguments. It uses a proposed assessment awaiting independent validation.

Deterministic code validates citations and exact method selectors, submits batched reachability queries, records findings/model gaps and resolves source conflicts. Static evidence retains its own axes. An uncertain graph or external fact can keep a candidate open with a precise blocker.

Use stable fingerprints derived from source root cause, boundary and mechanism, scoped to the repository. Retain multiple entry paths and affected scenarios under one cause. Deduplication begins with exact keys and small candidate groups reviewed as needed.

Provider/model/configuration and prompt revisions are recorded separately for discovery and verification. A distinct model is an optional experiment parameter. Fresh task context and independent evidence checking are required regardless of model choice.

Acceptance includes duplicate candidates, hallucinated citations, malformed structured output, provider errors, a missing method and a path dependent on CHA or caller-supplied dispatch.

## 8. RH-T4 — controlled experiments

Extend the current TM1 build environment into a worker with enforced write boundaries, sanitized environment, declared network policy and CPU/memory/process/disk/file-size/wall limits. Verify enforcement with small capability tests and record results. Dependency acquisition is a separately recorded preparation stage. A missing decisive execution capability produces a blocker.

Run a checked-in harness before generated harnesses. Research experiments invoke the original pinned library through its public API, in a declared configuration. Source hashes before/after the experiment detect accidental target changes. A proposed corrective patch is assessed in a separate copy with a recorded diff.

Define the security assertion independently of target invocation. Record a normal input, candidate input, property-preserving control and meaningful observed result. A parser exception, process failure or target method entry receives its actual outcome category.

Target-produced output is collected only after the worker and child processes terminate. Trusted host code promotes explicitly selected regular files with path confinement, no-follow access, bounded sizes and content hashes into immutable evidence storage. Test symlinks, hard links, special files and changing files against the chosen platform mechanism.

Add Jazzer after deterministic harness execution works. Record seeds/corpus, relevant coverage and resource outcomes. Reduce an observed case while preserving the assertion. A resource-exhaustion claim requires bounded repeated measurements and documented scaling assumptions.

## 9. RH-T5 — independent verification and decisions

Adapt upstream `VALIDATION-AND-REPORTING.md` as a versioned verifier instruction. Give a fresh task the candidate, minimal architecture facts, exact source identities and evidence. It re-reads cited code, reconstructs the strongest controls and attempts to refute the prerequisites and claimed effect. It records independent observations and an explicit decision.

The verifier cannot originate a new accepted finding under the candidate's identity. A newly discovered cause becomes a separate Hunt task linked to the current one. Verifiers do not receive another verifier's conclusion as a premise.

Tekmerion retains its independent defect, reachability/model, reproduction and novelty axes. A report mapping to upstream-style `confirmed`, `needs_validation` and `rejected` is derived through versioned rules. Confirmation requires a source-grounded boundary failure and bounded observed security effect. A missing observation retains the exact unresolved fact. A proposed correction and a fail-before/pass-after regression provide additional evidence when available.

Acceptance includes a valid candidate, a refuted attacker-control assumption, a documented powerful API, an unresolved environment fact, a corrupted artifact and a target modification that invalidates reproduction. Fresh-worker replay must preserve the claimed result for a confirmed report.

## 10. RH-T6 — report, coverage review and real pilot

Generate Markdown and JSON reports from saved validated state. Include scope, principals, assumptions, current source/build, independent decisions, raw evidence links, reproductions, blockers, rejected causes, deferred units and costs. Report model choices and provenance, with separate status for fixture-based and real analysis.

Run a bounded coverage review after the first Hunt wave. Its findings create or reopen research units within the remaining budget. A zero-candidate result prompts inspection of task health, context and coverage evidence. It can remain a legitimate result.

Qualify on the control set, then one real JVM library and one property family. Evaluate prompts on held-out cases with source evidence and original/corrected variants. Keep known-bug evaluation separate from novelty assessment.

Measure checked units, valid citations, candidates by decision, reproduced effects, rejected assumptions, unresolved facts, fresh replays, time to first reproduction and resource/LLM cost. Coverage describes investigated combinations and observed code execution. Unknown real-world recall remains explicitly unknown.

### Final report contract

Export versioned `report.json`, human-readable `report.md` and a linked `evidence/` tree containing immutable artifacts and minimal reproducers. Both reports derive from the same validated saved state and include a report-schema version, run identity, state snapshot and generation time. Report generation is deterministic for the same snapshot and supplied metadata, supports interrupted runs and requires no additional paid model calls. Preserve fixture versus real-analysis provenance.

The opening summary states known-CVE confirmation outcomes, distinct variant/new-candidate counts by decision, unresolved work, observed LLM spend, unsettled charges, elapsed time and the exact completion/stop reason. Avoid counting the same root cause as both a known defect and a newly discovered variant. Incomplete work remains visible even when a finding was confirmed.

| Finding field | Required content |
|---|---|
| Identity and decision | Stable candidate/root-cause identity, revisions, origin (CVE-guided or discovery), confirmed/rejected/needs-validation mapping and decision reasons |
| Target | Supplied binary hash, coordinates, source revision and correspondence checks, dependencies, runtime/configuration and graph identity |
| Defect and effect | Expected property, boundary failure, observed security effect, bounded impact and affected principal/resource |
| Prerequisites | Attacker-controlled values, required authority, API/configuration assumptions and their provenance |
| Root cause | Exact source/method references, mechanism and relevant controls/counterarguments |
| Static evidence | API entry, Ariadne queries, paths, edge assumptions, model gaps and independent reachability status |
| Reproduction | Harness/input hashes, environment, commands, expected and actual assertions, logs, outcomes and resource limits |
| Controls and review | Normal input, property-preserving or corrected control, independent review, fresh-worker replay and contradictory observations |
| CVE relationship | Applicability to the supplied artifact/configuration, evidence of reproduction, known-mechanism match and differences supporting a distinct variant |
| Novelty | Known/advisory match, no public match found or undetermined, with search scope, sources and lookup dates |
| Evidence | Relative references to exported artifacts, hashes, producing attempts and provenance |

Retain separate defect, static reachability/model, security-effect reproduction and novelty axes from the ledger. Every human decision label has versioned mapping rules to those axes. A missing observation or blocker cannot become confirmation through report wording. No public match found leaves novelty unestablished; do not automatically label a finding zero-day or imply that a CVE identifier has been assigned.

The closing sections enumerate examined APIs/properties and coverage limits, rejected hypotheses with reasons, unresolved candidates and exact blockers, deferred/unattempted units, and concrete next experiments. Include original versus revised estimates, settled spend by stage/model, reservations and unresolved charges, retries/cache effects, local resources and the configured budgets. A zero-finding conclusion says that no vulnerability was confirmed in the investigated scope; it does not certify the library's safety.

Example export layout (planned):

```text
run-output/
  report.md
  report.json
  evidence/
    index.json
    inputs/
    ariadne/
    findings/<candidate-id>/
      reproducer/
      observations/
      review/
```

Evidence retention/export policy determines whether sensitive raw provider payloads are included; reports must identify withheld artifacts and must exclude credentials. Include available reproducer commands and artifact hashes so another worker can check the stated result. Validate exported links and hashes before marking an export complete.

Acceptance covers a confirmed known CVE, a distinct variant, a rejected claim, an unresolved/static-gap case, zero findings and budget interruption. Verify JSON schema and decision mappings, Markdown/JSON agreement, artifact references, no double-counted candidates/costs and regeneration from saved state. Add paired CVE-guided/unguided evaluation to RH-T6 after the control suite passes.

## 11. RH-T7 — additions driven by evidence

Candidate extensions include richer coverage-critic waves, on-demand source/data-flow queries, CodeQL, more property families, additional model providers, semantic deduplication and cross-repository consumer analysis. Record the missing capability and a measurable success criterion before implementing an extension.

The first release uses the existing Ariadne graph interface and source mapping. CodeQL is introduced when a concrete candidate requires data-flow facts unavailable from those inputs. Fleet tracing follows multiple relevant repositories and a measured need for consumer context. RI6 runtime correlation follows a specific observation requirement.

## 12. Cross-repository milestones

| Milestone | Tekmerion | Ariadne | Result |
|---|---|---|---|
| H0 | RH-T0 | RH-A0 | Strict evidence acceptance and regression fixtures |
| H1 | RH-T1–RH-T2 | Needed RH-A1 operations | Persistent state and grounded coverage units |
| H2 | RH-T3 | RH-A1–RH-A2 | Resumable candidates with static evidence |
| H3 | RH-T4–RH-T5 | RH-A2–RH-A3 | Independent verification and property experiments |
| H4 | RH-T6 | RH-A3 | Reproducible real-library pilot |
| H5 | Measured RH-T7 extension | RH-A4 when needed | Explicitly evaluated follow-up |

Start with RH-T0 and the RH-T1 state design while Ariadne handles RH-A0. Then implement one Recon/Hunt/Validate path on the control target. Every increment has a separate reviewable PR, focused tests, source/protocol/prompt identities and documentation of actual behavior.

## 13. Acceptance and continuation

The adapted workflow is accepted when a run starts with zero hypotheses, records its coverage and assumptions, generates source-grounded candidates, consumes validated Ariadne evidence, verifies them independently and produces an auditable report. A stopped run can resume without losing evidence or silently resetting costs. Supported findings include a bounded reproduction through the original library's API. Rejected and unresolved candidates remain traceable.

Record completed increments and counterpart commits in the implementation plan. Preparing this document establishes planned work. Existing TM/RI partial implementations retain their current documented status.
