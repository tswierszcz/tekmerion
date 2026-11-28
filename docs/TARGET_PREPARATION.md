# Target preparation (TM1)

Date 2026-11-24. Implements TM1 of the [implementation plan](../IMPLEMENTATION_PLAN.md): a pinned revision is built from source under a declared recipe, the artifacts and classpath are hashed, a source index maps Ariadne method identities to source lines, `ariadne research index` builds the bundle, and a run manifest binds all of it.

```bash
go build -o bin/tekmerion ./cmd/tekmerion
bin/tekmerion prepare -project testdata/control/project.json -checkout /path/to/ariadne -work /tmp/tm1 -ariadne /path/to/ariadne/bin/ariadne
bin/tekmerion locate -work /tmp/tm1 fx.research.Extractor writeEntry '(Ljava/nio/file/Path;[B)V'
```

## 1. Project manifest (`tekmerion-project-1`)

Declared input, [internal/manifest](../internal/manifest/manifest.go). The control example is [testdata/control/project.json](../testdata/control/project.json). The real-library pilot uses [testdata/pilot/zt-zip-1.12.json](../testdata/pilot/zt-zip-1.12.json): zt-zip 1.12 (before the CVE-2018-1002201 zip slip fix), compiled with javac against slf4j-api 1.6.6, with a file-confinement threat model.

| Field | Content |
|---|---|
| `target.repository`, `target.revision` | Canonical URL and a full commit id |
| `target.paths` | Parts of the revision exported for the build (whole tree when empty) |
| `target.source_roots` | `{path, artifact}`: which source root each artifact is compiled from |
| `build.network` | `none` (enforced) or `allowed` (also needs `-allow-network`) |
| `build.env`, `build.steps` | Extra environment; steps as argv with `${SRC}`, `${OUT}`, `${WORK}` and `$$` |
| `build.outputs` | `app`, `deps`, `deps_list` relative to `${OUT}`, as `research index` takes them |
| `scenario` | Ariadne `roots`, `profile`, `scope` |
| `threat_model`, `research_scope`, `budgets` | Carried verbatim for later phases |

Unknown fields are rejected.

## 2. Controlled build

1. The checkout must contain `target.revision`. The revision's `target.paths` are exported with `git archive` into a fresh `work/src`, so the working tree's state is irrelevant. The git tree ids of the exported paths and a content hash of the exported files (`sha256 mode path` lines) are recorded.
2. `work/src` is made read-only. Steps run there with a fixed environment (`HOME`, `TMPDIR` inside the work directory, `LC_ALL=C`, `TZ=UTC`, `SOURCE_DATE_EPOCH` = commit time, `JAVA_HOME` if set, `PATH`, plus `build.env`). No shell is involved unless a step runs one.
3. With `network: none` every step runs inside `unshare --user --map-current-user --net`, which leaves only loopback. If the namespace is unavailable the preparation fails instead of building with network. A recipe with `network: allowed` runs unwrapped and only when the caller passes `-allow-network`.
4. Each step's argv, exit status, duration and output hashes are recorded; output is kept in `work/logs`. After the build the source tree hash is recomputed and must be unchanged.
5. Artifact hashes: the app jar, each dependency jar, the deps list (checked for `group:artifact:type:version:scope` lines). The classpath is the order Ariadne selects in, the app then dependency jars by file name; `classpath_sha256` covers its `sha256 path` lines.

The build environment is recorded (OS, kernel, java version/vendor/home and the launcher's hash), not provided; a container image is a later step (plan section 7).

## 3. Source index (`tekmerion-source-index-1`)

[internal/sourceindex](../internal/sourceindex/index.go) reads every class in each source root's artifact. The `SourceFile` attribute, the package directory and the source root give the file. Each method's `LineNumberTable` gives its first and last line (body lines; the constructor's first line is its `super` call). Methods without code have no lines. Entries are keyed by the class file's SHA-256, which is Ariadne's `class_sha256`, so a method resolves to the exact copy Ariadne analysed when two jars hold a class of the same name (the control library's two `fx.dep.Paths2`).

Binding: `build_verified` when the file is in the exported tree the artifact was built from, `declared` when the class names a file that is not there, `unavailable` without `SourceFile`.

`Resolve(method, ariadneSource)` combines Ariadne's `Source` record with the index:

- No usable Ariadne record (no path, no lines): the index entry, basis `tekmerion`.
- Ariadne only: Ariadne's record, basis `ariadne`.
- Both: they must agree on whatever both state. Ariadne's path must equal the indexed path or a suffix of it at a `/` boundary, since Ariadne reports it within the package tree or its `-sources` directory. Hashes must be equal and lines identical. On agreement the basis is `ariadne+tekmerion` and the stronger binding stands. Any disagreement is listed in `conflicts` and the binding becomes `unavailable`, so nothing cites it.

Ariadne main (baf3384) already reports lines from the same table with binding `declared` and no path. Ariadne tswierszcz/ariadne#153 (RI4, branch `research-source-paths`, not merged at the time of writing) adds `path` (package path plus `SourceFile`, e.g. `fx/research/Extractor.java`) and, with `research index -sources DIR|JAR`, `source_sha256` when exactly one file there ends with that path. Its binding stays `declared`. Tekmerion upgrades the binding to `build_verified` only when its own build of that tree agrees on path, hash and lines. When Ariadne lists `-sources` in `research index -h`, preparation passes the app's source root (`-sources auto`, the default; `always`/`never` override). Dependency roots are not passed, so dependency methods get a path but no hash from Ariadne. `sources_flag` in the run manifest records whether it was passed. The sources become part of the bundle identity, so the `analysis_id` differs from one indexed without `-sources`. It does not depend on the work directory.

The index stays the fallback for an Ariadne without RI4 and for anything Ariadne leaves null.

## 4. Run manifest (`tekmerion-run-manifest-1`)

`work/run-manifest.json`:

| Field | Binds |
|---|---|
| `project`, `project_original`, `project_sha256` | Readable input, exact original file bytes (base64) and their hash |
| `source` | Repository, commit, commit time, git tree ids, exported tree hash and file count |
| `build` | Network policy and enforcement, environment, step environment and step runs |
| `artifacts` | App, dependency jars and deps list with hashes; classpath and its hash |
| `source_index` | The index file's hash, methods and located methods |
| `analysis` | `analysis_id`, bundle manifest/identity hashes, scenario, Ariadne binary hash and version, `-sources`, argv |

The work directory appears as `${WORK}` in recorded paths. Two preparations of one project produce equal manifests except `prepared_at`, step durations and `analysis.manifest_sha256` (Ariadne's bundle manifest carries `created_at`; `analysis_id` is the hash of the bundle identity and is stable).

## 5. Acceptance

`TestAcceptanceControlLibrary` ([internal/prepare/acceptance_test.go](../internal/prepare/acceptance_test.go)) prepares Ariadne's control library (`testdata/research`: `lib`, `dep`, `depold`, built by Ariadne's own `scripts/JavaBuild.java`) twice from the revision in the project file and checks:

1. Both run manifests bind the same identities.
2. The rebuilt `lib.jar`, `deps/fx-dep-1.0.jar`, `deps/fx-dep-2.0.jar` and `deps.txt` are byte-identical to the files committed at that revision.
3. Indexing the committed jars gives the rebuild's `analysis_id`.
4. Every `fx.*` method listed by `methods` resolves to a `build_verified` file and lines, with Ariadne's lines and the index agreeing, including the selected 1.0 copy of `Paths2` (by class hash).

```bash
(cd $ARIADNE_SRC && go build -o bin/ariadne ./cmd/ariadne)
ARIADNE_SRC=/path/to/ariadne go test ./internal/prepare -run Acceptance -v
```

`ARIADNE_SRC` must have the pinned revision in its git history; `ARIADNE_BIN` overrides the binary. The build needs `java` with `jdk.compiler` and unprivileged user namespaces.

Results on 2026-11-24. The test passes with both Ariadne builds:

| Ariadne | `-sources` | `analysis_id` | Ariadne source records (17 `fx.*` methods) |
|---|---|---|---|
| main `baf3384` | not offered | `sha256:9b67ddf2…5b09b815` | lines only; agree with the index |
| #153 `3c999a8` | passed | `sha256:6d38e4db…63e9b007` | 17 paths, 14 hashes (the library's); all agree |

Identities with Ariadne baf3384 (`v0.0.0-20261124123008-baf3384fd63a`) and OpenJDK 25.0.5:

| Identity | Value |
|---|---|
| Commit | `baf3384fd63aca49e75abffa3735d7ad170041d3` |
| Exported source tree | `sha256:2506ab96252ad20741faf206a73b1b46f82fdcd6a6928d91e29eea680dd9d23b` (7 files) |
| `lib.jar` | `sha256:a1cbff5b999371b7317536eab17c2eefeff25bbfafae2f1f5fc18d3aee744718` |
| Classpath | `sha256:f9708026ee71b7349c29dd4c9531c9bc45ebeb4cae84394d5d3504c1fc840ad3` (3 jars) |
| `analysis_id` | `sha256:9b67ddf2e570b29c3a2e7e7a6d34503cacee104959f09448b764378b5d09b815` |

## 6. Not in this increment

- The property-preserving control variant of the plan's TM1 list. RH-T4 now builds a corrected variant from an experiment's correction patch with `prepare.BuildVariant` (same recipe, separate directory); a standalone variant target is still not part of preparation.
- A container image as the build environment, and resource limits for steps.
- Maven/Gradle recipe helpers: a networked dependency resolution is expressible as an `allowed` recipe, but resolution is not yet split into its own recorded stage.

## 6. Reusing preparation for Recon

`prepare.Verify` rechecks source tree/file count, original project bytes and semantic equality to the readable projection, repository/revision, successful build-step identity, artifact/classpath hashes, source-index identity/counts and bundle manifest/identity hashes. `ReadFile` confines bounded regular reads through a directory handle and rejects static symlink members and path escapes. Source collection runs only on this controller-owned prepared snapshot; target execution and hostile worker-output promotion remain separate work.

Recon verifies preparation again after collecting context and independently checks each selected source file against the source index. Selected source bytes are archived under their SHA-256, with exact excerpt ranges. New runs preserve `project_original` because JSON indentation changes the bytes of an embedded `json.RawMessage`; the readable `project` field alone cannot reproduce the original file hash. Legacy preparation has an explicit gap for that original-byte check while source/artifact/index/bundle checks still apply.
