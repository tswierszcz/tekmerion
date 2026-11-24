# Tekmerion

LLM-assisted vulnerability research for open-source JVM libraries. Combines Ariadne's reachability analysis with static analysis and targeted testing to generate hypotheses, investigate attack paths, and produce reproducible evidence of security flaws.

The project is in the planning stage. The [implementation plan](IMPLEMENTATION_PLAN.md) defines the first pilot, evidence formats, integration milestones, and acceptance criteria.

Tekmerion starts with a pinned library revision, a reproducible build, and a threat model. It discovers candidate security properties, generates hypotheses from source and API context, evaluates static evidence, and runs focused experiments through the library's public API. Findings record the suspected defect, reachability, and observed security effect as separate assessments.

[Ariadne](https://github.com/tswierszcz/ariadne) provides JVM graphs, API entry points, path evidence, and model gaps. Tekmerion owns LLM workflows, source analysis, test generation, experiment execution, and research reports. The integration uses a versioned CLI and JSON contract.

The first milestone is the shared contract and a local fixture-backed workflow. The first pilot covers one library and one vulnerability class, including a control variant and a reproducible test.
