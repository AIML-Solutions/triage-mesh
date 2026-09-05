# Architecture

This document is the system's source of truth. Code that disagrees with it is wrong or the doc gets a PR.

## 1. Components

| Component | Kind | Protocol surface | Container |
|---|---|---|---|
| `orchestrator` | A2A client + HTTP API | serves REST to users/CI; A2A client to agents | `svc-orchestrator` |
| `scanner-agent` | A2A server | A2A in; MCP client of `repo-reader` | `agent-scanner` |
| `intel-agent` | A2A server | A2A in; MCP client of `vuln-intel` | `agent-intel` |
| `assessor-agent` | A2A server | A2A in; MCP client of `report-writer` | `agent-assessor` |
| `repo-reader` | MCP server (stateless) | read-only filesystem/git tools | `mcp-repo-reader` |
| `vuln-intel` | MCP server (stateless) | OSV + NVD lookup tools | `mcp-vuln-intel` |
| `report-writer` | MCP server (stateless) | draft-report tools; writes only to a staging area | `mcp-report-writer` |

Each agent embeds the same harness library (`triage_mesh.harness`): model loop, policy engine, trust labeling, and structured logging. Agents differ only in their card, their toolset, and their system prompt.

## 2. Control flow

1. `POST /assessments {repo_url}` → orchestrator creates an assessment record and opens **A2A tasks** on scanner and intel (parallel, async lifecycle — these can take minutes; the orchestrator polls task state rather than holding connections).
2. Scanner returns a typed `DependencyInventory`; intel returns typed `AdvisoryBundle`s for the inventory.
3. Orchestrator opens an A2A task on assessor with both artifacts. Assessor drafts a `RemediationReport` through `report-writer`.
4. Report lands in **staging**, state `PENDING_APPROVAL`. A human approves via the orchestrator API; only then is the report published. No agent has a publish capability.

Failure policy: A2A tasks carry deadlines; the orchestrator degrades to partial results (e.g., inventory without intel) and says so in the report rather than silently retrying forever.

## 3. Protocol boundaries

**A2A for agent↔agent, MCP for agent↔tool.** Full rationale in [why-two-protocols.md](why-two-protocols.md). Consequences:

- Agents never call each other's MCP servers. Cross-agent data moves only through A2A task artifacts, which pass through the orchestrator — one choke point for validation and audit.
- MCP servers are stateless (2026-07-28 spec): no sessions, header-routed, horizontally scalable, individually replaceable.
- Discovery is explicit: agents publish A2A Agent Cards; the orchestrator is configured with card URLs, not hardcoded skills.

## 4. Security layers

Defense in depth, ordered from outermost:

1. **Network (K8s NetworkPolicies).** Orchestrator → agents; each agent → only its own MCP server; `vuln-intel` is the only pod with internet egress (to OSV/NVD). Everything else default-deny.
2. **Service auth.** Short-lived JWTs on every A2A and MCP request, issued per-service; an agent's token cannot authenticate to another agent's tool server.
3. **Policy engine (harness).** Declarative YAML policy per agent: allowed tools, argument constraints (path prefixes, domain allowlists, max result sizes), and rate ceilings. Enforced deterministically *before* any tool call leaves the harness — the model cannot talk its way past it.
4. **Schema validation.** Pydantic models on every boundary object (`DependencyInventory`, `AdvisoryBundle`, `RemediationReport`, all tool I/O). Reject-by-default; no free-form dict passthrough.
5. **Trust labeling.** All content fetched from the repo or advisory APIs is wrapped as `Untrusted[str]` and rendered into prompts inside delimited data blocks. Harness rule: a turn whose context contains untrusted content may *propose* tool calls only from that agent's read-only set; state-changing tools (report drafting) require arguments derived from validated, typed artifacts — the plan-then-execute pattern.
6. **Human gate.** Publishing is a capability held by the orchestrator's API layer only, behind explicit approval.

The red-team suite (`tests/redteam/`) attacks layers 3–5 directly: advisory text containing tool-call instructions, poisoned MCP tool descriptions, over-scoped argument attempts, oversized payloads. CI fails if any attack lands.

## 5. Deployment

- **Local demo:** `docker compose up` — seven containers, seeded demo repo, single command to a finished report.
- **Cluster:** Helm chart under `deploy/chart/`. One Deployment per component, non-root images, pinned digests, resource limits, liveness/readiness probes, secrets via K8s Secrets (API keys never in images). Reproducible on kind: `make cluster-demo`.
- The NetworkPolicy manifests are generated from the same topology declaration the policy engine reads — one source of truth for "who may talk to whom," enforced at two layers.

## 6. Observability

Structured JSON logs with a per-assessment correlation ID across all seven services; every tool call logs (agent, tool, policy decision, duration). Phase 4 adds OpenTelemetry traces so a full assessment renders as one trace.

## 7. Non-goals (v1)

- Auto-remediation PRs (the human gate is the point; PR drafting may come later).
- Supporting every ecosystem — v1 scans Python (`pyproject.toml`/lockfiles) and npm (`package-lock.json`) only.
- Multi-tenant operation. One deployment, one trust domain.
