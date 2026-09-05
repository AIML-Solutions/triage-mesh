# Threat model

Scope: one triage-mesh deployment, one trust domain, v1 components as listed in [architecture.md](architecture.md). The interesting property of this system is that its *primary inputs are attacker-influenced by design*: repo contents and public vulnerability advisories are untrusted text that the system must reason over without obeying.

## Trust zones

| Zone | Contents | Trust |
|---|---|---|
| Z0 | Human approver, orchestrator API auth | trusted |
| Z1 | Orchestrator service | trusted code, handles untrusted data |
| Z2 | Agents (model-in-the-loop) | **untrusted decisions** — treat the LLM as a confused deputy; its proposals are validated, never obeyed directly |
| Z3 | MCP servers | trusted code, constrained capabilities |
| Z4 | External world: scanned repo, OSV/NVD responses | **hostile** |

The load-bearing assumption, taken from the systems-security literature on agents: *the model is an untrusted component*. Safety properties must hold even if an agent's model is fully steered by injected content.

## Top threats and mitigations

| # | Threat | Path | Mitigations (layer) |
|---|---|---|---|
| T1 | Indirect prompt injection via advisory text | Z4→Z2: CVE description instructs assessor to alter the report or call tools | Trust labels + plan-then-execute (harness); state-changing tool args must derive from typed artifacts; red-team CI case |
| T2 | Indirect injection via repo contents | Z4→Z2: malicious `pyproject.toml` comment steers scanner | Scanner has read-only toolset; output constrained to `DependencyInventory` schema; injection can distort *data*, not *actions* — and the human gate catches distorted data |
| T3 | Tool poisoning / rug pull on an MCP server | compromised Z3 lies in tool descriptions or results | First-party servers, pinned digests; tool descriptions hashed at deploy and verified by harness; schema validation on results; red-team case with a deliberately poisoned server |
| T4 | Agent overreach (over-scoped or excessive tool calls) | Z2: model attempts a tool/argument outside its role | Policy engine deny-by-default with argument constraints and rate ceilings; violations logged and fail the task, not just the call |
| T5 | Lateral movement between services | compromised container reaches another's surface | Per-service JWTs (Z2↔Z3 pairwise); K8s NetworkPolicies default-deny; only `vuln-intel` has egress |
| T6 | Data exfiltration via the intel egress path | Z2 encodes repo secrets into OSV/NVD query parameters | Query schema allows package coordinates only (name/version/ecosystem enums + version strings); policy engine validates against the actual inventory; scanner redacts non-manifest content |
| T7 | Unapproved publication | any zone attempts to ship a report without review | Publish capability exists only in the orchestrator API behind Z0 approval; report-writer can write staging only |
| T8 | Secret leakage | keys in images, logs, or prompts | K8s Secrets only; structured logger redacts known key patterns; secrets never enter model context |
| T9 | Resource exhaustion / cost blowout | injected content induces loops or giant payloads | Task deadlines, per-task token budgets, MCP result size caps, container resource limits |

## Residual risks (v1, accepted)

- A poisoned advisory can still bias the *content* of an assessment (wrong severity narrative). Mitigated by the human gate and by citing raw advisory sources in the report; not eliminated.
- Supply-chain trust in the two SDKs and base images is pinned-and-reviewed, not proven.
- No multi-tenant isolation; deploying for multiple trust domains requires one mesh each.

## Verification

Every mitigation above maps to at least one automated check: red-team cases (`tests/redteam/`, threats T1–T4, T6), policy unit tests (T4, T6, T7), and a cluster conformance test that asserts the NetworkPolicy topology (T5). CI publishes the attack-block count the README badge reports.
