# Why two protocols

Short version: **MCP answers "how does an agent use a capability"; A2A answers "how does work move between autonomous parties."** Using either for the other's job costs you exactly the properties this system exists to demonstrate.

## The boundary rule

| Interaction | Protocol | Why |
|---|---|---|
| Agent ↔ tool (repo files, CVE APIs, report drafts) | **MCP** | Tools are capabilities: typed schemas, stateless request/response, no negotiation. MCP's 2026-07-28 stateless core makes tool servers cattle — scalable, replaceable, cacheable. |
| Orchestrator ↔ agent (delegate, monitor, collect) | **A2A** | Delegation is a *task* with a lifecycle: it runs for minutes, reports state, can fail partially, returns typed artifacts. A2A models exactly that (tasks, Agent Cards, async polling); MCP does not want to. |

## What each protocol buys us

**MCP at the tool boundary:**
- Tool schemas are the first validation layer — malformed arguments die at the protocol edge, before the policy engine even runs.
- Statelessness means the security analysis of a tool server is local: request in, response out, no session state to poison across calls.
- Swapping NVD for a different intel source is a server swap, invisible to the agent.

**A2A at the agent boundary:**
- Agent Cards make capabilities *discoverable and auditable* — the orchestrator delegates against a published contract, not a hardcoded import.
- The async task lifecycle fits real scan durations without holding connections open (and maps cleanly onto the orchestrator's degrade-to-partial-results policy).
- Task artifacts are the natural choke point: everything that crosses between agents is a typed, validated object passing through one place.

## What collapsing them would cost

- **Everything-as-MCP** (agents exposed as tools): delegation loses its lifecycle — no task state, no partial failure, no artifact contract — and agent-to-agent trust collapses into tool trust, so the policy engine can no longer distinguish "call a tool" from "hand work to another autonomous party." Those are different risk classes and are policed differently.
- **Everything-as-A2A** (tools wrapped as agents): every tool call inherits task-lifecycle overhead it doesn't need, and the tool layer loses schema-first validation — the property the threat model leans on hardest.

## Security consequence

The two-protocol split gives the deployment a clean privilege topology: A2A traffic exists only between orchestrator and agents; MCP traffic only between an agent and *its own* tool server. That statement is enforced twice — by per-agent policy in the harness and by NetworkPolicies in the cluster — and it's auditable because the protocol tells you what kind of interaction every packet is.

This mirrors where the field landed in 2025–2026 (MCP as the tool substrate, A2A as the coordination substrate); the point of this repo is showing the boundary *enforced*, not just diagrammed.
