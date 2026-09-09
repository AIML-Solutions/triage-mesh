"""Deterministic tool-call policy engine (threat T4, T6, T9).

Policies are data (deploy/policies.yaml), not prompts. Checks run in the
harness before a call leaves the agent; violations raise, and the task fails
rather than the call being silently dropped — a blocked call means either an
attack or a bug, and both must surface.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import yaml


class PolicyViolation(RuntimeError):
    pass


class PolicyEngine:
    def __init__(self, config: dict):
        self._agents: dict = config.get("agents") or {}
        self._integrity: dict = config.get("tool_integrity") or {}

    def expected_manifest(self, server: str) -> str | None:
        """Pinned manifest hash for a first-party MCP server (None if unpinned)."""
        value = self._integrity.get(server)
        return str(value) if value else None

    @classmethod
    def load(cls, path: str | Path | None = None) -> PolicyEngine:
        path = Path(path or os.environ.get("POLICY_PATH", "deploy/policies.yaml"))
        return cls(yaml.safe_load(path.read_text(encoding="utf-8")))

    def max_calls(self, agent: str) -> int:
        return int(self._agent_config(agent).get("max_calls_per_task", 10))

    def check(self, agent: str, tool: str, arguments: dict[str, Any]) -> None:
        tools = self._agent_config(agent).get("tools")
        if not isinstance(tools, dict) or tool not in tools:
            raise PolicyViolation(f"agent {agent!r} may not call tool {tool!r}")
        constraints = (tools[tool] or {}).get("args") or {}
        for arg_name, rules in constraints.items():
            if arg_name not in arguments:
                raise PolicyViolation(f"{agent}.{tool}: required argument {arg_name!r} missing")
            self._check_value(f"{agent}.{tool}.{arg_name}", arguments[arg_name], rules)
        for arg_name in arguments:
            if constraints and arg_name not in constraints:
                raise PolicyViolation(f"{agent}.{tool}: unexpected argument {arg_name!r}")

    def _agent_config(self, agent: str) -> dict:
        config = self._agents.get(agent)
        if not isinstance(config, dict):
            raise PolicyViolation(f"no policy defined for agent {agent!r}")
        return config

    @staticmethod
    def _check_value(label: str, value: Any, rules: dict) -> None:
        if "enum" in rules and value not in rules["enum"]:
            raise PolicyViolation(f"{label}: value {value!r} not in allowed set")
        if "pattern" in rules and (
            not isinstance(value, str) or not re.fullmatch(rules["pattern"], value)
        ):
            raise PolicyViolation(f"{label}: value does not match allowed pattern")
        if "max_bytes" in rules:
            size = len(json.dumps(value, default=str).encode("utf-8"))
            if size > int(rules["max_bytes"]):
                raise PolicyViolation(f"{label}: payload of {size} bytes exceeds cap")
