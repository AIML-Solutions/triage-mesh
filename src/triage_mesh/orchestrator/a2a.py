"""A2A client side: delegate one JSON task to an agent, with a deadline."""

from __future__ import annotations

import asyncio
import json
import uuid

import httpx
from a2a.client.client import ClientConfig
from a2a.client.client_factory import ClientFactory
from a2a.types import GetTaskRequest, Message, Part, SendMessageRequest

from triage_mesh.harness.auth import bearer_headers

_COMPLETED_STATE = 3  # TASK_STATE_COMPLETED


class AgentTaskError(RuntimeError):
    pass


async def send_task(
    agent_url: str, payload: dict, deadline_seconds: float, audience: str | None = None
) -> dict:
    """Send one task to an A2A agent and return its result artifact as a dict.

    Raises AgentTaskError on failure or deadline expiry — callers decide
    whether that degrades the assessment to partial or fails it.
    """
    try:
        return await asyncio.wait_for(_send(agent_url, payload, audience), timeout=deadline_seconds)
    except TimeoutError as error:
        raise AgentTaskError(f"deadline exceeded for {agent_url}") from error


async def _connect(agent_url: str, headers: dict):
    """Resolve the agent card with brief retries — agents may still be booting."""
    for attempt in range(3):
        config = ClientConfig(httpx_client=httpx.AsyncClient(headers=headers))
        try:
            return await ClientFactory(config).create_from_url(agent_url)
        except Exception:
            if attempt == 2:
                raise
            await asyncio.sleep(2.0 * (attempt + 1))
    raise AgentTaskError(f"unreachable: {agent_url}")  # pragma: no cover


async def _send(agent_url: str, payload: dict, audience: str | None = None) -> dict:
    headers = bearer_headers("orchestrator", audience) if audience else {}
    client = await _connect(agent_url, headers)
    try:
        message = Message(
            message_id=str(uuid.uuid4()),
            role="ROLE_USER",
            parts=[Part(text=json.dumps(payload, default=str))],
        )
        task_id = None
        async for event in client.send_message(SendMessageRequest(message=message)):
            if event.WhichOneof("payload") == "task":
                task_id = event.task.id
        if task_id is None:
            raise AgentTaskError(f"no task returned by {agent_url}")

        task = await client.get_task(GetTaskRequest(id=task_id))
        if task.status.state != _COMPLETED_STATE:
            raise AgentTaskError(
                f"task {task_id} on {agent_url} ended in state {task.status.state}"
            )
        for artifact in task.artifacts:
            for part in artifact.parts:
                if part.text:
                    return json.loads(part.text)
        raise AgentTaskError(f"task {task_id} on {agent_url} produced no artifact")
    finally:
        await client.close()
