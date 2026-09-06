"""A2A serving glue: JSON-payload task executor + Starlette app builder.

Payload convention (both directions): one text Part containing a JSON object.
Typed validation happens in each agent's handler against the schemas module.
"""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable

import uvicorn
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events.event_queue import EventQueue
from a2a.server.request_handlers.default_request_handler_v2 import DefaultRequestHandlerV2
from a2a.server.routes.agent_card_routes import create_agent_card_routes
from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.server.tasks.task_updater import TaskUpdater
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill, Part
from starlette.applications import Starlette

from triage_mesh.harness.logging import get_logger, log

Handler = Callable[[dict], Awaitable[dict]]


def make_card(*, name: str, description: str, skill: str, public_url: str) -> AgentCard:
    return AgentCard(
        name=name,
        description=description,
        version="0.1.0",
        supported_interfaces=[
            AgentInterface(url=public_url, protocol_binding="JSONRPC", protocol_version="1.0")
        ],
        capabilities=AgentCapabilities(streaming=False),
        default_input_modes=["application/json"],
        default_output_modes=["application/json"],
        skills=[AgentSkill(id=skill, name=skill, description=description, tags=["triage-mesh"])],
    )


def payload_of(context: RequestContext) -> dict:
    for part in context.message.parts if context.message else []:
        if part.text:
            return json.loads(part.text)
    raise ValueError("no JSON payload part in message")


class JsonTaskExecutor(AgentExecutor):
    """Runs one JSON-in/JSON-out handler per task, with full lifecycle events."""

    def __init__(self, service: str, handler: Handler):
        self._service = service
        self._handler = handler
        self._logger = get_logger(service)

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.current_task is None:
            from a2a.helpers.proto_helpers import new_task_from_user_message

            await event_queue.enqueue_event(new_task_from_user_message(context.message))
        updater = TaskUpdater(event_queue, context.task_id, context.context_id)
        await updater.start_work()
        try:
            payload = payload_of(context)
            correlation_id = payload.get("correlation_id", context.task_id)
            log(self._logger, "task.start", correlation_id=correlation_id, task_id=context.task_id)
            result = await self._handler(payload)
            await updater.add_artifact(
                [Part(text=json.dumps(result, default=str))], name=f"{self._service}.result"
            )
            await updater.complete()
            log(
                self._logger,
                "task.complete",
                correlation_id=correlation_id,
                task_id=context.task_id,
            )
        except Exception as error:
            log(self._logger, "task.failed", task_id=context.task_id, error=str(error))
            await updater.failed(
                updater.new_agent_message([Part(text=json.dumps({"error": str(error)}))])
            )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        await TaskUpdater(event_queue, context.task_id, context.context_id).cancel()


def build_app(card: AgentCard, executor: AgentExecutor) -> Starlette:
    handler = DefaultRequestHandlerV2(
        agent_executor=executor, task_store=InMemoryTaskStore(), agent_card=card
    )
    routes = create_agent_card_routes(card) + create_jsonrpc_routes(handler, rpc_url="/")
    return Starlette(routes=routes)


def serve_agent(card: AgentCard, executor: AgentExecutor, default_port: int) -> None:
    from triage_mesh.harness.auth import ServiceAuthMiddleware
    from triage_mesh.harness.telemetry import setup_telemetry, traced_asgi

    setup_telemetry(card.name)

    uvicorn.run(
        traced_asgi(ServiceAuthMiddleware(build_app(card, executor), audience=card.name)),
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", default_port)),
        log_level="warning",
    )
