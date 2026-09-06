"""OpenTelemetry wiring: one assessment renders as one distributed trace.

Tracing is opt-in via OTEL_EXPORTER_OTLP_ENDPOINT (compose points it at the
bundled Jaeger). When unset, get_tracer() hands back no-op tracers, so the
instrumented code paths cost nothing in tests and bare runs. Trace context
propagates across A2A and MCP hops automatically: the httpx instrumentation
injects traceparent on every outbound call, and the FastAPI/Starlette
instrumentation extracts it on every inbound one.
"""

from __future__ import annotations

import os

from opentelemetry import trace


def setup_telemetry(service_name: str) -> bool:
    """Install a tracer provider and auto-instrumentation. Call once per process."""
    if not os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return False

    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    HTTPXClientInstrumentor().instrument()
    return True


def traced_asgi(app):
    """Wrap an ASGI app so inbound requests join the caller's trace.

    Explicit wrapping (instead of framework monkey-patching) because our apps
    sit behind a raw ASGI auth middleware. No-op when telemetry is disabled.
    """
    if not os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return app
    from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware

    return OpenTelemetryMiddleware(app)


def get_tracer() -> trace.Tracer:
    return trace.get_tracer("triage_mesh")
