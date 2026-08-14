"""Error types and handlers.

Clients get a stable, machine-readable error envelope. Stack traces and
internal exception text never cross the API boundary in production -- they are
an information-disclosure vector (library versions, file paths, SQL fragments).
"""

from __future__ import annotations

import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import settings
from .sanitize import scrub, scrub_structure

logger = logging.getLogger("sentinelcti")

# Literal codes rather than the `status.*` constants: several of those names
# were renamed across Starlette versions (422 and 413 in particular), and the
# numbers are the stable part of the HTTP contract.
HTTP_BAD_REQUEST = 400
HTTP_NOT_FOUND = 404
HTTP_PAYLOAD_TOO_LARGE = 413
HTTP_UNSUPPORTED_MEDIA_TYPE = 415
HTTP_UNPROCESSABLE = 422
HTTP_TOO_MANY_REQUESTS = 429
HTTP_INTERNAL_ERROR = 500
HTTP_SERVICE_UNAVAILABLE = 503


class SentinelError(Exception):
    """Base class for expected, client-facing failures."""

    status_code = HTTP_BAD_REQUEST
    code = "sentinel_error"

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ValidationFailure(SentinelError):
    status_code = HTTP_UNPROCESSABLE
    code = "invalid_indicator"


class NotFoundError(SentinelError):
    status_code = HTTP_NOT_FOUND
    code = "not_found"


class PayloadTooLarge(SentinelError):
    status_code = HTTP_PAYLOAD_TOO_LARGE
    code = "payload_too_large"


class UnsupportedMedia(SentinelError):
    status_code = HTTP_UNSUPPORTED_MEDIA_TYPE
    code = "unsupported_media_type"


class RateLimited(SentinelError):
    status_code = HTTP_TOO_MANY_REQUESTS
    code = "rate_limited"


class CapacityExceeded(SentinelError):
    """Analysis capacity is saturated; the client should retry shortly.

    503 rather than 429: this is not the caller being rate-limited for their
    own behaviour, it is the service protecting itself, and the distinction
    matters to anyone reading the logs.
    """

    status_code = HTTP_SERVICE_UNAVAILABLE
    code = "capacity_exceeded"


def _envelope(code: str, message: str, details: dict | None = None) -> dict:
    """Build the client-facing error body.

    Messages are scrubbed because validation errors quote the *rejected* value
    back to the caller -- "'<value>' is not a valid IPv4 address". That is good
    feedback, but it means the error path carries submitter-controlled text into
    the UI and the logs, bypassing the scrubbing applied when an analysis is
    stored. A submission rejected for being malformed can still contain a bidi
    override or an ANSI escape, so it is neutralised here, at the one point
    every error envelope passes through.
    """
    body: dict = {"error": {"code": code, "message": scrub(message, max_length=500)}}
    if details:
        body["error"]["details"] = scrub_structure(details)
    return body


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(SentinelError)
    async def _sentinel(_: Request, exc: SentinelError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(exc.code, exc.message, exc.details),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        fields = [
            {"field": ".".join(str(p) for p in err.get("loc", [])[1:]), "issue": err.get("msg", "")}
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=HTTP_UNPROCESSABLE,
            content=_envelope("validation_error", "Request payload failed validation.", {"fields": fields}),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope("http_error", str(exc.detail)),
        )

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        # Correlate the opaque client response with the full server-side trace.
        incident = uuid.uuid4().hex[:12]
        logger.exception("unhandled_error incident=%s", incident)
        message = (
            "An internal error occurred. Quote the incident id when reporting it."
            if settings.is_production
            else f"{type(exc).__name__}: {exc}"
        )
        return JSONResponse(
            status_code=HTTP_INTERNAL_ERROR,
            content=_envelope("internal_error", message, {"incident_id": incident}),
        )
