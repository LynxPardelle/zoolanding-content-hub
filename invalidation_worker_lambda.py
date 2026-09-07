"""Dormant, isolated entrypoint for THN cache invalidation."""

from __future__ import annotations

from typing import Any


class HandlerNotActiveError(RuntimeError):
    """The reviewed invalidation contract is not installed."""


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del event, context
    raise HandlerNotActiveError("THN invalidation is not active")
