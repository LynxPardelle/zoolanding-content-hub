"""Dormant, isolated entrypoint for THN prepared-orphan collection."""

from __future__ import annotations

from typing import Any


class HandlerNotActiveError(RuntimeError):
    """The reviewed prepared-orphan collection contract is not installed."""


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del event, context
    raise HandlerNotActiveError("THN prepared-orphan collection is not active")
