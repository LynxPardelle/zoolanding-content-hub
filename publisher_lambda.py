"""Dormant, isolated entrypoint for THN publication."""

from __future__ import annotations

from typing import Any


class HandlerNotActiveError(RuntimeError):
    """The reviewed publication contract is not installed."""


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del event, context
    raise HandlerNotActiveError("THN publication is not active")
