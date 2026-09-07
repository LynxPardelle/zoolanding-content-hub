"""Dormant, isolated entrypoint for THN private-asset collection."""

from __future__ import annotations

from typing import Any


class HandlerNotActiveError(RuntimeError):
    """The reviewed private-asset collection contract is not installed."""


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del event, context
    raise HandlerNotActiveError("THN private-asset collection is not active")
