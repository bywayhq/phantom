"""Decisions made before sending a redirect hop."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import TypeAlias


class RedirectDecision(Enum):
    """Follow, return the unread redirect response, or fail the request."""

    FOLLOW = "follow"
    STOP = "stop"
    REJECT = "reject"


@dataclass(frozen=True)
class RedirectAttempt:
    """A resolved URL proposal, before DNS or the next HTTP attempt.

    Hop numbers start at one. URLs can contain secrets and are omitted from repr.
    next_method includes the redirect's proposed method rewrite.
    """

    from_url: str = field(repr=False)
    to_url: str = field(repr=False)
    status: int
    method: str
    next_method: str
    hop: int


RedirectCallback: TypeAlias = Callable[[RedirectAttempt], RedirectDecision]
AsyncRedirectCallback: TypeAlias = Callable[
    [RedirectAttempt], RedirectDecision | Awaitable[RedirectDecision]
]
