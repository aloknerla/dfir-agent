"""Read OpenRouter's own account of a request that no provider answered.

A router that fails over reports more than one outcome for one request: the
provider that finally answered, and, beside it, every provider it tried first.
That list is the only place a run can learn that its request was moved, and it
arrives in two different shapes.  Recognising both here, once and structurally,
is what lets the transport decide and the terminal explain without either of
them parsing prose.

Nothing in this module interprets the provider's WORDING.  ``code`` and the
``previous_errors`` chain are machine-readable fields; a decision built on them
cannot be widened by a provider changing how it phrases a rejection.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

#: Statuses with which an endpoint declines to SERVE a request instead of
#: judging it: busy, timed out, or broken.  None of them is a statement about
#: the body, which is exactly what makes them the discriminator below — a
#: provider that answered one of these never read the parameters it is being
#: used to excuse.
_UNAVAILABLE_STATUS_CODES = frozenset({408, 425, 429})

#: How much of a provider's own wording is worth carrying.  Long enough for a
#: sentence an operator can act on, short enough that no record and no terminal
#: line becomes a dump of an upstream body.
_DETAIL_LIMIT = 200


@dataclass(frozen=True)
class ProviderAttempt:
    """One upstream provider's outcome for a request the router placed."""

    provider_name: str | None
    status_code: int | None
    message: str | None

    @property
    def was_unavailable(self) -> bool:
        """Whether this provider declined to serve rather than to accept.

        A 5xx is included by range: every one of them says the endpoint failed,
        and none of them says anything about the request that reached it.
        """

        status = self.status_code
        if status is None:
            return False
        return status in _UNAVAILABLE_STATUS_CODES or 500 <= status < 600

    @property
    def rejected_the_request(self) -> bool:
        """Whether this provider read the body and refused it on its merits."""

        status = self.status_code
        return status is not None and 400 <= status < 500 and not self.was_unavailable


@dataclass(frozen=True)
class ProviderFailure:
    """What the router reported about one request, normalized.

    ``previous_attempts`` is in the router's own order: the providers it tried
    before the one whose outcome the run actually received.
    """

    status_code: int | None
    provider_name: str | None
    message: str
    upstream_detail: str | None
    previous_attempts: tuple[ProviderAttempt, ...]

    @property
    def swapped_from(self) -> ProviderAttempt | None:
        """The unavailable provider this request was moved off, if any.

        Only a rejection that follows such a move can be about WHERE the request
        went.  Three conditions have to hold together, and each one is load
        bearing:

        * this outcome is a 400 — the provider read the body and refused it;
        * a different provider was tried first and was merely unavailable, so
          nothing has yet judged this body;
        * no provider that did judge it rejected it.  Two independent providers
          refusing the same body is a bad request, and a bad request must
          surface rather than be re-sent at a third.
        """

        if self.status_code != 400 or not self.provider_name:
            return None
        if any(attempt.rejected_the_request for attempt in self.previous_attempts):
            return None
        return next(
            (
                attempt
                for attempt in self.previous_attempts
                if attempt.was_unavailable
                and attempt.provider_name
                and attempt.provider_name != self.provider_name
            ),
            None,
        )

    @property
    def rejected_after_provider_swap(self) -> bool:
        """Whether a second provider refused a body the first never judged."""

        return self.swapped_from is not None


def _as_error_mapping(value: object) -> Mapping[str, Any] | None:
    """Return the error object inside one candidate, unwrapping ``{"error": …}``."""

    if not isinstance(value, Mapping):
        return None
    nested = value.get("error")
    if isinstance(nested, Mapping):
        return nested
    if "message" in value or "code" in value:
        return value
    return None


def _error_object(error: BaseException) -> Mapping[str, Any] | None:
    """Find the router's error object on either exception shape.

    An HTTP-level rejection reaches the run as an OpenAI SDK status error whose
    ``body`` is the parsed response.  A rejection the router reports inside a
    200 response reaches it as a plain exception carrying that same object as
    its only argument, because ``langchain-openai`` raises the ``error`` member
    of a body it cannot read as a completion.  Both are the same fact.
    """

    candidates = (getattr(error, "body", None), *getattr(error, "args", ()))
    return next(
        (mapping for mapping in map(_as_error_mapping, candidates) if mapping is not None),
        None,
    )


def _status_code(value: object) -> int | None:
    """Read an HTTP status from a field providers spell as int or as digits."""

    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _text(value: object) -> str | None:
    """Return a non-empty, bounded string, or nothing at all."""

    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    return trimmed[:_DETAIL_LIMIT] if trimmed else None


def _upstream_detail(raw: object) -> str | None:
    """Lift the upstream provider's own sentence out of its verbatim body.

    ``metadata.raw`` is the bytes the provider returned, which the router passes
    through undecoded.  The sentence inside it is the only part that tells an
    operator anything ("invalid request params"); the envelope around it repeats
    a status the record already holds.  A body that is not JSON is kept as it
    came, because then the envelope IS the sentence.
    """

    text = _text(raw)
    if text is None:
        return None
    try:
        decoded = json.loads(text)
    except ValueError:
        return text
    return _sentence(decoded) or text


def _sentence(decoded: object, *, depth: int = 2) -> str | None:
    """Find the human sentence inside a decoded upstream body.

    Providers nest it one level as often as not (``{"error": {"message": …}}``),
    so a single pass over the top-level fields finds nothing and the whole
    envelope gets shown instead.  The descent is bounded rather than general: it
    is looking for a sentence, not walking a document.
    """

    if not isinstance(decoded, Mapping):
        return None
    for field in ("msg", "message", "detail", "error"):
        value = decoded.get(field)
        sentence = _text(value)
        if sentence is not None:
            return sentence
        if depth > 0:
            nested = _sentence(value, depth=depth - 1)
            if nested is not None:
                return nested
    return None


def _attempt(fields: Mapping[str, Any]) -> ProviderAttempt:
    metadata = fields.get("metadata")
    return ProviderAttempt(
        provider_name=_text(
            fields.get("provider_name")
            or (metadata.get("provider_name") if isinstance(metadata, Mapping) else None)
        ),
        status_code=_status_code(fields.get("code")),
        message=_text(fields.get("message")),
    )


def describe_provider_failure(error: BaseException) -> ProviderFailure | None:
    """Normalize a failed model request into what the router said about it.

    Returns ``None`` for anything that is not a router-reported provider
    outcome — a timeout, a transport fault, a bug in this process — so every
    caller keeps treating those exactly as it did before.
    """

    fields = _error_object(error)
    if fields is None:
        return None
    metadata = fields.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    message = _text(fields.get("message")) or ""
    status = _status_code(fields.get("code"))
    if status is None:
        status = _status_code(getattr(error, "status_code", None))
    if not message and status is None:
        return None
    previous = metadata.get("previous_errors")
    return ProviderFailure(
        status_code=status,
        provider_name=_text(metadata.get("provider_name")),
        message=message,
        upstream_detail=_upstream_detail(metadata.get("raw")),
        previous_attempts=tuple(
            _attempt(item)
            for item in (previous if isinstance(previous, list) else ())
            if isinstance(item, Mapping)
        ),
    )
