"""Say a provider failure in the words the console already uses.

A router error arrives as a nested machine-readable object.  Printed as it
came, it tells the operator that something numbered 400 happened somewhere and
nothing about what to do next; the interesting part — which provider refused,
what it said, and whether the request had already been moved off another one —
is inside it, and is exactly what an operator acts on.

This module renders that, and only that.  The full object stays where the run
keeps it: the transport writes the router's whole account to the oversight
chain, so nothing shown here is the only copy of anything.
"""

from __future__ import annotations

from rich.markup import escape

from forensic_agent.agent.provider_failure import ProviderFailure, describe_provider_failure
from forensic_agent.cli.i18n import t as _t
from forensic_agent.cli.terminal import ACCENT, DIM, GLYPH_POINT, GLYPH_WARN, ORANGE


def _headline(failure: ProviderFailure) -> str:
    """Name what happened, from the status the provider itself returned."""

    if failure.rejected_after_provider_swap:
        return _t("This request was sent to a second provider, which would not accept it.")
    status = failure.status_code
    if status == 429:
        return _t("The model provider is rate limiting these requests.")
    if status is not None and 500 <= status < 600:
        return _t("The model provider failed while answering this request.")
    return _t("The model provider rejected this request.")


def _attribution(failure: ProviderFailure) -> str | None:
    """One line naming the provider, its status, and its own sentence."""

    parts: list[str] = []
    if failure.provider_name:
        parts.append(f"[bold]{escape(failure.provider_name)}[/]")
    if failure.status_code is not None:
        parts.append(f"[{DIM}]HTTP {failure.status_code}[/]")
    # The upstream sentence is preferred over the router's own, which says only
    # that a provider returned an error — a fact the status code already carries.
    detail = failure.upstream_detail or failure.message
    if detail:
        parts.append(escape(detail))
    if not parts:
        return None
    separator = ", "
    return f"  [{DIM}]{_t('provider')}[/] " + separator.join(parts)


def _origin(failure: ProviderFailure) -> str | None:
    """The endpoint the request was moved off, when there was one."""

    swapped_from = failure.swapped_from
    if swapped_from is None or not swapped_from.provider_name:
        return None
    status = (
        f" [{DIM}](HTTP {swapped_from.status_code})[/]"
        if swapped_from.status_code is not None
        else ""
    )
    return (
        f"  [{DIM}]{_t('first tried')}[/] "
        f"{escape(swapped_from.provider_name)}{status}"
    )


def _options(failure: ProviderFailure) -> str:
    """What the operator can actually do about it, in this console's terms."""

    hint = (
        f"[{DIM}]{GLYPH_POINT} {_t('Ask again, or use')}[/] "
        f"[{ACCENT}]/model <model-id>[/] "
        f"[{DIM}]{_t('to pick another model.')}[/]"
    )
    # Only when rate limiting is what the operator is actually waiting on: after
    # a swap it is the provider the request was moved OFF that was throttled.
    swapped_from = failure.swapped_from
    rate_limited = failure.status_code == 429 or (
        swapped_from is not None and swapped_from.status_code == 429
    )
    if rate_limited:
        hint += f" [{DIM}]{_t('Rate limits clear on their own.')}[/]"
    return hint


def provider_failure_notice(error: BaseException) -> str | None:
    """Render one failed model request, or nothing if it was not the provider's.

    ``None`` means this exception carries no router account of a provider
    outcome, so the caller keeps whatever it already prints for it.
    """

    failure = describe_provider_failure(error)
    if failure is None:
        return None
    lines = [
        f"[{ORANGE}]{GLYPH_WARN} {_headline(failure)}[/]",
        _attribution(failure),
        _origin(failure),
        _options(failure),
    ]
    return "\n".join(line for line in lines if line is not None)
