"""Public CLI facade and composition root for the forensic agent."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, cast

from rich.console import Console
from rich.markup import escape

import forensic_agent.cli.i18n as _i18n
import forensic_agent.cli.model_catalog_view as _model_catalog_view
import forensic_agent.cli.reasoning as _reasoning
import forensic_agent.cli.terminal as _terminal
from forensic_agent.cli.session import (
    INTERACTIVE_MODEL,
    InteractiveSession,
)
from forensic_agent.cli.setup import (
    ProviderConfiguration,
    SetupCancelled,
    SetupError,
    configuration_ready,
    run_setup,
    validate_saved_configuration,
)
from forensic_agent.core.environ import (
    ProviderEndpointError,
    backend_kind,
    backend_status,
    configured_backend,
    validate_local_endpoint_value,
    validate_openrouter_endpoint_value,
)
from forensic_agent.core.telemetry_egress import (
    describe_neutralised,
    neutralised_telemetry_variables,
)


class _Reconfigurable(Protocol):
    def reconfigure(self, *, encoding: str, errors: str) -> None: ...


for _stream in (sys.stdout, sys.stderr):
    try:
        cast(_Reconfigurable, _stream).reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


console = Console(highlight=False, color_system="truecolor")
_PUBLIC_COMMANDS = frozenset({"doctor", "ask", "models", "setup", "tui"})
SESSION_STARTUP_FAILURE_EXIT_CODE = 78

#: The run examined the evidence, closed its record cleanly, and published no
#: finding. Its own code, because it is not a failure of this program and a
#: harness has to be able to tell the two apart without reading the transcript:
#: "the weaker model spent its time budget" is a measurement, and rc 1 beside a
#: crash makes it unrecordable. 1 stays what it has always been, everything that
#: went wrong, and the two codes the launcher reads (75, 78) are untouched.
UNPUBLISHED_ANSWER_EXIT_CODE = 79


def _normalize_case_shortcut(arguments: list[str]) -> list[str]:
    """Expand ``dfir-agent PATH`` to the regular console case arguments.

    ``dfir-agent /case PATH`` is honoured too: the console teaches /case as
    THE way to open evidence, and the muscle memory that types it at the
    shell prompt deserves the case, not an argparse error.
    """

    if not arguments:
        return arguments
    if arguments[0].casefold() == "/case":
        arguments = ["tui", *(["--case", arguments[1]] if len(arguments) > 1 else []), *arguments[2:]]
        return arguments
    candidate = arguments[0]
    if candidate.startswith("-") or candidate.casefold() in _PUBLIC_COMMANDS:
        return arguments
    if Path(candidate).expanduser().exists():
        return ["tui", "--case", candidate, *arguments[1:]]
    return arguments


def _default_run_dir(
    *,
    platform_name: str | None = None,
    environment: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> str:
    """Return a durable per-user state directory on Windows and POSIX."""

    env = os.environ if environment is None else environment
    configured = env.get("DFA_RUNS_DIR")
    if configured:
        return _terminal.resolved_cli_path(configured)

    platform_name = os.name if platform_name is None else platform_name
    home = Path.home() if home is None else home
    if platform_name == "nt":
        base = Path(env.get("LOCALAPPDATA") or home / "AppData" / "Local")
    else:
        base = Path(env.get("XDG_STATE_HOME") or home / ".local" / "state")
    return str((base / "dfir-agent").expanduser().resolve())


class Session(InteractiveSession):
    """Public interactive session with the facade console injected explicitly."""

    def __init__(self, args) -> None:
        super().__init__(args, console=console)


def list_backend_models(base_url: str, api_key: str | None = None) -> list[str]:
    """List models from the configured backend without trying another endpoint."""
    return cast(list[str], backend_status(base_url, api_key=api_key).get("models", []))


def render_doctor(model, base_url, api_key=None) -> bool:
    """Render the environment preflight through the patchable facade console."""
    return _terminal.render_doctor(model, base_url, api_key, console=console)


def _validated_backend(
    base_url: str,
    api_key: str | None,
    *,
    require_openrouter_key: bool = True,
) -> tuple[str, str]:
    """Validate the destination before any provider request can use a credential."""

    if backend_kind(base_url) == "ollama":
        return validate_local_endpoint_value(base_url), "ollama"
    validation_key = api_key if require_openrouter_key else (api_key or "endpoint-check")
    validated = validate_openrouter_endpoint_value(base_url, validation_key)
    if require_openrouter_key:
        assert isinstance(api_key, str)
        return validated, api_key
    return validated, api_key or ""


def _apply_provider_to_args(args, configuration: ProviderConfiguration) -> None:
    """Make a newly saved provider immediately active in this process."""

    args.base_url = configuration.base_url
    args.api_key = configuration.api_key
    args.model = configuration.model



def _quieten_transport_logs() -> None:
    """Keep the HTTP client's own chatter out of the investigation transcript.

    httpx logs one INFO line per request, and something in the forensic stack
    configures the root logger, so every model call printed a line naming the
    endpoint in the middle of the operator's session.  It says nothing about the
    evidence and nothing the run record does not already hold: the oversight
    chain is where a request belongs.  Raised to WARNING rather than disabled,
    so a transport failure still reaches the operator.
    """

    import logging

    for name in ("httpx", "httpcore", "openai", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)


def main() -> None:
    """Parse CLI options and run one interactive forensic session."""

    _quieten_transport_logs()
    # Sealing happened at package import, long before this frame; saying so
    # here is what makes it visible.  A channel closed without a word leaves
    # the operator unable to tell a run that was never at risk from one that
    # was, and both look identical in the output.
    neutralised = neutralised_telemetry_variables()
    if neutralised:
        Console(stderr=True).print(f"[yellow]{escape(describe_neutralised(neutralised))}[/]")
    _run_cli()


def _run_cli() -> None:
    """Parse CLI options and run one interactive forensic session."""
    default_base_url, default_api_key = configured_backend()
    parser = _terminal.build_parser(
        interactive_model=INTERACTIVE_MODEL,
        default_base_url=default_base_url,
        default_api_key=default_api_key,
        default_run_dir=_default_run_dir(),
    )
    args = parser.parse_args(_normalize_case_shortcut(sys.argv[1:]))

    # Open the console in the language the operator last chose, so the banner and
    # every prompt from here on render in it. Presentation only: this never
    # reaches the model surface.
    _i18n.set_language(_i18n.load_saved_language())

    # Open with the reasoning effort the operator last chose, so a console they
    # left on a cheap setting does not silently go back to spending minutes per
    # question. Unset means the effort the console has always used.
    _reasoning.set_effort(_reasoning.load_saved_effort())

    # The demo console needs no provider, Docker, or evidence: it replays a
    # recorded case. Handle it before any configuration gating so a reviewer can
    # launch it on a bare checkout.
    if args.command == "tui" and getattr(args, "demo", False):
        from forensic_agent.tui import run_demo_tui

        run_demo_tui()
        return

    if args.command == "setup":
        try:
            configuration = run_setup(console=console)
        except SetupCancelled:
            console.print("[dim]Setup cancelled; configuration was not changed.[/]")
            return
        except (SetupError, KeyboardInterrupt, EOFError) as exc:
            parser.error(str(exc) or "setup was cancelled")
        _apply_provider_to_args(args, configuration)
        return

    if args.command == "ask" and (
        not isinstance(args.question, str) or not args.question.strip()
    ):
        parser.error("ask requires --question")
    if args.command != "ask" and args.question is not None:
        parser.error("--question can only be used with ask")

    if args.command == "models":
        try:
            args.base_url, args.api_key = _validated_backend(
                args.base_url,
                args.api_key,
                require_openrouter_key=False,
            )
        except ProviderEndpointError as exc:
            parser.error(str(exc))
        # One listing, drawn by the view the interactive /model list uses, so
        # the command line and the console never describe the same catalogue
        # two different ways. The view handles both backends, the refusal
        # section, the bound and the language layer, and reports an empty or
        # unreachable provider in its own words rather than through an exit code.
        selected_model = args.model or os.environ.get("DFA_MODEL") or INTERACTIVE_MODEL
        _model_catalog_view.show_model_catalog(
            console,
            "",
            model=selected_model,
            base_url=args.base_url,
            api_key=args.api_key,
        )
        return

    if args.command == "doctor":
        args.doctor = True

    if args.doctor:
        # A local backend with no explicitly selected model must not be checked
        # against the OpenRouter default; the models command presents the choice.
        try:
            args.base_url, args.api_key = _validated_backend(
                args.base_url,
                args.api_key,
                require_openrouter_key=False,
            )
        except ProviderEndpointError as exc:
            parser.error(str(exc))

        configured_model = args.model or os.environ.get("DFA_MODEL")
        if configured_model:
            checked_model = configured_model
        elif backend_kind(args.base_url) == "ollama":
            checked_model = None
        else:
            checked_model = INTERACTIVE_MODEL
        ready = render_doctor(checked_model, args.base_url, args.api_key)
        if not ready:
            raise SystemExit(1)
        return

    selected_model = args.model or os.environ.get("DFA_MODEL")
    needs_setup = not configuration_ready(
        args.base_url,
        args.api_key,
        selected_model,
    )
    if not needs_setup and args.command == "tui" and sys.stdin.isatty():
        try:
            validated = validate_saved_configuration(
                base_url=args.base_url,
                api_key=args.api_key,
                model=selected_model,
            )
        except SetupError as exc:
            console.print(
                "[yellow]Saved model configuration is not usable:[/] "
                f"{escape(str(exc))}"
            )
            console.print(
                "[dim]Provider setup will open so you can repair it "
                "before an investigation starts.[/]"
            )
            needs_setup = True
        else:
            _apply_provider_to_args(args, validated)

    if needs_setup:
        if not sys.stdin.isatty():
            parser.error(
                "no model provider is configured; run dfir-agent setup "
                "in an interactive terminal"
            )
        try:
            configuration = run_setup(console=console)
        except SetupCancelled:
            console.print("[dim]Setup cancelled; no investigation was started.[/]")
            return
        except (SetupError, KeyboardInterrupt, EOFError) as exc:
            parser.error(str(exc) or "setup was cancelled")
        _apply_provider_to_args(args, configuration)

    if args.command == "ask":
        try:
            session = Session(args)
        except Exception as exc:
            console.print(f"[bold red]Agent startup failed:[/] {escape(str(exc))}")
            raise SystemExit(SESSION_STARTUP_FAILURE_EXIT_CODE) from exc
        try:
            assert isinstance(args.question, str)
            completed = session.ask(args.question.strip())
        finally:
            session.close()
        if completed is False:
            # Read after close on purpose: closing detaches evidence and touches
            # nothing about what the question did, and the outcome has to
            # survive the teardown that always runs.
            outcome = getattr(session, "last_ask_outcome", "")
            raise SystemExit(
                UNPUBLISHED_ANSWER_EXIT_CODE
                if outcome == Session.ASK_UNPUBLISHED
                else 1
            )
        return

    # The console is the interface: every remaining launch — bare, --case, or
    # an explicit tui — opens the full-screen investigation console. The line
    # shell it replaced no longer exists.
    from forensic_agent.tui import run_live_tui

    try:
        run_live_tui(args, console=console)
    except Exception as exc:
        console.print(f"[bold red]Agent startup failed:[/] {escape(str(exc))}")
        raise SystemExit(SESSION_STARTUP_FAILURE_EXIT_CODE) from exc


if __name__ == "__main__":
    main()
