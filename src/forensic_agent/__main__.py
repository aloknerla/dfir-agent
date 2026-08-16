"""Package entry point for ``python -m forensic_agent``."""


def main() -> None:
    """Delegate to the single console entry-point implementation."""
    from forensic_agent.cli import main as cli_main

    cli_main()


if __name__ == "__main__":  # pragma: no cover - executed by Python's module runner
    main()
