# Test suite

Unit and behaviour tests for the kept surface of `forensic_agent`. The suite is
offline and hermetic: it binds no real evidence image, spawns no external
forensic binary, and reads only what each test sets for itself. Tests that need
an optional native library (a MIME classifier, a Public Suffix List reader) skip
cleanly when it is absent rather than fail.

## Running

From the repository root:

```
PYTHONPATH=src pytest -q
```

`pytest` reads `testpaths`, `pythonpath`, and `addopts` from `pyproject.toml`, so
a bare `pytest` also works once the package's dependencies are installed
(`pip install -e ".[dev]"`).

## Coverage by subsystem

- **core** — evidence source and probing, controlled scratch, configuration and
  backend selection, the tool-result and result-contract formats, result reading,
  audit hashing, reproducibility, and telemetry egress.
- **oversight** — policy scope and enforcement over synthetic calls, the argument
  contract gate, call accounting, and module boundaries.
- **agent** — tool contracts and per-operation argument validation, domain-facade
  dispatch, identifier grounding, lineage resolution, evidence classification and
  regions, structured-answer assembly, and the model-result envelope.
- **tools** — pure-logic helpers that do not shell out: the hardware-vendor and
  public-suffix lookups, offset attribution, and payload identification.
- **cli** — command listing, presentation, progress rendering, terminal theming,
  and localisation.

Fixtures are synthetic. No test embeds a real case's evidence or ground-truth
answer.
