# Documentation

This directory documents the design of DFIR Agent: a language model bound to a
closed set of vetted forensic tools, with a deterministic oversight layer that
validates every action and a record of the whole run in `audit.jsonl`,
hash-chained so later modification is detectable.

## Recommended reading order

1. [Architecture overview](ARCHITECTURE_OVERVIEW.md) — what the system is and, on
   one page, what stops it asserting something the evidence does not support. Names
   the file and function that enforces each answer.
2. [Architecture](ARCHITECTURE.md) — the high-level architecture, the layer
   diagram, and the end-to-end evidence lifecycle.
3. [Architecture detail](ARCHITECTURE_DETAIL.md) — the maintainer's view: the
   execution path in order, from keystroke to published answer, with call-flow and
   layer diagrams.
4. [Usage](USAGE.md) — how to start the console and the `/` commands it accepts.

## Figures

Diagram sources rendered in the documents above live in [`figures/`](figures/).
