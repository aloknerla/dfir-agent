# Changelog

This project adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- `/budget time <seconds>` sets the per-question wall clock from the console,
  and the `/budget` screen shows it beside the step and tool-call rows as a
  duration. The limit was previously reachable only by relaunching, so a run
  that ended with `budget_exhausted:max_wall_time_s` could not be given more
  time. The value applies to the next question and is kept for the next launch.

### Changed

- **Breaking (console commands):** `/effort` is split into `/reasoning` and
  `/budget`, and is not kept as an alias of either. `/reasoning
  [none|low|medium|high]` sets only the model's reasoning level; `/budget
  [time S|steps N|toolcalls N]` holds only the resource ceilings and shows
  nothing about reasoning. This reverses the earlier merge of `/reasoning` and
  `/budget` into `/effort`: the reasoning level is a property of how the model
  thinks and travels to the provider, while the budgets are limits this console
  places on a run and end it with no finding when they are reached.
  `/steps` and `/toolcalls` remain arguments of `/budget` rather than commands.
- The `DFA_REASONING_EFFORT` environment variable is unchanged.

## 0.1.0 — Initial public release

First public release of DFIR Agent: an investigation assistant for digital
forensics and incident response in which a language model plans the investigation
while a deterministic layer controls tool execution, reads forensic sources
through vetted open-source tools, standardizes results into findings, enforces an
oversight policy on every proposed action, and records every tool call and its
result in `audit.jsonl`, hash-chained so later modification is detectable.

Includes:

- interactive terminal console for multi-question case investigation;
- deterministic forensic wrappers exposed to the model through structured tool
  schemas, backed by established open-source analyzers;
- an oversight layer enforcing capability, argument, path, and budget checks on
  every call;
- standardized findings carrying provenance and coverage metadata, bound to an
  append-only hash chain;
- answer verification, bounded deterministic recovery, persistent sessions, and
  SVG execution traces.
