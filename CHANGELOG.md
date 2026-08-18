# Changelog

This project adheres to [Semantic Versioning](https://semver.org/).

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
