# Security policy

## Supported version

Security fixes target the latest tagged version and the current release branch.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub Security Advisories or directly
to the repository owner. Do not open a public issue containing:

* credentials, API keys, internal paths, or personal data;
* content from a forensic source;
* an oversight-layer bypass;
* a method for modifying evidence or executing evidence content.

Include the affected version or commit, minimal reproduction steps, expected and
observed behavior, and an impact assessment. Use synthetic data whenever
possible.

## Security scope

High-impact findings include path-boundary escapes, arbitrary command
execution, credential disclosure, evidence modification, tampering with the
`audit.jsonl` record, and publication of claims that are not linked to recorded
forensic findings.

DFIR Agent does not guarantee legal admissibility. A qualified examiner remains
responsible for verification and the final professional conclusion.
