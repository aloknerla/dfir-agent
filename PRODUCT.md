# Product direction

## Product name

DFIR Agent

## Intended users

DFIR Agent is designed for digital forensic examiners, incident-response
analysts, security researchers, and students. They work with disk images,
memory captures, network traffic, and derived artifacts, and need to
understand both the answer and the analytical path that produced it.

## Purpose

The system demonstrates how a large language model can assist a forensic
investigation without receiving unrestricted access to evidence or the host
workstation. The investigator opens a case and asks questions in natural
language. The model plans the next analytical action, while deterministic
components validate calls, execute forensic analyzers, normalize findings, and
maintain the execution record.

Success means that an investigation is understandable, repeatable, and
reviewable by a qualified examiner. It does not mean that the model replaces
the examiner or that fluent output is accepted without supporting evidence.

## Product character

The interface should be calm, technical, and evidence-oriented. Trust should
come from clear state, visible analytical actions, explicit limitations, and
traceable findings rather than visual spectacle or anthropomorphic behavior.

## Design principles

1. Show the active case context before agent activity and the final answer.
2. Make every important claim traceable to a recorded forensic finding.
3. Keep the default view readable while making technical depth available on
   demand.
4. Display errors, incomplete coverage, and failed verification explicitly.
5. Keep evidence access read-only and isolate temporary analytical work.
6. Preserve keyboard operation and readable output in light and dark terminals.

## Product boundaries

DFIR Agent must not present private chain-of-thought reasoning, execute evidence
content, expose a general-purpose shell to the model, or imply certainty that
the recorded findings do not support.

The application supports OpenRouter and local Ollama providers.
