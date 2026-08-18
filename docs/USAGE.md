# Using the console

DFIR Agent is operated from an interactive terminal console. This page describes
how to start it and the commands it accepts. For the design behind the console —
the oversight gate, the evidence lifecycle, and the answer path — see
[Architecture](ARCHITECTURE.md).

## Starting the console

```bash
dfir-agent
```

At first launch, choose a model provider and enter its credentials through a
hidden prompt. The credentials are stored in the local configuration directory,
never in the evidence directory. Two non-interactive subcommands help with setup:

```bash
dfir-agent setup     # configure OpenRouter or a local Ollama model
dfir-agent doctor    # check the model connection and forensic dependencies
```

## Asking a question

Load a case first, then type a question in ordinary language. A line that does not
begin with `/` is treated as an investigation question and is refused if no
evidence is loaded. The console prints the answer together with an evidence
summary and a control panel, so the analytical path behind an answer is visible
alongside it.

## Commands

Type `/` to open the command menu. `/help` lists everything; `/help <command>`
shows one command in detail. Commands are grouped by purpose.

### General

| Command | Purpose |
|---|---|
| `/help [command]` | Show all commands or detailed help for one command. |
| `/status` | Show the active model, case, evidence sources, and tools. |
| `/clear [all]` | Clear the terminal without changing the investigation; `all` also drops the status panel. |
| `/layout [simple\|full]` | Switch between the full layout and a simple one-column view. Bare `/layout` opens the chooser, which names both; the active one is shown in the Session panel. |
| `/quit` | Close the terminal; the investigation history is saved automatically. |

### Case and evidence

| Command | Purpose |
|---|---|
| `/case [disk\|memory\|network] <path>` | Open a case directory, evidence file, or explicitly typed RAW source. |
| `/attach <disk\|memory\|network> <path>` | Attach another evidence source to the active case. |
| `/sources` | Show every evidence source currently attached to the case. |
| `/context [show\|set <text>\|load <path>\|clear]` | Show or manage the non-evidentiary case brief. |

Evidence is always opened read-only. Opening a host path outside the active
evidence root requires one host-side approval before it becomes visible to the
console.

### Investigation

| Command | Purpose |
|---|---|
| `/tools [name]` | List active tools with their operation count and external backing, or show one function's full detail. |
| `/findings [id]` | List the standardized findings, or describe one of them by its listing id. |
| `/oversight [n\|calls\|prompt]` (alias `/guardrails`) | Account for every tool call: how many ran, how many were refused and by which layer. `n` shows one call whole; `calls` lists executed commands with full arguments; `prompt` shows the message sent to the model. |
| `/retry` | Run the most recent investigation question again. |
| `/export [n\|path]` | Write the investigation report: every question this history retains, one question by its position with `n`, or the most recent question's report to a path. Nothing is closed and no evidence is detached. |
| `/complete [path]` | Close the case: after a confirmation, write the full case report, the investigation diagram, and the completion record, then detach the evidence sources. |

A refusal by the oversight policy and a refusal by the tool are counted apart,
because only the first is the gate stopping a call.

### Session

| Command | Purpose |
|---|---|
| `/new [name]` (alias `/reset`) | Start a new investigation history for the active case, and clear the previous messages, tool activity and guardrail decisions off the screen with it. The case, its evidence, the run record and the findings survive. |
| `/history [limit]` | Show previous questions and answers in this investigation. |
| `/undo` | Exclude the latest answer from future model context. |
| `/resume [id]` | Open a saved investigation and put it back on screen. With no id it opens the picker. `/sessions` is the same command. |
| `/continue` | Continue the previous investigation and reopen its evidence. |

### System

| Command | Purpose |
|---|---|
| `/setup` | Configure OpenRouter or a local Ollama model. |
| `/model [list [all\|<text>]\|<model-id>]` | Show the active model, list what the backend offers, or switch to one by id. |
| `/doctor` | Check the model connection and forensic dependencies. |
| `/language [en\|hr]` | Show or switch the terminal language (English or Croatian). |
| `/theme [name]` | Show or switch the console colour theme; bare `/theme` lists the shipped themes and marks the active one, and the choice is kept for the next launch. |
| `/reasoning [none\|low\|medium\|high]` | Show or set how much reasoning the model spends per request. Bare `/reasoning` opens the level chooser and marks the active one; a level sets it for the next question. The `DFA_REASONING_EFFORT` environment variable sets the same level for a non-interactive run. |
| `/budget [time S\|steps N\|toolcalls N]` | Show and set the limits one question may spend: the wall clock in seconds, the investigation steps and the tool calls. Bare `/budget` opens the screen; `time 600`, `steps 30` or `toolcalls 30` sets one directly. Each is a whole number of at least 1, applies to the next question, and is kept for the next launch. |
