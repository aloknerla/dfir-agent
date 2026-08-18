# DFIR-AGENT — Investigation Console (Textual TUI)

A calm, full-screen **Textual** front-end for the DFIR agent — the
interface. The line shell it replaced no longer exists: bare ``dfir-agent``
opens this console, and every registry command works here. It is a
**presentation layer only**: it wraps the existing `InteractiveSession` /
`ControlledInvestigationSession` and re-presents a real `ControlledRun`. No
forensic logic is re-implemented, and the frozen core code is left untouched.

---

## Running it

```bash
# Recorded, stubbed case — needs no Docker, no evidence image, no model.
# The mode to use for a first look, no evidence and no model required.
dfir-agent tui --demo

# Live case — bare dfir-agent also opens the console; a path is a case.
dfir-agent tui --case D:\Cases\case-2026-0731-laptop
dfir-agent D:\Cases\case-2026-0731-laptop
```

`tui` is a subcommand of the existing `dfir-agent` entry point. Demo mode is
handled before any provider gating, so it launches on a bare checkout.
**Requires** `textual` (declared under the optional `tui` extra in
`pyproject.toml`; already installed here). Nothing else was added.

---

## Design rationale — *constraint breeds clarity*

The console keeps the original dashboard's structure — a standing status
frame, the conversation beside live instruments — but strips the jargon that
made the first cut overwhelming (`req›granted`, `net›DENIED`, receipt and
risk columns) and keeps the plain-language naming pass below:

- **The conversation is chat, and only chat.** Messages and answers — nothing
  else lands there. The instruments accumulate instead: ACTIVITY and FINDINGS
  keep every run's rows in their scrollback, separated by a dim exchange
  number, so a new question never erases what an earlier one produced.
- **The conversation is a real chat.** The line CLI's gradient banner (which
  re-renders on resize, growing through DFIR, full-width and double-scale
  tiers) and Session panel open it; the operator's messages sit in compact
  right-aligned bubbles, the agent's answers in left-aligned panels whose
  border colour carries the verdict — no sender labels, the sides say who is
  speaking. While a run is in flight an animated line right under the
  message names the call in progress with its arguments and elapsed time,
  like a typing indicator.
- **The instruments live on the right, each answering a different question.**
  Typing `/` opens the command palette; a pick runs at once — only commands
  that require an argument land in the prompt together with their exact
  usage line, so the correct shape is shown before typing, never through an
  error. Command output (status, sources, tools, findings, oversight, trace,
  history…) opens as popups — the
  conversation is never touched. ACTIVITY — *what is the agent doing?* — streams every tool
  call as it runs:
  the exact `function.operation` with its duration, the complete arguments
  wrapping beneath (in live mode the full argument list, not a clipped
  summary), and — once the run settles — a `› read …` line stating what the
  call actually covered, which names the registry scope even for plugin
  operations whose arguments carry no path. Every exchange opens a numbered
  group (`01 ──`), and the digit keys 1–9 jump the feed to that exchange. FINDINGS — *what has the operator accepted?* — after each answer the
  conversation offers `v` to review the run's findings one by one in a
  full-screen sheet: the result, the complete command in one line, the
  coverage, the recorded records themselves (in live mode, straight from the
  run's tool-result trace) and the full provenance receipt; `y` accepts, `n`
  rejects. Only accepted findings enter the pane — marked with a single ★ —
  and `m` removes one. The tool never decides what counts as evidence.
  GUARDRAILS — *what may it do?* — the granted authority once, then one
  row per denial, grouped per message; clicking a row unfolds the exact
  arguments, the wanted capabilities and every recorded reason.
- **Full command replacement.** Every registry command has a real in-console
  form. `/case` with no argument opens a folder browser (a path field over a
  `DirectoryTree`); with a path it opens evidence at runtime, including the
  multi-source selection resolved through choice modals. `/attach` asks what
  kind of evidence it is, then browses for the file. Bare `/context` opens
  the case-brief screen (current text plus a rewrite box; `Ctrl+X` clears).
  `/sessions` and bare `/resume` list the saved investigations — `Enter`
  resumes one; `/continue` takes up the previous investigation and reopens
  its evidence. `/retry` re-sends the previous message through the normal
  pipeline. `/setup` walks provider configuration behind modal prompts
  (choice → model → masked key → live probe) and applies it without
  detaching evidence; `/model list` is a picker over the live catalogue —
  `Enter` switches; `/model <id>` switches directly. `/effort` is the one
  surface for how much work a message may spend: pick a row and `Enter`
  edits the steps, the tool calls or the reasoning effort in place
  (`/effort high` sets the level, and `/effort steps 30` or
  `/effort toolcalls 30` sets a limit directly; there are no separate
  `/steps` and `/toolcalls` commands); everything goes through the session's
  own setters, so it persists and reaches the next message. `/doctor` runs the
  environment check into a popup.
  `/complete` (with `/export` kept as its alias) is the one end-of-case act:
  confirmed first, it writes the full case report, the completion bundle
  (report, diagram, recorded declaration) and the execution-trace SVG, then
  detaches the evidence — the case is closed. `/trace` is gone; the trace
  ships with completion.
  Read-only views (`/sources`, `/tools`, `/findings <n>`, `/history`,
  `/oversight calls|prompt|<n>`) render the shell's own output in popups
  through a recording console. While a message is being investigated, the
  commands that would mutate the session are refused with a busy notice.
- **Plain language in the UI; jargon behind `?`.** See the naming pass below.
- **A 5-key footer.** `e  a  g  ?  q`. Budgets, model-request counts, trace
  ids and the full command list live in the `?` overlay.
- **One navy ground, one accent, semantic colour only** — teal = ok/complete,
  amber = partial, red = blocked — and it stays fully legible in **monochrome**:
  the glyphs `✓ ▲ ✗` carry the meaning without any colour.

### Naming pass (applied exactly)

| before (jargon) | after (plain, in the UI) |
|---|---|
| deterministic oversight layer | **Guardrails** |
| requested vs granted authority · `req›grant` · `net›DENIED` | **"blocked: reached the internet — denied"** / **"all steps allowed"** |
| flight recorder | **Activity** |
| provenance chain · claim→evidence→SHA-256 | **"where this came from"** (evidence id + short receipt, in the detail overlay only) |
| coverage bound stated · truncated | **"read first 4000 of 18213 bytes — more remains"** / **"partly read"** |
| answer_source · verified model report | **✓ grounded** / **⚠ unverified** |
| model-reqs · steps · tool-calls (main view) | moved into the `?` overlay |

---

## Visual design

The aesthetic layer is one committed system, applied end to end: one palette
family, one border style and one accent, shared by the TCSS stylesheet and the
Rich renderables. Run `dfir-agent --demo` to see the result without evidence or
a model.

### Palette — eight themes, each one family

Eight `textual.theme.Theme` palettes are registered in `app.py` and selected
with `/theme`: `dfir-tokyo` (the default), `dfir-light` and `dfir-contrast`,
which the console designed for itself, and `dfir-nord`, `dfir-gruvbox`,
`dfir-solarized`, `dfir-mocha` and `dfir-dracula`, taken from published
terminal palettes and cited to their sources in `model.py`. Every one of them
clears the same legibility floors as the first three: 4.5:1 for text and 3:1
for a panel edge, measured in `tests/test_tui_theme.py`.
Each is built from the role names in `model.py`, so Rich renderables and the
TCSS stylesheet
draw from the same ramp; the stylesheet itself uses only `$variables`
(`$background`, `$accent`, `$text-muted`, …), never loose hex.

| token | value | role |
|---|---|---|
| `BACKGROUND` | `#16161e` | the terminal ground (deepest Tokyo Night navy) |
| `PANEL_BG` | `#1a1b26` | raised surface (kept equal to the ground via the theme — depth comes from borders, not fills) |
| `PANEL_RAISED` | `#24283b` | second step: neutral chips |
| `BORDER` | `#616a99` | quiet hairlines (Tokyo Night gutter) |
| `TEXT` | `#c0caf5` | ordinary foreground |
| `DIM` / `DIM_BRIGHT` | `#8a93c0` / `#9aa5d4` | secondary metadata, two tiers |
| `ACCENT` | `#bb9af7` | the single accent: identity, focus, keys, sender chips |
| `SUCCESS` | `#73daca` | verified · complete · allowed |
| `ORANGE` | `#e0af68` | caution: partial, degraded, refused-by-tool |
| `RED` | `#f7768e` | failed · blocked |

Each signal colour also has a muted fill (`*_MUTED`, the colour blended 22%
over the ground) so chips can pair bright text with a legible tinted
background — `✓ grounded` is teal on `#2a4144`, `✗ 1 blocked` red on
`#482b37`. The theme deliberately sets `surface == background` and a fully
transparent boost layer (the Harlequin trick): elevation never comes from
lighter fills, only from borders and the overlay scrim.

### Spacing scale

Terminal cells are ~2× taller than wide, so the scale is asymmetric and used
everywhere: **1 cell vertical, 2–3 cells horizontal**. The body splits 3fr
(conversation) to 2fr (instruments); the status bar keeps a one-cell stand-off
above the body, message panels carry `(1, 2)` padding, and one blank line
separates chat turns.

### Borders and focus

One border style — `round` — for every pane, message panel and overlay. At
rest a border is the quiet gutter colour (`$border-blurred`, `#616a99`); focus
re-colours it to the accent without changing its shape, and the answer panel's
border takes the verdict colour. Pane titles live *in* the border
(`border-title`, bold, dim-bright at rest, accent on focus); in-flight hints
land in the border subtitles. The status bar is flat with a single hairline
underneath, and the footer is a flat line with accent keycaps. Scrollbars are
one cell wide with an invisible track. The selected row — evidence list or
activity table — is a full `ACCENT_MUTED` bar (fainter when the pane is
blurred), the global focus tint is disabled, and the disabled input dims to
half opacity while a run is in flight.

### Typography and chips

Metadata is never a separator chain: every field is a dim label beside its
value (`model  deepseek-chat`), in the status bar, the Session panel and the
help overlay alike. Messages are bordered panels — `❯ you` quiet, the agent's
verdict-coloured — with exchange numbers in the panel subtitles. Qualifiers
render as muted-fill chips under the answer. Uppercase is reserved for pane
titles; secondary metadata uses the two dim tiers.

---

## Layout

```
 DEMO/LIVE  model X  provider Y                              ● ready
 case NAME  evidence disk: …  memory: …
 ╭ CONVERSATION ──────────────╮  ╭ ACTIVITY (live) ───────────╮
 │ DFIR-AGENT banner          │  │ ✓ tool.op   args      1.8s │
 │ › Session panel            │  │ › tool.op   args           │
 │ ╭ ❯ you ────────────╮      │  ╰────────────────────────────╯
 │ │ question          │ 01   │  ╭ EVIDENCE ──────────────────╮
 │ ╰───────────────────╯      │  │ rows (Enter = detail)      │
 │ ╭ ◆ agent ──────────╮      │  ╰────────────────────────────╯
 │ │ markdown answer   │      │  ╭ GUARDRAILS ────────────────╮
 │ ╰──────── ✓ grounded╯      │  │ plain rows                 │
 │ ▲ qualifier chips          │  ╰────────────────────────────╯
 ╰────────────────────────────╯
 ╭ type a message… ╮                    footer:  e  a  g  ?  q
```

## Keys

| key | does |
|-----|------|
| type + `Enter` | send a message |
| `Esc` | switch between typing and browsing |
| `e` | the accepted evidence — opens the selected finding's detail at once (arrows browse, `m` removes) |
| `a` | the live Activity feed — the newest exchange unfolds at once |
| `g` | Guardrails — what the safety layer allowed or blocked |
| `?` | help (plain glossary, this run's limits/trace, full command list) |
| `v` | review the last run's findings as evidence (`y` accept, `n` reject) |
| `1`–`9` | jump the activity feed to that exchange |
| `q` | quit (press twice — a single press only arms it) |
| `Ctrl+P` | search the full slash-command list (`COMMAND_REGISTRY`) |

The prompt is the home: it is focused on start. After an answer, focus moves
to the conversation so `e / a / g / ?` work at once; `Esc` (or `i`) returns to
the prompt.

While a run is in flight an animated `investigating` line under the message
names the call in progress with its arguments and elapsed time, and a quiet
`working…` row inside the exchange's ACTIVITY group counts the model requests
as the run record grows. `Ctrl+C` cancels the run; the model's reasoning
text is deliberately never recorded or shown — only request counts, token
facts and outcomes.

## Files

| file | role |
|------|------|
| `tui/__init__.py` | launchers: `run_demo_tui`, `run_live_tui`, `build_app` |
| `tui/model.py` | palette + the plain cards every pane renders (`humanize`, `display_label`) |
| `tui/demo_data.py` | the recorded, stubbed case for `--demo` |
| `tui/controller.py` | `DemoController` and `LiveController` (wraps `InteractiveSession`) |
| `tui/app.py` | the Textual app: theme, stylesheet, conversation, two panes, overlays, 5-key footer |

Wiring: `cli/terminal.py` (`tui` command + `--demo` flag) and `cli/app.py`
(routing). Tests: `tests/test_tui_console.py`.

## Known gaps

- **Findings do not survive a restart.** The conversation is persisted per
  evidence source and reloaded into the model's context, but the EVIDENCE
  pane is rebuilt only from the current session's runs: reopening a case
  shows an empty pane even though every turn's run record still holds the
  findings. Restoring them on case open (rebuilding the finding cards from
  the saved turns, with their review state) is the missing piece.
