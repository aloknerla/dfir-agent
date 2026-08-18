# DFIR Agent

DFIR Agent is an investigation assistant for digital forensics and incident
response. A large language model plans the investigation and chooses the next
analytical action. Around that model sits a deterministic layer that controls
tool execution, reads forensic sources through vetted open-source tools,
standardizes the results into findings, enforces an oversight policy on every
proposed action, and records every tool call and its result in `audit.jsonl`,
hash-chained so later modification is detectable.

It is a research system, not a certified forensic product, and not a replacement
for a qualified examiner.

## Why it is built this way

Language models can help an investigator navigate heterogeneous evidence and
connect related findings, but fluent text is not forensic proof. DFIR Agent
therefore separates model-driven planning from evidence processing:

1. The investigator opens a case and asks a question.
2. The model may select only registered, task-appropriate capabilities.
3. The oversight layer validates every proposed call before it runs.
4. Deterministic analyzers access approved evidence in read-only mode.
5. Results are normalized into findings with source and coverage metadata.
6. The final answer and its supporting calls remain available for review.

The model has no general-purpose shell and no unrestricted access to the host
file system. What the model can do is bounded by the registered tool set and by
the oversight policy, not by the model's own restraint.

## Core capabilities

DFIR Agent can work with supported disk images, memory captures, PCAP files,
Windows artifacts, archives, and integrity metadata. The exact
capabilities offered to the model depend on the sources loaded in the active
case.

- Interactive, multi-question case investigation from a terminal console.
- Deterministic forensic wrappers exposed to the model through structured tool
  schemas.
- Path, capability, argument, time, and call-budget enforcement on every call.
- Standardized findings carrying provenance and coverage information.
- Answer verification and bounded recovery for incomplete runs.
- Persistent sessions, the `audit.jsonl` execution record, and SVG execution
  traces.

## Forensic tools it binds

The forensic reading itself is done by established community tools. DFIR Agent
contributes the orchestration, the oversight, and the record of what ran. The
tool layer wraps each program through its own public interface, predominantly in
read-only mode. The tools are invoked only if present on the host and are not
redistributed here:

- **The Sleuth Kit** (via `pytsk3`) for file-system analysis
- **libewf** and **dfVFS** for expert-witness and layered image access
- **regipy** for Windows registry parsing
- **Volatility 3** for memory analysis
- **bulk_extractor** for feature and artifact extraction
- **tshark** (Wireshark) for network capture analysis
- **ClamAV** for signature scanning
- **Tesseract** for optical character recognition

See the `NOTICE` file for the full attribution and license of each tool.

## Architecture

The deterministic control layer, the tool boundary, the oversight policy, and
the execution record are described in `docs/`. Start with
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the layer diagram and the
investigation entry point, and follow the pointers from there into the tool
registry and the oversight components.

## Install

Prerequisites:

- Git and a checkout of the repository.
- Docker Desktop on Windows, or Docker Engine with the Compose plugin on Linux,
  with access to the Docker daemon.
- About 2 GB of disk space for the image, plus about 800 MB for the Volatility
  symbol pack.
- A model provider and its API key. The console asks for them at first launch.

### Docker path (supported)

The host needs nothing but Docker. Every forensic tool lives inside the image.

```powershell
git clone https://github.com/aloknerla/dfir-agent.git
cd dfir-agent
.\install.ps1
```

```bash
git clone https://github.com/aloknerla/dfir-agent.git
cd dfir-agent
./install.sh
```

The installer checks that Docker is local and running, builds the image, and
links a `dfir-agent` command to the cloned project directory. Keep the checkout
in place; if it moves, run the installer again from its new location.

Memory analysis needs a local Volatility symbol pack, because the console never
goes to the network to fetch one. The pack is not shipped with the repository.
Put it in `work/volatility-symbols/` before the first launch. The container
copies it once into its own volume on that first run, which takes a few minutes
and prints its progress, and every run after that reads the fast copy.

### Plain Python path (not supported)

This installs the Python package only, with no forensic tool at all:

```bash
pip install -c constraints.txt -e ".[dev]"
```

The host then needs Python 3.11 or 3.12 and must provide every external tool on
`PATH` itself: `vol` (Volatility 3), `tshark` and `mergecap` (Wireshark), `7z`,
`tesseract`, `regripper`, `bulk_extractor`, and `clamscan` (ClamAV). Check the
result with `dfir-agent doctor`. That command also lists John the Ripper as
optional; no console capability currently uses it.

Tested on Python 3.12.10 on Windows 11 and on Python 3.12 on Ubuntu 24.04.

## Run the console

Start the interactive console:

```bash
dfir-agent
```

At first launch, choose a model provider and enter the credentials through a
hidden prompt; they are stored in the local configuration directory, never in
the image or the evidence directory. Configuration and dependency checks are
available through:

```bash
dfir-agent setup
dfir-agent doctor
```

Inside the console, typing `/` opens a command menu. Open a case or a single
evidence source with `/case`, add a source with `/attach`, and provide a short
non-evidentiary case brief with `/context`. Evidence is always mounted
read-only, and opening a new host path requires one host-side approval before it
becomes visible to the console.

Two commands govern what one question is allowed to consume. `/reasoning`
sets how much reasoning the model spends per request (`none`, `low`, `medium`,
`high`). `/budget` sets the ceilings on the run itself — the wall clock in
seconds, the investigation steps and the tool calls — as `/budget time 600`,
`/budget steps 30` and `/budget toolcalls 30`, or on the screen a bare
`/budget` opens. A question that exhausts one of those ceilings ends there
and publishes no finding, so a run that keeps stopping short is asking for a
larger budget. Both settings apply to the next question and are kept for the
next launch.

### Updating

A `git pull` does not change the image. Until it is rebuilt, the console keeps
running the old one:

```bash
git pull
dfir-agent --rebuild
```

`dfir-agent --rebuild` builds the image the launcher then starts, because it
calls Compose with the same compose file and under the same project name as the
console run, so it works from any directory. `docker compose build console`
builds that same image only when it is typed in the project directory; anywhere
else it names a different project and builds an image the launcher never runs.

If the launcher script itself changed, install it again with
`.\install.ps1 -SkipBuild` or `./install.sh --skip-build`. The launcher checks
both cases before every start and reports when the installed command is older
than the one in the project directory, or when the image was built before the
newest commit in the repository.

## License

Released under the MIT License. See [`LICENSE`](LICENSE) for the full text and
[`NOTICE`](NOTICE) for third-party attribution.
