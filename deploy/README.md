# Console deployment

This directory holds the container definition for the DFIR Agent console: a
single, self-contained image that pins the Python environment and every
forensic analyzer the agent binds, so findings stay reproducible across
workstations.

## Contents

- [`Dockerfile`](Dockerfile) — multi-stage build of the `console` target.
- [`forensic-top-level-constraints.txt`](forensic-top-level-constraints.txt) —
  frozen top-level forensic distributions used while building the environment.
- [`clamav-wrapper.sh`](clamav-wrapper.sh) — points the loader at the bundled
  ClamAV libraries before running `clamscan`.
- [`bulk-extractor-wrapper.sh`](bulk-extractor-wrapper.sh) — points the loader
  at the compiled `bulk_extractor` prefix before running the tool.
- [`console/`](console) — host launchers (`launch.ps1`, `launch.sh`), the Linux
  Docker preflight, and the optional SELinux compose override.

## What the image provides

The build compiles or installs the community forensic tooling on a pinned Debian
base and installs the project with its forensic extras:

- The Sleuth Kit, libewf and dfVFS for file-system and image access
- Volatility 3 for memory analysis
- bulk_extractor for feature and artifact extraction (compiled from the pinned
  upstream release)
- tshark for network capture analysis
- ClamAV for signature scanning (scanner and signed databases copied from the
  official image)
- Tesseract for optical character recognition
- RegRipper and 7-Zip

The container runs as an unprivileged, non-root user. Evidence is mounted
read-only and reconstructed content is written to an isolated payload volume.

## Build and run

The supported path is the top-level installer, which builds this image and links
a `dfir-agent` command to the checkout:

```powershell
.\install.ps1     # Windows
```

```bash
bash install.sh      # Linux
```

Direct Docker commands remain available for development:

```bash
docker compose build console
docker compose run --rm console doctor
docker compose run --rm console
```

To build the image on its own, from the repository root:

```bash
docker build --target console --file deploy/Dockerfile --tag dfir-agent-console .
```

See the top-level [`README.md`](../README.md) for the full usage guide.

## Ollama on a Linux host

The container reaches a host Ollama service through `host.docker.internal`
(mapped to the host gateway in `docker-compose.yml`). Ollama's default
listener binds loopback only, which a bridge container cannot reach:

1. Make Ollama listen on all interfaces — e.g. a systemd override:
   `systemctl edit ollama` with `Environment="OLLAMA_HOST=0.0.0.0"`, then
   `systemctl restart ollama`.
2. Allow the docker bridge subnet (typically `172.17.0.0/16`) through the
   host firewall to port `11434`.
3. Raise the served context window and keep the model warm for agent runs —
   the OpenAI-compatible endpoint cannot set these per request:
   `Environment="OLLAMA_CONTEXT_LENGTH=16384"` and
   `Environment="OLLAMA_KEEP_ALIVE=30m"` in the same override.
4. Rootless Docker may additionally block host loopback via slirp4netns;
   prefer a rootful engine or bind Ollama to the bridge address directly.
