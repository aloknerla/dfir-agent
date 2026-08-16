<a id="hrvatski"></a>

**Hrvatski** · [English](#english)

# Isporuka konzole

Ovaj direktorij sadrži definiciju kontejnera za konzolu DFIR Agenta: jednu
samostalnu sliku koja fiksira Python okruženje i svaki forenzički analizator koji
agent povezuje, pa nalazi ostaju ponovljivi na svim radnim stanicama.

## Sadržaj

- [`Dockerfile`](Dockerfile) je višefazna gradnja cilja `console`.
- [`forensic-top-level-constraints.txt`](forensic-top-level-constraints.txt)
  sadrži zamrznute forenzičke distribucije najviše razine koje se koriste pri
  gradnji okruženja.
- [`clamav-wrapper.sh`](clamav-wrapper.sh) usmjerava učitavač na isporučene
  ClamAV biblioteke prije pokretanja naredbe `clamscan`.
- [`bulk-extractor-wrapper.sh`](bulk-extractor-wrapper.sh) usmjerava učitavač na
  prevedeni `bulk_extractor` prefiks prije pokretanja alata.
- [`console/`](console) sadrži pokretače na domaćinu (`launch.ps1`, `launch.sh`),
  Docker predprovjeru za Linux i neobaveznu SELinux compose nadopunu.

## Što slika nudi

Gradnja prevodi ili instalira forenzičke alate zajednice na fiksiranoj Debian
osnovi i instalira projekt s njegovim forenzičkim dodacima:

- The Sleuth Kit, libewf i dfVFS za pristup datotečnom sustavu i slikama
- Volatility 3 za analizu memorije
- bulk_extractor za izdvajanje značajki i artefakata (preveden iz fiksiranog
  izvornog izdanja)
- tshark za analizu mrežnih snimki
- ClamAV za pretragu po potpisima (skener i potpisane baze preuzeti iz službene
  slike)
- Tesseract za optičko prepoznavanje znakova
- RegRipper i 7-Zip

Kontejner se izvodi kao neprivilegiran korisnik koji nije root. Dokazi se
montiraju samo za čitanje, a rekonstruirani sadržaj zapisuje se u izdvojeni
volumen za sadržaj.

## Gradnja i pokretanje

Podržani put je instalacijska skripta na najvišoj razini, koja gradi ovu sliku i
povezuje naredbu `dfir-agent` s kopijom repozitorija:

```powershell
.\install.ps1     # Windows
```

```bash
bash install.sh      # Linux
```

Izravne Docker naredbe ostaju dostupne za razvoj:

```bash
docker compose build console
docker compose run --rm console doctor
docker compose run --rm console
```

Za samostalnu gradnju slike, iz korijena repozitorija:

```bash
docker build --target console --file deploy/Dockerfile --tag dfir-agent-console .
```

Potpune upute za rad nalaze se u [`README.md`](../README.md) na najvišoj razini.

## Ollama na Linux domaćinu

Kontejner do Ollama servisa na domaćinu dolazi kroz `host.docker.internal`
(preslikan na pristupnik domaćina u `docker-compose.yml`). Zadani Ollamin
osluškivač veže se samo na povratnu petlju, do koje kontejner u mostu ne može
doprijeti:

1. Neka Ollama sluša na svim sučeljima, primjerice kroz systemd nadopunu:
   `systemctl edit ollama` s `Environment="OLLAMA_HOST=0.0.0.0"`, zatim
   `systemctl restart ollama`.
2. Propustite podmrežu Docker mosta (obično `172.17.0.0/16`) kroz vatrozid
   domaćina do vrata `11434`.
3. Povećajte posluženi kontekstni prozor i držite model toplim za izvođenja
   agenta, jer OpenAI kompatibilna krajnja točka to ne može postaviti po
   zahtjevu: `Environment="OLLAMA_CONTEXT_LENGTH=16384"` i
   `Environment="OLLAMA_KEEP_ALIVE=30m"` u istoj nadopuni.
4. Docker bez root ovlasti može dodatno blokirati povratnu petlju domaćina kroz
   slirp4netns; u tom slučaju koristite pokretač s root ovlastima ili vežite
   Ollamu izravno na adresu mosta.

---

<a id="english"></a>

[Hrvatski](#hrvatski) · **English**

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
