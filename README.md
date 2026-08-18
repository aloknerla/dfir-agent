<a id="hrvatski"></a>

**Hrvatski** · [English](#english)

# DFIR Agent

DFIR Agent je pomoćnik u istrazi za digitalnu forenziku i odgovor na incidente.
Veliki jezični model planira istragu i bira sljedeći analitički potez. Oko modela
stoji deterministički sloj koji upravlja izvođenjem alata, čita forenzičke izvore
kroz provjerene alate otvorenog koda, svodi rezultate na standardizirane nalaze,
provodi sigurnosna pravila nad svakom predloženom radnjom te zapisuje svaki poziv
alata i njegov rezultat u `audit.jsonl`, povezano u lanac sažetaka pa je naknadna
izmjena zapisa vidljiva.

Ovo je istraživački sustav, a ne certificirani forenzički proizvod, i ne zamjenjuje
kvalificiranog vještaka.

## Zašto je ovako građen

Jezični model može istražitelju pomoći da se snađe u raznorodnim dokazima i poveže
srodne nalaze, ali tečno napisana rečenica nije forenzički dokaz. DFIR Agent zato
odvaja planiranje, koje vodi model, od obrade dokaza:

1. Istražitelj otvara predmet i postavlja pitanje.
2. Model smije odabrati samo registrirane funkcije primjerene zadatku.
3. Nadzorni sloj provjerava svaki predloženi poziv prije izvođenja.
4. Deterministički analizatori pristupaju odobrenim dokazima samo za čitanje.
5. Rezultati se svode na nalaze s podacima o podrijetlu i pokrivenosti.
6. Konačan odgovor i pozivi koji ga podupiru ostaju dostupni na uvid.

Model nema opću ljusku ni neograničen pristup datotečnom sustavu domaćina. Ono što
model može učiniti određeno je registriranim skupom alata i sigurnosnim pravilima,
a ne suzdržanošću samog modela.

## Osnovne mogućnosti

DFIR Agent radi s podržanim slikama diska, snimkama memorije, PCAP datotekama,
Windows artefaktima, arhivama i metapodacima o integritetu. Koje su mogućnosti
stvarno ponuđene modelu ovisi o izvorima učitanima u aktivnom predmetu.

- Interaktivna istraga predmeta kroz više pitanja iz terminalske konzole.
- Deterministički forenzički omotači izloženi modelu kroz strukturirane sheme
  alata.
- Provjera putanja, ovlasti, argumenata, vremena i proračuna poziva pri svakom
  pozivu.
- Standardizirani nalazi koji nose podatke o podrijetlu i pokrivenosti.
- Provjera odgovora i ograničeni oporavak nepotpunih izvođenja.
- Trajne sesije, zapisnik izvođenja u `audit.jsonl` i SVG dijagrami tijeka.

## Forenzički alati koje povezuje

Samo forenzičko čitanje obavljaju uhodani alati zajednice. DFIR Agent doprinosi
orkestracijom, nadzorom i zapisnikom o tome što je izvedeno. Sloj alata svaki
program poziva kroz njegovo javno sučelje, pretežno u načinu samo za čitanje.
Alati se pozivaju samo ako postoje na domaćinu i ovdje se ne isporučuju:

- **The Sleuth Kit** (kroz `pytsk3`) za analizu datotečnog sustava
- **libewf** i **dfVFS** za pristup expert-witness i slojevitim slikama
- **regipy** za čitanje Windows registra
- **Volatility 3** za analizu memorije
- **bulk_extractor** za izdvajanje značajki i artefakata
- **tshark** (Wireshark) za analizu mrežnih snimki
- **ClamAV** za pretragu po potpisima
- **Tesseract** za optičko prepoznavanje znakova

Potpuno navođenje autorstva i licencija svakog alata nalazi se u datoteci `NOTICE`.

## Arhitektura

Deterministički upravljački sloj, granica prema alatima, sigurnosna pravila i
zapisnik izvođenja opisani su u `docs/`. Počnite od
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) zbog dijagrama slojeva i ulazne
točke istrage, pa odatle slijedite poveznice prema registru alata i sastavnicama
nadzornog sloja.

## Instalacija

Preduvjeti:

- Git i kopija repozitorija.
- Docker Desktop na Windowsu ili Docker Engine s Compose dodatkom na Linuxu, uz
  pristup Docker servisu.
- Oko 2 GB prostora na disku za sliku, uz još oko 800 MB za Volatilityjev paket
  simbola.
- Davatelj modela i njegov pristupni ključ. Konzola ih traži pri prvom
  pokretanju.

### Docker put (podržani)

Domaćinu ne treba ništa osim Dockera. Svi forenzički alati nalaze se u slici.

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

Instalacijska skripta provjerava je li Docker lokalan i pokrenut, gradi sliku i
povezuje naredbu `dfir-agent` s kloniranim direktorijem projekta. Ostavite kopiju
na mjestu; ako je premjestite, pokrenite instalacijsku skriptu ponovno s nove
lokacije.

Analiza memorije traži lokalni paket Volatilityjevih simbola, jer se konzola
nikada ne spaja na mrežu da ga dohvati. Paket se ne isporučuje s repozitorijem.
Smjestite ga u `work/volatility-symbols/` prije prvog pokretanja. Kontejner ga
pri prvom pokretanju jednom prekopira u vlastiti volumen, što traje nekoliko
minuta i ispisuje napredak, a svako sljedeće pokretanje čita tu brzu kopiju.

### Obični Python put (nije podržan)

Ovaj put instalira samo Python paket, bez ijednog forenzičkog alata:

```bash
pip install -c constraints.txt -e ".[dev]"
```

Domaćin tada mora imati Python 3.11 ili 3.12 i sam osigurati svaki vanjski alat
na `PATH`: `vol` (Volatility 3), `tshark` i `mergecap` (Wireshark), `7z`,
`tesseract`, `regripper`, `bulk_extractor` te `clamscan` (ClamAV). Stanje se
provjerava naredbom `dfir-agent doctor`. Ta naredba ispisuje i John the Ripper
kao neobavezan; nijedna funkcija konzole trenutno ga ne koristi.

Testirano je na Pythonu 3.12.10 na Windowsu 11 i na Pythonu 3.12 na Ubuntuu
24.04.

## Pokretanje konzole

Pokretanje interaktivne konzole:

```bash
dfir-agent
```

Pri prvom pokretanju odaberite davatelja modela i unesite pristupne podatke kroz
skriveni upit; spremaju se u lokalni direktorij s postavkama, nikad u sliku ni u
direktorij s dokazima. Provjera postavki i ovisnosti dostupna je kroz:

```bash
dfir-agent setup
dfir-agent doctor
```

Unutar konzole znak `/` otvara izbornik naredbi. Predmet ili pojedini dokazni
izvor otvara se naredbom `/case`, izvor se dodaje naredbom `/attach`, a kratak
opis predmeta bez dokazne vrijednosti unosi se naredbom `/context`. Dokazi se
uvijek montiraju samo za čitanje, a otvaranje nove putanje na domaćinu traži
jedno odobrenje sa strane domaćina prije nego što postane vidljiva konzoli.

### Nadogradnja

`git pull` ne mijenja sliku. Dok se ne izgradi ponovno, konzola pokreće staru:

```bash
git pull
dfir-agent --rebuild
```

`dfir-agent --rebuild` gradi upravo onu sliku koju pokretač poslije pokreće, jer
Compose poziva s istom compose datotekom i pod istim imenom projekta kao i pri
pokretanju konzole, pa radi iz bilo kojeg direktorija. `docker compose build
console` gradi istu sliku samo ako je upisan u direktoriju projekta; drugdje
imenuje drugi projekt i gradi sliku koju pokretač nikada ne pokreće.

Ako se promijenila i sama skripta pokretača, instalirajte je ponovno naredbom
`.\install.ps1 -SkipBuild` odnosno `./install.sh --skip-build`. Pokretač
provjerava oba slučaja prije svakog pokretanja i javlja kada je instalirana
naredba starija od one u direktoriju projekta ili kada je slika izgrađena prije
zadnje promjene u repozitoriju.

## Licencija

Objavljeno pod MIT licencijom. Puni tekst je u [`LICENSE`](LICENSE), a navođenje
autorstva za komponente trećih strana u [`NOTICE`](NOTICE).

---

<a id="english"></a>

[Hrvatski](#hrvatski) · **English**

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
