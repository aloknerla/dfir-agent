<a id="hrvatski"></a>

**Hrvatski** · [English](#english)

# Doprinosi

DFIR Agent je istraživački sustav za istragu usmjerenu na dokaze. Izmjene moraju
očuvati dva temeljna ograničenja: dokazni izvori ostaju samo za čitanje, a model
im pristupa isključivo kroz registrirane funkcije.

## Razvojno okruženje

Preporučuje se Python 3.11 ili 3.12.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -c constraints.txt -e ".[forensics,dev]"
```

Na Linuxu i macOS-u koristi se `source .venv/bin/activate`.

## Obavezne provjere

```text
ruff check src
mypy src
pytest -q
```

Automatizirani testovi ne smiju zahtijevati pravi API ključ, pristup mreži, poziv
jezičnog modela ni forenzičku sliku.

## Pravila za izmjene

* Nikad ne pohranjuj u repozitorij dokaze, pristupne podatke, podatke sesije,
  zapisnike izvođenja ni sirove nalaze.
* Svaka modelu vidljiva funkcija traži tipiziranu shemu argumenata, ograničen
  ispis, deklarirane ovlasti i testove za putanje neuspjeha.
* Nikad ne stavljaj oznake predmeta ni očekivane odgovore u produkcijske upute
  modelu ili u analizatore.
* Kod proizvoda, nazive datoteka, ispis sučelja i javnu tehničku dokumentaciju
  drži na engleskom.
* Uzorke pretrage vezane uz jezik zadrži samo kad su namjerna mogućnost
  lokalizacije.
* Izmjene dijeli u usredotočene commitove i provjeri točan popis pripremljenih
  datoteka.

## Zahtjevi za povlačenje

Opiši motivaciju, granice povjerenja na koje izmjena utječe i provedene provjere.
Izmjene uputa modelu, shema funkcija ili manifesta izvora mijenjaju ponašanje
sustava i tako ih treba i opisati.

---

<a id="english"></a>

[Hrvatski](#hrvatski) · **English**

# Contributing

DFIR Agent is a research system for evidence-oriented investigation. Changes
must preserve two core constraints: evidence sources remain read-only, and the
model accesses them only through registered capabilities.

## Development environment

Python 3.11 or 3.12 is recommended.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -c constraints.txt -e ".[forensics,dev]"
```

Linux and macOS use `source .venv/bin/activate`.

## Required checks

```text
ruff check src
mypy src
pytest -q
```

Automated tests must not require a real API key, network access, language-model
request, or forensic image.

## Change rules

* Never commit evidence, credentials, session data, execution logs, or raw
  findings.
* Every model-visible capability requires a typed argument schema, bounded
  output, declared permissions, and failure-path tests.
* Never place case identifiers or expected answers in production prompts or
  analyzers.
* Keep product code, filenames, CLI output, and public technical documentation
  in English.
* Preserve language-specific search patterns only when they are intentional
  localization capabilities.
* Split changes into focused commits and review the exact staged file list.

## Pull requests

Describe the motivation, the affected trust boundaries, and the checks performed.
Changes to prompts, capability schemas, or source manifests affect the system's
behaviour and should be described as such.
