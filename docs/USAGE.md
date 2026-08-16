<a id="hrvatski"></a>

**Hrvatski** · [English](#english)

# Rad s konzolom

DFIR Agentom se upravlja iz interaktivne terminalske konzole. Ova stranica opisuje
kako je pokrenuti i koje naredbe prihvaća. Zamisao iza konzole, nadzornu kontrolnu
točku, životni ciklus dokaza i put do odgovora opisuje
[Arhitektura](ARCHITECTURE.md).

## Pokretanje konzole

```bash
dfir-agent
```

Pri prvom pokretanju odaberite davatelja modela i unesite njegove pristupne
podatke kroz skriveni upit. Pristupni podaci spremaju se u lokalni direktorij s
postavkama, nikad u direktorij s dokazima. U postavljanju pomažu dvije
neinteraktivne podnaredbe:

```bash
dfir-agent setup     # postavi OpenRouter ili lokalni Ollama model
dfir-agent doctor    # provjeri vezu s modelom i forenzičke ovisnosti
```

## Postavljanje pitanja

Prvo učitajte predmet, zatim upišite pitanje običnim jezikom. Redak koji ne
počinje znakom `/` tumači se kao istražno pitanje i odbija se ako nisu učitani
dokazi. Konzola ispisuje odgovor zajedno sa sažetkom dokaza i upravljačkom pločom,
pa je analitički put iza odgovora vidljiv uz njega.

## Naredbe

Znak `/` otvara izbornik naredbi. `/help` popisuje sve, a `/help <command>`
prikazuje jednu naredbu u detalje. Naredbe su grupirane po namjeni.

### Općenito

| Naredba | Namjena |
|---|---|
| `/help [command]` | Prikaži sve naredbe ili detaljnu pomoć za jednu. |
| `/status` | Prikaži aktivni model, predmet, dokazne izvore i alate. |
| `/clear [all]` | Očisti terminal bez utjecaja na istragu; uz `all` uklanja se i statusna ploča. |
| `/layout [simple\|full]` | Prebaci se između punog rasporeda i jednostavnog prikaza u jednom stupcu. Sam `/layout` otvara izbornik koji imenuje oba rasporeda; aktivni je vidljiv u ploči sesije. |
| `/quit` | Zatvori terminal; povijest istrage sprema se automatski. |

### Predmet i dokazi

| Naredba | Namjena |
|---|---|
| `/case [disk\|memory\|network] <path>` | Otvori direktorij predmeta, dokaznu datoteku ili izrijekom označen RAW izvor. |
| `/attach <disk\|memory\|network> <path>` | Priključi još jedan dokazni izvor aktivnom predmetu. |
| `/sources` | Prikaži svaki dokazni izvor trenutno priključen predmetu. |
| `/context [show\|set <text>\|load <path>\|clear]` | Prikaži ili uredi opis predmeta bez dokazne vrijednosti. |

Dokazi se uvijek otvaraju samo za čitanje. Otvaranje putanje na domaćinu izvan
aktivnog korijena dokaza traži jedno odobrenje sa strane domaćina prije nego što
postane vidljiva konzoli.

### Istraga

| Naredba | Namjena |
|---|---|
| `/tools [name]` | Popiši aktivne alate s brojem operacija i vanjskim osloncem ili prikaži punu razradu jedne funkcije. |
| `/findings [id]` | Popiši standardizirane nalaze ili opiši jedan od njih po oznaci s popisa. |
| `/oversight [n\|calls\|prompt]` (alias `/guardrails`) | Obračunaj svaki poziv alata: koliko ih je izvedeno, koliko odbijeno i u kojem sloju. `n` prikazuje jedan poziv u cijelosti; `calls` popisuje izvedene naredbe s punim argumentima; `prompt` prikazuje poruku poslanu modelu. |
| `/retry` | Ponovno pokreni posljednje istražno pitanje. |
| `/export [n\|path]` | Zapiši izvještaj istrage: svako pitanje koje ova povijest čuva, jedno pitanje po njegovom položaju uz `n` ili izvještaj posljednjeg pitanja na zadanu putanju. Ništa se ne zatvara i nijedan dokaz se ne odvaja. |
| `/complete [path]` | Zatvori predmet: nakon potvrde zapiši puni izvještaj predmeta, dijagram istrage i zapis o dovršetku, pa odvoji dokazne izvore. |

Odbijanje po sigurnosnim pravilima i odbijanje od strane alata broje se odvojeno
jer je samo prvo kontrolna točka koja je poziv zaustavila.

### Sesija

| Naredba | Namjena |
|---|---|
| `/new [name]` (alias `/reset`) | Započni novu povijest istrage za aktivni predmet i istodobno očisti s ekrana prethodne poruke, pozive alata i odluke sigurnosnih pravila. Predmet, dokazi, zapis izvođenja i nalazi ostaju. |
| `/history [limit]` | Prikaži prethodna pitanja i odgovore u ovoj istrazi. |
| `/undo` | Izuzmi posljednji odgovor iz budućeg konteksta modela. |
| `/resume [id]` | Otvori spremljenu istragu i vrati je na zaslon. Bez oznake otvara popis. `/sessions` je isto. |
| `/continue` | Nastavi prethodnu istragu i ponovno otvori njezine dokaze. |

### Sustav

| Naredba | Namjena |
|---|---|
| `/setup` | Postavi OpenRouter ili lokalni Ollama model. |
| `/model [list [all\|<text>]\|<model-id>]` | Prikaži aktivni model, popiši što pozadinski sustav nudi ili se prebaci na model po oznaci. |
| `/doctor` | Provjeri vezu s modelom i forenzičke ovisnosti. |
| `/language [en\|hr]` | Prikaži ili promijeni jezik terminala (engleski ili hrvatski). |
| `/theme [name]` | Prikaži ili promijeni paletu boja terminala; sam `/theme` popisuje isporučene teme i označava aktivnu, a izbor se pamti za sljedeće pokretanje. |
| `/effort [none\|low\|medium\|high\|steps N\|toolcalls N]` | Prikaži i postavi koliko posla smije potrošiti jedno pitanje: trud razmišljanja modela te ograničenja koraka i poziva alata. Sam `/effort` otvara zaslon; razina postavlja trud, a `steps N` ili `toolcalls N` ograničenje. |

---

<a id="english"></a>

[Hrvatski](#hrvatski) · **English**

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
| `/effort [none\|low\|medium\|high\|steps N\|toolcalls N]` | Show and set how much work one question may spend: the model's reasoning effort and the step and tool-call limits. Bare `/effort` opens the screen; a level sets the effort, `steps N` or `toolcalls N` sets a limit. |
