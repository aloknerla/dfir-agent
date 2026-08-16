<a id="hrvatski"></a>

**Hrvatski** · [English](#english)

# Smjer proizvoda

## Naziv proizvoda

DFIR Agent

## Kome je namijenjen

DFIR Agent je namijenjen forenzičkim vještacima, analitičarima za odgovor na
incidente, sigurnosnim istraživačima i studentima. Oni rade sa slikama diska,
snimkama memorije, mrežnim prometom i izvedenim artefaktima, a treba im i odgovor
i analitički put koji je do njega doveo.

## Svrha

Sustav pokazuje kako veliki jezični model može pomoći u forenzičkoj istrazi bez
neograničenog pristupa dokazima ili radnoj stanici. Istražitelj otvara predmet i
postavlja pitanja običnim jezikom. Model planira sljedeći analitički potez, dok
determinističke sastavnice provjeravaju pozive, pokreću forenzičke analizatore,
svode nalaze na jedinstven oblik i vode zapisnik izvođenja.

Uspjeh znači da je istraga razumljiva, ponovljiva i provjerljiva od strane
kvalificiranog vještaka. Ne znači da model zamjenjuje vještaka niti da se tečno
napisan ispis prihvaća bez potpornih dokaza.

## Karakter proizvoda

Sučelje treba biti smireno, tehničko i usmjereno na dokaze. Povjerenje treba
proizlaziti iz jasnog stanja, vidljivih analitičkih radnji, izrečenih ograničenja
i sljedivih nalaza, a ne iz vizualnog spektakla ili ponašanja nalik ljudskom.

## Načela oblikovanja

1. Prikaži aktivni kontekst predmeta prije rada agenta i prije konačnog odgovora.
2. Neka svaka važna tvrdnja bude sljediva do zabilježenog forenzičkog nalaza.
3. Zadani prikaz drži čitljivim, a tehničku dubinu ponudi na zahtjev.
4. Pogreške, nepotpunu pokrivenost i neuspjelu provjeru prikaži izričito.
5. Pristup dokazima drži samo za čitanje i izoliraj privremeni analitički rad.
6. Očuvaj rad tipkovnicom i čitljiv ispis u svijetlim i tamnim terminalima.

## Granice proizvoda

DFIR Agent ne smije prikazivati privatni tijek razmišljanja modela, izvršavati
sadržaj dokaza, izlagati modelu opću ljusku niti nagovještavati sigurnost koju
zabilježeni nalazi ne podupiru.

Aplikacija podržava davatelje OpenRouter i lokalni Ollama.

---

<a id="english"></a>

[Hrvatski](#hrvatski) · **English**

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
