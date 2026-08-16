<a id="hrvatski"></a>

**Hrvatski** · [English](#english)

# Popis promjena

Projekt se drži [semantičkog verzioniranja](https://semver.org/).

## 0.1.0 — prvo javno izdanje

Prvo javno izdanje sustava DFIR Agent, pomoćnika u istrazi za digitalnu forenziku
i odgovor na incidente, u kojem jezični model planira istragu, a deterministički
sloj upravlja izvođenjem alata, čita forenzičke izvore kroz provjerene alate
otvorenog koda, svodi rezultate na standardizirane nalaze, provodi sigurnosna
pravila nad svakom predloženom radnjom te zapisuje svaki poziv alata i njegov
rezultat u `audit.jsonl`, povezano u lanac sažetaka pa je naknadna izmjena zapisa
vidljiva.

Uključuje:

- interaktivnu terminalsku konzolu za istragu predmeta kroz više pitanja;
- determinističke forenzičke omotače izložene modelu kroz strukturirane sheme
  alata, oslonjene na uhodane analizatore otvorenog koda;
- nadzorni sloj koji pri svakom pozivu provjerava ovlasti, argumente, putanje i
  proračun;
- standardizirane nalaze s podacima o podrijetlu i pokrivenosti, vezane uz lanac
  zapisa koji se samo dopisuje;
- provjeru odgovora, ograničen deterministički oporavak, trajne sesije i SVG
  dijagrame tijeka izvođenja.

---

<a id="english"></a>

[Hrvatski](#hrvatski) · **English**

# Changelog

This project adheres to [Semantic Versioning](https://semver.org/).

## 0.1.0 — Initial public release

First public release of DFIR Agent: an investigation assistant for digital
forensics and incident response in which a language model plans the investigation
while a deterministic layer controls tool execution, reads forensic sources
through vetted open-source tools, standardizes results into findings, enforces an
oversight policy on every proposed action, and records every tool call and its
result in `audit.jsonl`, hash-chained so later modification is detectable.

Includes:

- interactive terminal console for multi-question case investigation;
- deterministic forensic wrappers exposed to the model through structured tool
  schemas, backed by established open-source analyzers;
- an oversight layer enforcing capability, argument, path, and budget checks on
  every call;
- standardized findings carrying provenance and coverage metadata, bound to an
  append-only hash chain;
- answer verification, bounded deterministic recovery, persistent sessions, and
  SVG execution traces.
