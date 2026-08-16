<a id="hrvatski"></a>

**Hrvatski** · [English](#english)

# Dokumentacija

Ovaj direktorij opisuje kako je DFIR Agent zamišljen: jezični model vezan uz
zatvoren skup provjerenih forenzičkih alata, s determinističkim nadzornim slojem
koji provjerava svaku radnju i zapisom cijelog izvođenja u `audit.jsonl`,
povezanim u lanac sažetaka pa je naknadna izmjena zapisa vidljiva.

## Preporučeni redoslijed čitanja

1. [Pregled arhitekture](ARCHITECTURE_OVERVIEW.md) opisuje što sustav jest i, na
   jednoj stranici, što ga sprječava da ustvrdi nešto što dokazi ne podupiru.
   Imenuje datoteku i funkciju koja provodi svaku provjeru odgovora.
2. [Arhitektura](ARCHITECTURE.md) donosi arhitekturu na visokoj razini, dijagram
   slojeva i životni ciklus dokaza od početka do kraja.
3. [Detalji arhitekture](ARCHITECTURE_DETAIL.md) donose pogled održavatelja:
   put izvođenja redom, od pritiska tipke do objavljenog odgovora, s dijagramima
   tijeka poziva i slojeva.
4. [Upute za rad](USAGE.md) opisuju kako pokrenuti konzolu i koje `/` naredbe
   prihvaća.

## Slike

Izvori dijagrama prikazanih u gornjim dokumentima nalaze se u
[`figures/`](figures/).

---

<a id="english"></a>

[Hrvatski](#hrvatski) · **English**

# Documentation

This directory documents the design of DFIR Agent: a language model bound to a
closed set of vetted forensic tools, with a deterministic oversight layer that
validates every action and a record of the whole run in `audit.jsonl`,
hash-chained so later modification is detectable.

## Recommended reading order

1. [Architecture overview](ARCHITECTURE_OVERVIEW.md) — what the system is and, on
   one page, what stops it asserting something the evidence does not support. Names
   the file and function that enforces each answer.
2. [Architecture](ARCHITECTURE.md) — the high-level architecture, the layer
   diagram, and the end-to-end evidence lifecycle.
3. [Architecture detail](ARCHITECTURE_DETAIL.md) — the maintainer's view: the
   execution path in order, from keystroke to published answer, with call-flow and
   layer diagrams.
4. [Usage](USAGE.md) — how to start the console and the `/` commands it accepts.

## Figures

Diagram sources rendered in the documents above live in [`figures/`](figures/).
