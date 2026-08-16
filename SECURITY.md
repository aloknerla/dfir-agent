<a id="hrvatski"></a>

**Hrvatski** · [English](#english)

# Sigurnosna pravila

## Podržana inačica

Sigurnosni popravci ciljaju posljednju označenu inačicu i tekuću granu izdanja.

## Prijava ranjivosti

Ranjivosti prijavite povjerljivo kroz GitHub Security Advisories ili izravno
vlasniku repozitorija. Ne otvarajte javnu prijavu koja sadrži:

* pristupne podatke, API ključeve, interne putanje ili osobne podatke;
* sadržaj iz forenzičkog izvora;
* zaobilaženje nadzornog sloja;
* postupak za izmjenu dokaza ili izvršavanje sadržaja dokaza.

Navedite pogođenu inačicu ili commit, najmanji postupak za ponavljanje problema,
očekivano i opaženo ponašanje te procjenu učinka. Kad god je moguće, koristite
umjetno stvorene podatke.

## Sigurnosni doseg

Nalazi velikog učinka uključuju izlazak izvan dopuštenih putanja, izvršavanje
proizvoljnih naredbi, otkrivanje pristupnih podataka, izmjenu dokaza, izmjenu
zapisa u `audit.jsonl` i objavu tvrdnji koje nisu vezane uz zabilježene
forenzičke nalaze.

DFIR Agent ne jamči pravnu prihvatljivost dokaza. Za provjeru i konačan stručni
zaključak ostaje odgovoran kvalificirani vještak.

---

<a id="english"></a>

[Hrvatski](#hrvatski) · **English**

# Security policy

## Supported version

Security fixes target the latest tagged version and the current release branch.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub Security Advisories or directly
to the repository owner. Do not open a public issue containing:

* credentials, API keys, internal paths, or personal data;
* content from a forensic source;
* an oversight-layer bypass;
* a method for modifying evidence or executing evidence content.

Include the affected version or commit, minimal reproduction steps, expected and
observed behavior, and an impact assessment. Use synthetic data whenever
possible.

## Security scope

High-impact findings include path-boundary escapes, arbitrary command
execution, credential disclosure, evidence modification, tampering with the
`audit.jsonl` record, and publication of claims that are not linked to recorded
forensic findings.

DFIR Agent does not guarantee legal admissibility. A qualified examiner remains
responsible for verification and the final professional conclusion.
