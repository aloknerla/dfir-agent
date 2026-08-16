#!/bin/bash
# CTF driver helper — one question per call, appended to a per-model transcript.
# Usage: DFA_MODEL=<id> ./ctf.sh <t1|t2|t3|t4> "<pitanje>"
#   t1 = DNS egzfiltracija (promet.pcap)          --pcap
#   t2 = Svjetionik / Cobalt Strike (memory.dmp)  --memory
#   t3 = Autentifikacija / HTTP+RC4 (challenge)   --pcap  (+ /evidence/ShipIt.sh)
#   t4 = Krijumcar / HTML smuggling (memory.dmp)  --memory
set -u
# Derived from this script's own location, so the helper follows the checkout
# instead of pinning one workstation's drive letter.
SELF=$(readlink -f -- "${BASH_SOURCE[0]}")
PROJ=$(cd -- "$(dirname -- "$SELF")/../.." && pwd -P)
ROOT="${DFA_CTF_EVIDENCE_ROOT:-$(dirname -- "$PROJ")/evidence-ctf}"
MODEL="${DFA_MODEL:-deepseek/deepseek-v4-flash}"
TAG="${MODEL//\//-}"
case "${1:-}" in
  t1) EVID="$ROOT";                 TARGET="--pcap /evidence/promet.pcap";;
  t2) EVID="$ROOT/svjetionik";      TARGET="--memory /evidence/memory.dmp";;
  t3) EVID="$ROOT/autentifikacija"; TARGET="--pcap /evidence/challenge.pcap";;
  t4) EVID="$ROOT/krijumcar";       TARGET="--memory /evidence/memory.dmp";;
  *)  echo "task = t1|t2|t3|t4 ; usage: DFA_MODEL=<id> ./ctf.sh t2 \"<pitanje>\""; exit 1;;
esac
[ -d "$EVID" ] || { echo "evidence not found: $EVID (set DFA_CTF_EVIDENCE_ROOT)" >&2; exit 1; }
Q="${2:?trebam pitanje kao drugi argument}"
OUT="ctf_out/$TAG/$1.txt"; mkdir -p "$(dirname "$OUT")"
printf '\n### Q: %s\n' "$Q" | tee -a "$OUT"
# No --project-name: docker-compose.yml names the project, so this helper shares
# the image the installer built rather than building one of its own.
EVIDENCE="$EVID" RUNS="$PROJ/runs" CONFIG="$PROJ/config" WORK="$PROJ/work" \
  DFA_UID=10001 DFA_GID=10001 DFA_HOST_PLATFORM=windows DOCKER_CLI_HINTS=false MSYS_NO_PATHCONV=1 \
  docker compose --project-directory "$PROJ" \
  --file "$PROJ/docker-compose.yml" run --rm --no-deps -e MSYS_NO_PATHCONV=1 \
  -e "DFA_REASONING_EFFORT=high" -e "DFA_MODEL=$MODEL" \
  console ask $TARGET --question "$Q" 2>&1 | tee -a "$OUT"
