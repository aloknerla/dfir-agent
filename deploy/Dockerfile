# Official multi-architecture Python image, pinned to the inspected OCI index digest.
ARG PYTHON_IMAGE=python:3.12.10-slim-bookworm@sha256:fd95fa221297a88e1cf49c55ec1828edd7c5a428187e67b5d1805692d11588db
ARG CLAMAV_IMAGE=clamav/clamav@sha256:6f4a9e7d616ffc8d1070200fe35ac860735fdd522161a1043f94856e6ee13c28
# Debian bookworm packages no bulk-extractor, so the console compiles the pinned
# upstream release itself. The digest is the publisher's own release tarball and
# is checked before unpacking, giving the source the same fixed identity that an
# image digest gives the ClamAV scanner above.
ARG BULK_EXTRACTOR_VERSION=2.1.1
ARG BULK_EXTRACTOR_SHA256=0cd57c743581a66ea94d49edac2e89210c80a2a7cc90dd254d56940b3d41b7f7

FROM ${CLAMAV_IMAGE} AS clamav-runtime

FROM ${PYTHON_IMAGE} AS forensic-builder

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libewf-dev \
        libtsk-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv "$VIRTUAL_ENV" \
    && python -m pip install \
        pip==25.1.1 \
        setuptools==80.9.0 \
        wheel==0.45.1

WORKDIR /build
COPY pyproject.toml constraints.txt ./
COPY deploy/forensic-top-level-constraints.txt ./forensic-top-level-constraints.txt

RUN python - <<'PY'
import subprocess
import sys
import tomllib

with open("pyproject.toml", "rb") as file_object:
    project = tomllib.load(file_object)["project"]
dependencies = list(project["dependencies"])
optional = project["optional-dependencies"]
dependencies.extend(optional["forensics"])
# The full-screen console IS the interface now (CMD ["tui"]); an image
# without the tui extra starts and immediately dies on the textual import.
dependencies.extend(optional["tui"])
subprocess.check_call(
    [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--constraint",
        "constraints.txt",
        "--constraint",
        "forensic-top-level-constraints.txt",
        *dependencies,
    ]
)
PY

# Pillow backs ocr_image's preprocessing — the grayscale/threshold, colour-channel
# isolation and upscaling passes that let it read coloured text off a noisy
# background. It is an image-only need of that one tool, so it is pinned here
# rather than in pyproject.toml, whose dependency set governs host installs.
RUN python -m pip install --constraint constraints.txt Pillow==11.2.1

COPY README.md LICENSE NOTICE ./
COPY src ./src
RUN python -m pip install --no-deps --no-build-isolation . \
    && python -c "import dfvfs, py7zr, pyewf, pytsk3, regipy, volatility3" \
    && python -m pip freeze --all > "$VIRTUAL_ENV/image-python-packages.txt"


FROM ${PYTHON_IMAGE} AS python-runtime-base

ENV DEBIAN_FRONTEND=noninteractive \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app/src:/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    HOME=/tmp/home \
    XDG_CACHE_HOME=/tmp/xdg

# The disk and registry adapters import native shared libraries at load time, so
# the runtime carries libewf and libtsk even before any evidence is mounted.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libewf2 \
        libtsk19 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 dfir \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/dfir dfir \
    && install -d -o 10001 -g 10001 \
        /app /evidence /work /runtime \
    && install -d -o 10001 -g 10001 -m 1777 /payload

USER 10001:10001
WORKDIR /work
STOPSIGNAL SIGTERM


FROM python-runtime-base AS forensic-tools-runtime

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpsl5 \
        p7zip-full \
        regripper \
        sleuthkit \
        tesseract-ocr \
        tesseract-ocr-eng \
        tshark \
    && rm -f /usr/bin/dumpcap \
    && rm -rf /var/lib/apt/lists/* \
    && command -v 7z \
    && command -v fls \
    && command -v mergecap \
    && command -v regripper \
    && command -v tesseract \
    && command -v tshark \
    # libpsl carries the Public Suffix List, which decides the registrable
    # domain a hostname belongs to. It arrives anyway as a dependency of
    # libcurl4, and a delegation resting on another package's dependency is one
    # apt resolution away from becoming an in-house rule again.
    && ldconfig -p | grep -q libpsl

# Copy the scanner, its musl runtime, and its publisher-signed databases from one
# immutable official ClamAV image. The image never runs freshclam and cannot
# update signatures at runtime, so every session observes the same scanner bytes.
COPY --from=clamav-runtime /usr/bin/clamscan /opt/clamav-1.5.3/bin/clamscan
COPY --from=clamav-runtime /usr/lib /opt/clamav-1.5.3/lib
COPY --from=clamav-runtime /lib/ld-musl-*.so.1 /lib/
COPY --from=clamav-runtime /var/lib/clamav /opt/clamav-1.5.3/db
COPY --from=clamav-runtime /etc/clamav/certs /etc/clamav/certs
COPY deploy/clamav-wrapper.sh /usr/local/bin/memory-clamscan

RUN chmod 0555 /usr/local/bin/memory-clamscan /opt/clamav-1.5.3/bin/clamscan \
    && chmod -R a-w /opt/clamav-1.5.3 \
    && chmod -R a-w /etc/clamav/certs \
    && test "$(find /etc/clamav/certs -maxdepth 1 -type f -name 'clamav.crt' | wc -l)" -eq 1 \
    && test -s /etc/clamav/certs/clamav.crt \
    && test -s /opt/clamav-1.5.3/db/main.cvd \
    && test "$(find /opt/clamav-1.5.3/db -maxdepth 1 -type f -name 'main-*.cvd.sign' | wc -l)" -eq 1 \
    && test -s /opt/clamav-1.5.3/db/daily.cvd \
    && test "$(find /opt/clamav-1.5.3/db -maxdepth 1 -type f -name 'daily-*.cvd.sign' | wc -l)" -eq 1 \
    && test -s /opt/clamav-1.5.3/db/bytecode.cvd \
    && test "$(find /opt/clamav-1.5.3/db -maxdepth 1 -type f -name 'bytecode-*.cvd.sign' | wc -l)" -eq 1 \
    && /usr/local/bin/memory-clamscan --version
USER 10001:10001

ENV DFA_TSHARK=/usr/bin/tshark \
    DFA_MERGECAP=/usr/bin/mergecap \
    DFA_7Z=/usr/bin/7z \
    DFA_REGRIPPER=/usr/bin/regripper \
    DFA_TESSERACT=/usr/bin/tesseract \
    DFA_CLAMSCAN=/usr/local/bin/memory-clamscan \
    DFA_CLAMAV_DB=/opt/clamav-1.5.3/db


# ---------------------------------------------------------------------------
#  Bulk Extractor
# ---------------------------------------------------------------------------
# Debian bookworm has no bulk-extractor package, so the pinned upstream release
# is compiled here. A separate stage keeps the compiler, the fetched tarball and
# the unpacked sources out of the final image: only the finished version-stamped
# prefix is copied onward, and only into the console.
FROM ${PYTHON_IMAGE} AS bulk-extractor-builder

ARG BULK_EXTRACTOR_VERSION
ARG BULK_EXTRACTOR_SHA256

ENV DEBIAN_FRONTEND=noninteractive \
    BULK_EXTRACTOR_PREFIX=/opt/bulk_extractor-${BULK_EXTRACTOR_VERSION}

# The Debian/Ubuntu build dependencies this release documents in its own
# etc/CONFIGURE_UBUNTU20LTS.bash, plus the two packages needed to fetch the
# tarball at all, plus libewf-dev. The tarball ships a prebuilt ./configure, so
# no autoreconf toolchain is required.
#
# libewf-dev is NOT in the release's documented list, and without it ./configure
# silently compiles the E01 reader out: the binary then aborts with
# "This program was compiled without E01 support" on the EWF containers this
# project's evidence actually ships in, while every other tool here reads them
# through the libewf the forensic-builder stage already installs. It is added
# here so one stage's package list cannot decide which evidence containers a
# tool can open.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        flex \
        libabsl-dev \
        libewf-dev \
        libexpat1-dev \
        libre2-dev \
        libssl-dev \
        libtool \
        libxml2-utils \
        make \
        pkg-config \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# The publisher digest is verified before a single archive member is unpacked,
# so a substituted or truncated download can never reach the compiler. The
# runtime libraries are then read out of ldd rather than guessed and copied
# beside the binary: the console base does not carry libexpat, and a tool that
# resolved its libraries from whatever base it happened to land on would not be
# reproducible. That same ldd output is asserted to name libewf, because
# ./configure reports a missing EWF reader only as a line of build output and
# would otherwise leave the omission to be discovered by an aborted scan against
# real evidence. The RUN ends with the version check so a build that produces a
# non-working binary fails here instead of shipping one.
WORKDIR /build
RUN curl --fail --location --silent --show-error \
        --output "bulk_extractor-${BULK_EXTRACTOR_VERSION}.tar.gz" \
        "https://github.com/simsong/bulk_extractor/releases/download/v${BULK_EXTRACTOR_VERSION}/bulk_extractor-${BULK_EXTRACTOR_VERSION}.tar.gz" \
    && echo "${BULK_EXTRACTOR_SHA256}  bulk_extractor-${BULK_EXTRACTOR_VERSION}.tar.gz" | sha256sum -c - \
    && tar -xzf "bulk_extractor-${BULK_EXTRACTOR_VERSION}.tar.gz" \
    && cd "bulk_extractor-${BULK_EXTRACTOR_VERSION}" \
    && ./configure --prefix="${BULK_EXTRACTOR_PREFIX}" \
    && make -j"$(nproc)" \
    && make install \
    && install -d "${BULK_EXTRACTOR_PREFIX}/lib" \
    && ldd "${BULK_EXTRACTOR_PREFIX}/bin/bulk_extractor" > /build/bulk_extractor.ldd \
    && ! grep -q 'not found' /build/bulk_extractor.ldd \
    && grep -q 'libewf' /build/bulk_extractor.ldd \
    && awk '$2 == "=>" && $3 ~ /^\// { print $3 }' /build/bulk_extractor.ldd | sort -u \
        > /build/bulk_extractor.libs \
    && test "$(wc -l < /build/bulk_extractor.libs)" -ge 1 \
    && xargs -a /build/bulk_extractor.libs -I {} cp -L {} "${BULK_EXTRACTOR_PREFIX}/lib/" \
    && test "$(find "${BULK_EXTRACTOR_PREFIX}/lib" -maxdepth 1 -type f | wc -l)" \
        -eq "$(wc -l < /build/bulk_extractor.libs)" \
    && "${BULK_EXTRACTOR_PREFIX}/bin/bulk_extractor" -V


# ---------------------------------------------------------------------------
#  Interactive console
# ---------------------------------------------------------------------------
# The console is the single published image. It carries the pinned OS and
# forensic-tool layer plus the forensic Python environment.
#
# Evidence sources are mounted read-only. The container is unprivileged and
# inherits the non-root user from the runtime stage.
FROM forensic-tools-runtime AS console

LABEL org.opencontainers.image.title="DFIR Agent console" \
      org.opencontainers.image.description="Interactive forensic console with pinned tools"

COPY --from=forensic-builder /opt/venv /opt/venv
COPY --chown=10001:10001 pyproject.toml README.md constraints.txt LICENSE NOTICE /app/
COPY --chown=10001:10001 src /app/src
RUN command -v dfir-agent \
    && python -c "from forensic_agent.core.environ import vol_path; assert vol_path()"

# Bulk Extractor is compiled in its own stage and lands only here. The prefix
# carries its own libraries, the wrapper points the loader at them, and both are
# made read-only so an unprivileged session cannot alter the tool it is about to
# attribute findings to. The RUN ends with the version check: the console is
# proven to execute the tool at build time, not first discovered to be broken in
# the middle of an investigation.
ARG BULK_EXTRACTOR_VERSION
USER root
COPY --from=bulk-extractor-builder /opt/bulk_extractor-${BULK_EXTRACTOR_VERSION} /opt/bulk_extractor-${BULK_EXTRACTOR_VERSION}
COPY deploy/bulk-extractor-wrapper.sh /usr/local/bin/bulk_extractor

RUN chmod 0555 /usr/local/bin/bulk_extractor \
        /opt/bulk_extractor-${BULK_EXTRACTOR_VERSION}/bin/bulk_extractor \
    && chmod -R a-w /opt/bulk_extractor-${BULK_EXTRACTOR_VERSION} \
    && /usr/local/bin/bulk_extractor -V
USER 10001:10001

# Session records use a mounted directory rather than the container layer so
# the audit trail survives container removal. Reconstructed evidence content
# does the opposite: files a scan reconstructed and unpacked archive members
# are executables taken out of the evidence, so they are written below the
# payload volume, which the host filesystem does not see.
ENV DFA_RUNS_DIR=/runtime \
    DFA_PAYLOAD_ROOT=/payload \
    DFA_BULK_EXTRACTOR=/usr/local/bin/bulk_extractor

# Volatility identifies a memory image by scanning the whole symbol store for a
# matching kernel GUID, so the store is re-read by every memory plugin. Read
# across the host bind mount that scan costs 2631 ms for the 3015-file pack and
# 28 ms from container-local storage. The host directory below /work stays the
# source of truth and is copied into the local store the first time a container
# finds it missing; the copy is staged and renamed into place so an interrupted
# seed cannot leave a half-store that looks finished.
USER root
RUN cat >/usr/local/bin/dfir-agent-console <<'SH'
#!/bin/sh
set -eu

host_store=/work/volatility-symbols
local_store=/symbols/store
staging=/symbols/.staging.$$

say() {
    printf 'dfir-agent: %s\n' "$1" >&2
}

is_number() {
    case "${1:-}" in
        '' | *[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

# Size of a directory tree in kilobytes, or nothing when du cannot answer.
# The total to copy and the amount copied so far are both measured this way,
# so the ratio between them is a comparison of like with like rather than of
# two different notions of size.
tree_kb() {
    du -sk -- "$1" 2>/dev/null | cut -f1
}

# Whether /symbols is a mount of its own rather than a plain directory in the
# image. Started without the named volume, a container copies the whole store
# into a layer that is discarded when it exits, and pays the same cost again
# on the next run with nothing on screen to say why.
#
# Answers "mounted" whenever it cannot tell. A false warning that a volume is
# missing would send an operator looking for a fault that is not there, which
# is worse than staying quiet.
symbols_volume_mounted() {
    if [ -r /proc/mounts ]; then
        if grep -q ' /symbols ' /proc/mounts; then
            return 0
        fi
        return 1
    fi
    symbols_device=$(stat -c %d /symbols 2>/dev/null || true)
    root_device=$(stat -c %d / 2>/dev/null || true)
    if is_number "$symbols_device" && is_number "$root_device"; then
        if [ "$symbols_device" = "$root_device" ]; then
            return 1
        fi
    fi
    return 0
}

# A sign of life while cp is silent. Where the total is known this is a
# measured fraction of it; where it is not, it is a count of what has landed
# so far. Neither is ever a percentage nobody computed.
report_copy_progress() {
    while :; do
        sleep 5
        copied_kb=$(tree_kb "$staging")
        is_number "$copied_kb" || continue
        if is_number "${total_kb:-}"; then
            printf 'dfir-agent: symbol store %s MB of %s MB%b' \
                "$((copied_kb / 1024))" "$((total_kb / 1024))" "$progress_end" >&2
        else
            printf 'dfir-agent: symbol store %s MB copied%b' \
                "$((copied_kb / 1024))" "$progress_end" >&2
        fi
    done
}

seed_symbol_store() {
    total_kb=$(tree_kb "$host_store")
    if is_number "$total_kb"; then
        say "preparing the local symbol store, $((total_kb / 1024)) MB, first run only"
    else
        say "preparing the local symbol store, first run only"
        total_kb=""
    fi
    if ! symbols_volume_mounted; then
        say "the volatility-symbols volume is not mounted, so this copy is repeated on every run"
        say "mounting it pays the cost once; docker compose and the launchers already do"
    fi

    # Rewritten in place on a terminal, one line per update otherwise, so a
    # captured log records that the copy advanced without filling with redraws.
    if [ -t 2 ]; then
        progress_end='\r'
    else
        progress_end='\n'
    fi

    started=$(date +%s 2>/dev/null || true)
    mkdir -p -- "$staging" || return 1

    # The reporter is the background job and cp is the foreground one, so the
    # loop is ended by killing a child this script started rather than by
    # polling for the disappearance of one that may still be unreaped.
    report_copy_progress &
    reporter=$!
    copied=0
    if cp -r -- "$host_store/." "$staging/"; then
        copied=1
    fi
    kill "$reporter" 2>/dev/null || true
    wait "$reporter" 2>/dev/null || true
    if [ -t 2 ]; then
        printf '\r%-60s\r' '' >&2
    fi

    if [ "$copied" -ne 1 ] || ! mv -- "$staging" "$local_store"; then
        rm -rf -- "$staging"
        say "the local symbol store could not be prepared; the host copy is used instead"
        return 1
    fi

    finished=$(date +%s 2>/dev/null || true)
    if is_number "$started" && is_number "$finished"; then
        say "symbol store ready in $((finished - started))s"
    else
        say "symbol store ready"
    fi
    return 0
}

if [ ! -d "$local_store" ] && [ -w /symbols ] &&
    [ -n "$(ls -A "$host_store" 2>/dev/null || true)" ]; then
    seed_symbol_store || true
fi

# An explicit setting is the operator's and is never second-guessed. Otherwise
# the fast local copy wins, and the host directory remains the fallback for a
# workstation whose volume could not be seeded.
if [ -z "${DFA_VOL_SYMBOL_DIRS:-}" ]; then
    if [ -d "$local_store" ]; then
        export DFA_VOL_SYMBOL_DIRS="$local_store"
    elif [ -d "$host_store" ]; then
        export DFA_VOL_SYMBOL_DIRS="$host_store"
    fi
fi

exec dfir-agent "$@"
SH

RUN install -d -o 10001 -g 10001 -m 1777 /symbols \
    && chmod 0555 /usr/local/bin/dfir-agent-console \
    && sh -n /usr/local/bin/dfir-agent-console
USER 10001:10001

WORKDIR /work
ENTRYPOINT ["dfir-agent-console"]
CMD ["tui"]
