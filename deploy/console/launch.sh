#!/usr/bin/env bash
#
# Linux host launcher for the containerized DFIR Agent console.

set -Eeuo pipefail

fail() {
    printf 'dfir-agent: %s\n' "$*" >&2
    exit 1
}

launcher_path=$(readlink -f -- "${BASH_SOURCE[0]}") ||
    fail "the installed launcher path could not be resolved."
launcher_directory=$(dirname -- "$launcher_path")
root_file="$launcher_directory/project-root.txt"

[[ -f "$root_file" ]] ||
    fail "the installation is incomplete; run install.sh again."

project_root=$(<"$root_file")
[[ -n "$project_root" ]] ||
    fail "the recorded project directory is empty; run install.sh again."
[[ "$project_root" != *$'\n'* && "$project_root" != *$'\r'* ]] ||
    fail "the recorded project directory contains a forbidden control character."
compose_file="$project_root/docker-compose.yml"
[[ -f "$compose_file" ]] ||
    fail "the project directory no longer contains docker-compose.yml; run install.sh again."
preflight_file="$project_root/deploy/console/linux_docker_preflight.sh"
[[ -f "$preflight_file" ]] ||
    fail "the project directory no longer contains the Linux Docker preflight; run install.sh again."

# shellcheck source=deploy/console/linux_docker_preflight.sh
source "$preflight_file"
DFA_ERROR_PREFIX=dfir-agent
dfa_require_local_docker
dfa_select_container_identity
dfa_prepare_selinux_security "$project_root"

agent_arguments=("$@")
launcher_working_directory=$PWD
known_commands=(tui doctor ask models setup)
converted_case_path=
private_evidence_root=$(realpath -m -- "$launcher_directory/../evidence-mount-root")
evidence_mount_arguments=()
authorized_evidence_paths=()
evidence_selection_kind=directory
evidence_entry_file=
evidence_selection_source_path=
# Operator-facing case name, rewritten by every evidence selection below. It
# starts cleared so a value left in the invoking shell cannot label this case.
DFA_CASE_LABEL=
export DFA_CASE_LABEL

validate_path_text() {
    local value=$1
    local label=$2
    [[ -n "$value" ]] || fail "$label must not be empty."
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] ||
        fail "$label contains a forbidden control character."
    if printf '%s' "$value" | LC_ALL=C grep -q '[[:cntrl:]]'; then
        fail "$label contains a forbidden control character."
    fi
    case "$value" in
        *$'\u061c'*|*$'\u200e'*|*$'\u200f'*|*$'\u202a'*|*$'\u202b'*|\
        *$'\u202c'*|*$'\u202d'*|*$'\u202e'*|*$'\u2066'*|*$'\u2067'*|\
        *$'\u2068'*|*$'\u2069'*)
            fail "$label contains a forbidden bidirectional control character."
            ;;
    esac
}

clear_private_evidence_root() {
    local item
    [[ -e "$private_evidence_root" ]] || return 0
    [[ -d "$private_evidence_root" && ! -L "$private_evidence_root" ]] ||
        fail "the private evidence mount root must be a direct directory."
    shopt -s nullglob dotglob
    for item in "$private_evidence_root"/*; do
        [[ -f "$item" && ! -L "$item" && ! -s "$item" ]] ||
            fail "the private evidence mount root contains an unexpected item: $item"
        rm -f -- "$item"
    done
    shopt -u nullglob dotglob
}

initialize_private_evidence_root() {
    mkdir -p -- "$private_evidence_root"
    [[ -d "$private_evidence_root" && ! -L "$private_evidence_root" ]] ||
        fail "the private evidence mount root must be a direct directory."
    chmod 700 -- "$private_evidence_root"
    clear_private_evidence_root
}

collect_segmented_evidence_files() {
    local primary=$1
    local directory selected_name segment_stem segment_kind first_segment_name
    local candidate candidate_name resolved_candidate
    local -a candidates

    directory=$(dirname -- "$primary")
    selected_name=$(basename -- "$primary")
    # Every single evidence file the launcher can mount passes through here, so
    # this is where a kind the console no longer opens has to be turned away.
    # A .plaso store is the one such kind left: mounting one would open a case
    # whose only source was then silently ignored, which reads as an empty
    # investigation rather than as an unsupported file.
    if [[ "${selected_name,,}" == *.plaso ]]; then
        fail "timeline evidence is no longer supported: $primary. Open the disk image, memory image or capture it was built from."
    fi
    segment_stem=
    segment_kind=
    first_segment_name=
    if [[ "$selected_name" =~ ^(.+)\.[Ee][Xx][0-9]{2}$ ]]; then
        segment_stem=${BASH_REMATCH[1]}
        segment_kind=ewfx
        first_segment_name="${segment_stem}.Ex01"
    elif [[ "$selected_name" =~ ^(.+)\.[Ee]([0-9]{2}|[A-Za-z]{2})$ ]]; then
        segment_stem=${BASH_REMATCH[1]}
        segment_kind=ewf
        first_segment_name="${segment_stem}.E01"
    elif [[ "${selected_name,,}" =~ \.(7z|zip|rar|tar|gz|bz2|xz)\.[0-9]{3}$ ]]; then
        fail "multipart archive volumes cannot be opened as disk images: $primary"
    elif [[ "$selected_name" =~ ^(.+)\.[0-9]{3}$ ]]; then
        segment_stem=${BASH_REMATCH[1]}
        segment_kind=raw
        first_segment_name="${segment_stem}.001"
    fi

    authorized_evidence_paths=("$primary")
    evidence_entry_file=$primary
    [[ -n "$segment_kind" ]] || return 0

    authorized_evidence_paths=()
    evidence_entry_file=
    shopt -s nullglob dotglob
    candidates=("$directory"/*)
    shopt -u nullglob dotglob
    for candidate in "${candidates[@]}"; do
        candidate_name=$(basename -- "$candidate")
        case "$segment_kind" in
            ewfx)
                [[ "$candidate_name" =~ ^(.+)\.[Ee][Xx][0-9]{2}$ ]] || continue
                ;;
            ewf)
                [[ "$candidate_name" =~ ^(.+)\.[Ee]([0-9]{2}|[A-Za-z]{2})$ ]] ||
                    continue
                ;;
            raw)
                [[ "$candidate_name" =~ ^(.+)\.[0-9]{3}$ ]] || continue
                ;;
        esac
        [[ "${BASH_REMATCH[1]}" == "$segment_stem" ]] || continue
        [[ -f "$candidate" && ! -L "$candidate" ]] ||
            fail "an evidence segment is not a direct regular file: $candidate"
        resolved_candidate=$(realpath -- "$candidate")
        authorized_evidence_paths+=("$resolved_candidate")
        if [[ "${candidate_name,,}" == "${first_segment_name,,}" ]]; then
            evidence_entry_file=$resolved_candidate
        fi
    done
    ((${#authorized_evidence_paths[@]} > 0)) ||
        fail "the selected evidence segment set could not be resolved."
    [[ -n "$evidence_entry_file" ]] ||
        fail "the selected split evidence set is missing its first segment: $directory/$first_segment_name"
}

set_evidence_mount_selection() {
    local evidence_item=$1
    local file file_name

    if [[ -d "$evidence_item" ]]; then
        clear_private_evidence_root
        EVIDENCE=$evidence_item
        converted_case_path=/evidence
        evidence_mount_arguments=()
        authorized_evidence_paths=("$evidence_item")
        evidence_selection_kind=directory
        evidence_selection_source_path=$evidence_item
        # The directory always mounts at /evidence, so its real name is
        # invisible in-container; carry it for display, as launch.ps1 does.
        DFA_CASE_LABEL=$(basename -- "$evidence_item")
        export EVIDENCE DFA_CASE_LABEL
        return 0
    fi

    # A single file (or segment set) mounts under its own name, so the folder it
    # came from is what names the case for the operator, exactly as launch.ps1
    # does. Display only, never the identity.
    DFA_CASE_LABEL=$(basename -- "$(dirname -- "$evidence_item")")
    export DFA_CASE_LABEL

    collect_segmented_evidence_files "$evidence_item"
    set_evidence_mount_file_set \
        "$evidence_entry_file" \
        "${authorized_evidence_paths[@]}"
}

set_evidence_mount_file_set() {
    local entry_file=$1
    shift
    local -a files=("$@")
    local file file_name

    initialize_private_evidence_root
    EVIDENCE=$private_evidence_root
    converted_case_path="/evidence/$(basename -- "$entry_file")"
    evidence_mount_arguments=()
    evidence_selection_kind=files
    evidence_selection_source_path=$entry_file
    authorized_evidence_paths=("${files[@]}")
    for file in "${files[@]}"; do
        [[ "$file" != *:* ]] ||
            fail "an evidence filename containing ':' cannot be mounted safely: $file"
        file_name=$(basename -- "$file")
        [[ ! -e "$private_evidence_root/$file_name" ]] ||
            fail "duplicate evidence segment name: $file_name"
        : >"$private_evidence_root/$file_name"
        chmod 400 -- "$private_evidence_root/$file_name"
        evidence_mount_arguments+=(
            --volume
            "$file:/evidence/$file_name:ro"
        )
    done
    export EVIDENCE
}

add_evidence_mount_file_set() {
    local attachment_entry=$1
    shift
    local -a attachment_files=("$@")
    local -a combined=("${authorized_evidence_paths[@]}")
    local current_entry=$evidence_selection_source_path
    local known file file_name path_key name_key case_root case_entry
    declare -A known_names=()
    declare -A known_paths=()

    for known in "${authorized_evidence_paths[@]}"; do
        [[ -f "$known" ]] || continue
        file_name=$(basename -- "$known")
        known_names["${file_name,,}"]=$known
        known_paths["${known,,}"]=1
    done
    if [[ "$evidence_selection_kind" == directory ]]; then
        case_root=${authorized_evidence_paths[0]}
        shopt -s nullglob dotglob
        for case_entry in "$case_root"/*; do
            file_name=$(basename -- "$case_entry")
            known_names["${file_name,,}"]=$case_entry
        done
        shopt -u nullglob dotglob
    fi
    for file in "${attachment_files[@]}"; do
        path_key=${file,,}
        file_name=$(basename -- "$file")
        name_key=${file_name,,}
        if [[ "$evidence_selection_kind" == directory &&
            "$file" == "$case_root/"* ]]; then
            continue
        fi
        [[ -z "${known_paths[$path_key]+x}" ]] || continue
        [[ -z "${known_names[$name_key]+x}" ]] ||
            fail "evidence filename collision: $file_name. Reopen one folder containing uniquely named sources."
        known_names["$name_key"]=$file
        known_paths["$path_key"]=1
        combined+=("$file")
    done
    if [[ "$evidence_selection_kind" == directory ]]; then
        evidence_mount_arguments=()
        for file in "${combined[@]:1}"; do
            [[ "$file" != *:* ]] ||
                fail "an evidence filename containing ':' cannot be mounted safely: $file"
            file_name=$(basename -- "$file")
            evidence_mount_arguments+=(
                --volume
                "$file:/evidence/$file_name:ro"
            )
        done
        authorized_evidence_paths=("${combined[@]}")
        if [[ "$attachment_entry" == "$case_root/"* ]]; then
            converted_attachment_path="/evidence/${attachment_entry#"$case_root/"}"
        else
            converted_attachment_path="/evidence/$(basename -- "$attachment_entry")"
        fi
        return 0
    fi
    set_evidence_mount_file_set "$current_entry" "${combined[@]}"
    converted_attachment_path="/evidence/$(basename -- "$attachment_entry")"
}

convert_case_path() {
    local host_path=$1
    local resolved_path

    validate_path_text "$host_path" "the case path"
    if [[ -e "$host_path" ]]; then
        [[ ! -L "$host_path" ]] ||
            fail "the case path must not be a symbolic link: $host_path"
        resolved_path=$(realpath -- "$host_path")
        if [[ ! -d "$resolved_path" && ! -f "$resolved_path" ]]; then
            fail "the case path is not a regular file or directory: $host_path"
        fi
        set_evidence_mount_selection "$resolved_path"
        return 0
    fi

    if [[ "$host_path" == "/evidence" || "$host_path" == /evidence/* ]]; then
        converted_case_path=$host_path
        return 0
    fi
    fail "the case path does not exist: $host_path"
}

is_known_command() {
    local candidate=${1,,}
    local command_name
    for command_name in "${known_commands[@]}"; do
        [[ "$candidate" == "$command_name" ]] && return 0
    done
    return 1
}

# "dfir-agent /case PATH" is the console's own vocabulary typed at the shell
# prompt; dropping the token lets PATH flow into the bare-case shortcut below.
if ((${#agent_arguments[@]} > 0)) && [[ "${agent_arguments[0],,}" == "/case" ]]; then
    agent_arguments=("${agent_arguments[@]:1}")
fi

if ((${#agent_arguments[@]} > 0)); then
    first_argument=${agent_arguments[0]}
    if [[ "$first_argument" != -* ]] &&
        ! is_known_command "$first_argument"; then
        convert_case_path "$first_argument"
        agent_arguments=(tui --case "$converted_case_path" "${agent_arguments[@]:1}")
    else
        for ((index = 0; index < ${#agent_arguments[@]}; index++)); do
            argument=${agent_arguments[index]}
            if [[ "${argument,,}" == "--case" ]]; then
                ((index + 1 < ${#agent_arguments[@]})) ||
                    fail "--case requires a path."
                if convert_case_path "${agent_arguments[index + 1]}"; then
                    agent_arguments[index+1]=$converted_case_path
                fi
                break
            fi
            if [[ "${argument,,}" == --case=* ]]; then
                host_path=${argument#*=}
                if convert_case_path "$host_path"; then
                    agent_arguments[index]="--case=$converted_case_path"
                fi
                break
            fi
        done
    fi
fi

EVIDENCE=${EVIDENCE:-"$project_root/evidence"}
RUNS=${RUNS:-"$project_root/runs"}
CONFIG=${CONFIG:-"$project_root/config"}
WORK=${WORK:-"$project_root/work"}

validate_path_text "$EVIDENCE" "EVIDENCE"
validate_path_text "$RUNS" "RUNS"
validate_path_text "$CONFIG" "CONFIG"
validate_path_text "$WORK" "WORK"
[[ -d "$EVIDENCE" ]] ||
    fail "EVIDENCE must name an existing directory: $EVIDENCE"

EVIDENCE=$(realpath -- "$EVIDENCE")
[[ "$EVIDENCE" != "/" ]] ||
    fail "EVIDENCE must not overlap or alias writable runtime paths."
if [[ -z "$evidence_selection_source_path" ]]; then
    evidence_selection_source_path=$EVIDENCE
fi
RUNS=$(realpath -m -- "$RUNS")
CONFIG=$(realpath -m -- "$CONFIG")
WORK=$(realpath -m -- "$WORK")
dfa_reject_nested_mounts "$EVIDENCE"
dfa_verify_evidence_access_without_supplementary_groups "$EVIDENCE"
for evidence_file in "${authorized_evidence_paths[@]}"; do
    if [[ -f "$evidence_file" ]]; then
        dfa_verify_evidence_access_without_supplementary_groups "$evidence_file"
    fi
done

paths_overlap() {
    local first=$1
    local second=$2
    local identity_status
    if [[ "$first" == "/" || "$second" == "/" ]]; then
        return 0
    fi
    if [[ "$first" == "$second" || "$first" == "$second/"* || "$second" == "$first/"* ]]; then
        return 0
    fi
    if dfa_paths_share_identity_or_ancestry "$first" "$second"; then
        return 0
    else
        identity_status=$?
        ((identity_status == 1)) || return "$identity_status"
    fi
    return 1
}

assert_separate_paths() {
    local first=$1
    local first_label=$2
    local second=$3
    local second_label=$4
    local overlap_status
    if paths_overlap "$first" "$second"; then
        fail "$first_label and $second_label must not overlap or alias one another."
    else
        overlap_status=$?
        ((overlap_status == 1)) ||
            fail "$first_label and $second_label identities could not be verified."
    fi
}

assert_evidence_sources_separated_from_writable_roots() {
    local source link_count
    for source in "${authorized_evidence_paths[@]}"; do
        source=$(realpath -- "$source")
        if [[ -f "$source" ]]; then
            link_count=$(stat -c '%h' -- "$source") ||
                fail "the evidence file link count could not be verified: $source"
            ((link_count == 1)) ||
                fail "evidence files with multiple hard-link names cannot be mounted safely: $source"
        fi
        assert_separate_paths "$source" "evidence source" "$RUNS" RUNS
        assert_separate_paths "$source" "evidence source" "$CONFIG" CONFIG
        assert_separate_paths "$source" "evidence source" "$WORK" WORK
    done
}

assert_separate_paths "$EVIDENCE" EVIDENCE "$RUNS" RUNS
assert_separate_paths "$EVIDENCE" EVIDENCE "$CONFIG" CONFIG
assert_separate_paths "$EVIDENCE" EVIDENCE "$WORK" WORK
assert_separate_paths "$RUNS" RUNS "$CONFIG" CONFIG
assert_separate_paths "$RUNS" RUNS "$WORK" WORK
assert_separate_paths "$CONFIG" CONFIG "$WORK" WORK

umask 077
mkdir -p -- "$RUNS" "$CONFIG" "$WORK/home" "$WORK/cache"

# Resolve again after creation so a concurrently introduced symlink cannot
# bypass the pre-creation separation check.
RUNS=$(realpath -- "$RUNS")
CONFIG=$(realpath -- "$CONFIG")
WORK=$(realpath -- "$WORK")
assert_separate_paths "$EVIDENCE" EVIDENCE "$RUNS" RUNS
assert_separate_paths "$EVIDENCE" EVIDENCE "$CONFIG" CONFIG
assert_separate_paths "$EVIDENCE" EVIDENCE "$WORK" WORK
assert_separate_paths "$RUNS" RUNS "$CONFIG" CONFIG
assert_separate_paths "$RUNS" RUNS "$WORK" WORK
assert_separate_paths "$CONFIG" CONFIG "$WORK" WORK
assert_evidence_sources_separated_from_writable_roots
dfa_verify_writable_bind_ownership "$RUNS" "$CONFIG" "$WORK"

DFA_HOST_PLATFORM=linux
export EVIDENCE RUNS CONFIG WORK DFA_UID DFA_GID DFA_HOST_PLATFORM

console_image_name=
console_image_created_epoch=
staleness_warnings=()

moment_epoch() {
    local text=$1
    local trimmed=${text%%.*}
    # Docker records nanoseconds. The fraction is dropped before parsing rather
    # than after failing, and nothing compared here needs better than a second.
    # Whatever offset followed the fraction is kept.
    if [[ "$text" == *.* ]]; then
        trimmed="$trimmed$(printf '%s' "${text#*.}" | sed 's/^[0-9]*//')"
    fi
    [[ -n "$trimmed" ]] || return 1
    date -d "$trimmed" +%s 2>/dev/null
}

resolve_console_image_name() {
    local output
    # docker-compose.yml pins "name: dfir-agent" and Compose tags an image it
    # builds itself <project>-<service>, so this checkout resolves to
    # dfir-agent-console:latest wherever it happens to live. Asking Compose
    # rather than assembling that string keeps a later rename of the project in
    # one file; the literal below is only the answer for a Compose release
    # without "config --images".
    output=$(
        docker compose \
            --project-directory "$project_root" \
            --file "$compose_file" \
            "${DFA_DOCKER_OVERRIDE_ARGS[@]}" \
            config --images 2>/dev/null
    ) || output=
    console_image_name=${output%%$'\n'*}
    [[ -n "$console_image_name" ]] || console_image_name=dfir-agent-console
}

set_build_identity_variables() {
    local inspected
    # Nothing inside an image can name the image it is in, so the only place
    # this answer exists is out here, and the console shows whatever it is told.
    # An image that has not been built yet leaves both variables empty, which is
    # what the console reads as "unknown" rather than as an error.
    inspected=$(
        docker image inspect "$console_image_name" \
            --format '{{.Id}} {{.Created}}' 2>/dev/null
    ) || inspected=
    DFA_BUILD_ID=
    DFA_BUILD_TIME=
    export DFA_BUILD_ID DFA_BUILD_TIME
    [[ "$inspected" == *" "* ]] || return 0
    DFA_BUILD_ID=${inspected%% *}
    DFA_BUILD_TIME=${inspected##* }
    export DFA_BUILD_ID DFA_BUILD_TIME
    console_image_created_epoch=$(moment_epoch "$DFA_BUILD_TIME") ||
        console_image_created_epoch=
}

set_host_mount_variables() {
    # A container cannot see where a bind mount came from, so the console would
    # otherwise print /runtime/exports at an operator whose machine has no such
    # directory. Recomputed before every run rather than exported once: the
    # handoff loop below remounts a different host path and relaunches, and a
    # value captured before that would name the previous case.
    DFA_HOST_RUNS=$RUNS
    if [[ "$evidence_selection_kind" == directory ]]; then
        DFA_HOST_EVIDENCE=$EVIDENCE
    elif [[ -n "$evidence_selection_source_path" ]]; then
        # A single-file case mounts each file under its own name below
        # /evidence, and EVIDENCE names the private root of empty placeholders
        # rather than anything the operator owns. The directory the entry file
        # came from is what /evidence/<name> actually corresponds to.
        DFA_HOST_EVIDENCE=$(dirname -- "$evidence_selection_source_path")
    else
        DFA_HOST_EVIDENCE=
    fi
    export DFA_HOST_RUNS DFA_HOST_EVIDENCE
}

collect_staleness_warnings() {
    # Two separate things go stale, and an operator reading a defect report
    # cannot tell which without being told. The command they type is a copy of
    # deploy/console/launch.sh taken at install time, and the image is a copy of
    # the source taken at build time; either can predate the checkout while the
    # other is current. Both cost whole days when they pass unnoticed, because
    # the console then behaves like a version nobody is looking at.
    local checkout_launcher commit_text commit_epoch image_when commit_when
    staleness_warnings=()

    checkout_launcher="$project_root/deploy/console/launch.sh"
    # Contents, not dates: a git checkout does not preserve modification times,
    # so the tree's launcher can be older on disk than the installed copy and
    # still be the newer version.
    if command -v cmp >/dev/null 2>&1 &&
        [[ -f "$checkout_launcher" && -f "$launcher_path" ]] &&
        ! cmp -s -- "$launcher_path" "$checkout_launcher"; then
        staleness_warnings+=(
            "The installed dfir-agent command is not the launcher in the project directory."
            "  installed: $launcher_path"
            "  checkout:  $checkout_launcher"
            "  reinstall: $project_root/install.sh --skip-build"
        )
    fi

    # The image is compared against the checkout's newest commit rather than
    # against file modification times under src: a fresh clone stamps every file
    # with the moment it was cloned, which would report a correct image as stale
    # on the first launch after every clone. A commit date moves only when work
    # lands, so an image built from the current HEAD is always newer than it and
    # this cannot fire on a freshly built image. The one case it reports without
    # cause is building and then committing, where the image does hold the
    # committed code; that is a maintainer's order of work, not an operator's,
    # and it is answered by rebuilding or by DFA_ALLOW_STALE.
    [[ -n "$console_image_created_epoch" ]] || return 0
    commit_text=$(git -C "$project_root" log -1 --format=%cI 2>/dev/null) ||
        commit_text=
    [[ -n "$commit_text" ]] || return 0
    commit_epoch=$(moment_epoch "$commit_text") || commit_epoch=
    [[ -n "$commit_epoch" ]] || return 0
    ((console_image_created_epoch < commit_epoch)) || return 0
    image_when=$(date -d "@$console_image_created_epoch" '+%Y-%m-%d %H:%M')
    commit_when=$(date -d "@$commit_epoch" '+%Y-%m-%d %H:%M')
    staleness_warnings+=(
        "The image $console_image_name was built before the project directory's newest commit."
        "  image built:   $image_when"
        "  newest commit: $commit_when"
        "  rebuild: docker compose --project-directory $project_root --file $compose_file build console"
    )
}

confirm_staleness() {
    local answer
    collect_staleness_warnings
    ((${#staleness_warnings[@]} > 0)) || return 0
    printf '\n'
    printf '%s\n' \
        "dfir-agent is about to run something other than the project directory you launched it from."
    printf '%s\n' "${staleness_warnings[@]}"
    printf '%s\n' "The Session panel names the build that actually starts."
    printf '\n'
    # A warning printed here would be gone the moment the full screen console
    # draws over it, so the operator is stopped once, before the first run, and
    # never again inside the relaunch loop below. Refusing outright was the
    # other option and was rejected: reinstalling needs a running Docker and
    # rebuilding costs several gigabytes, so a refusal can strand someone whose
    # image is a day old and working. An unattended run cannot answer a prompt,
    # so it is warned and allowed to proceed rather than left hanging.
    [[ "${DFA_ALLOW_STALE:-}" != "1" ]] || return 0
    [[ -t 0 ]] || return 0
    printf 'Continue anyway? [y/N] '
    answer=
    IFS= read -r answer || answer=
    case "${answer,,}" in
        y|yes) return 0 ;;
    esac
    printf '%s\n' "Stopped. Set DFA_ALLOW_STALE=1 to skip this question."
    exit 1
}

resolve_console_image_name
set_build_identity_variables
set_host_mount_variables
confirm_staleness

if ((${#agent_arguments[@]} == 0)); then
    agent_arguments=(tui)
fi

tty_arguments=()
if [[ ! -t 0 || ! -t 1 ]]; then
    tty_arguments=(-T)
fi

set_evidence_launch_arguments() {
    local container_path=$1
    local action=$2
    shift 2
    local -a original=("$@")
    local -a updated=()
    local argument selected_option

    case "$action" in
        case) selected_option=--case ;;
        disk) selected_option=--image ;;
        memory) selected_option=--memory ;;
        network) selected_option=--pcap ;;
        *) fail "the terminal requested an unsupported evidence action." ;;
    esac

    for ((index = 0; index < ${#original[@]}; index++)); do
        argument=${original[index]}
        case "$argument" in
            --case|--image|--memory|--pcap)
                ((index + 1 < ${#original[@]})) ||
                    fail "$argument requires a path."
                index=$((index + 1))
                ;;
            --resume)
                ((index + 1 < ${#original[@]})) ||
                    fail "--resume requires an investigation identifier."
                index=$((index + 1))
                ;;
            --continue|--resume=*) ;;
            --case=*|--image=*|--memory=*|--pcap=*) ;;
            *) updated+=("$argument") ;;
        esac
    done
    if ((${#updated[@]} == 0)) || [[ "${updated[0]}" != tui ]]; then
        updated=(tui "${updated[@]}")
    fi
    agent_arguments=("${updated[@]}" "$selected_option" "$container_path")
}

explicit_evidence_option() {
    local path=${1,,}
    case "$path" in
        *.e01|*.ex01|*.dd|*.img|*.001|*.iso|*.vhd|*.vhdx)
            printf '%s\n' --image
            ;;
        *.mem|*.vmem|*.dmp) printf '%s\n' --memory ;;
        *.pcap|*.pcapng) printf '%s\n' --pcap ;;
        *)
            fail "the active single-file case type cannot be preserved while attaching another source. Reopen one folder containing all related sources."
            ;;
    esac
}

add_evidence_launch_arguments() {
    local container_path=$1
    local action=$2
    shift 2
    local -a original=("$@")
    local -a updated=()
    local argument option value selected_option index
    declare -A present=()

    case "$action" in
        attach-disk) selected_option=--image ;;
        attach-memory) selected_option=--memory ;;
        attach-network) selected_option=--pcap ;;
        *) fail "the terminal requested an unsupported attachment action." ;;
    esac

    for ((index = 0; index < ${#original[@]}; index++)); do
        argument=${original[index]}
        case "$argument" in
            --case|--image|--memory|--pcap)
                ((index + 1 < ${#original[@]})) ||
                    fail "$argument requires a path."
                value=${original[++index]}
                option=${argument,,}
                [[ "$option" != --case ||
                    "$evidence_selection_kind" == directory ]] ||
                    option=$(explicit_evidence_option "$value")
                [[ -z "${present[$option]+x}" ]] ||
                    fail "the active terminal contains duplicate evidence options."
                present["$option"]=1
                updated+=("$option" "$value")
                ;;
            --resume)
                ((index + 1 < ${#original[@]})) ||
                    fail "--resume requires an investigation identifier."
                index=$((index + 1))
                ;;
            --continue|--resume=*) ;;
            --case=*|--image=*|--memory=*|--pcap=*)
                option=${argument%%=*}
                value=${argument#*=}
                option=${option,,}
                [[ "$option" != --case ||
                    "$evidence_selection_kind" == directory ]] ||
                    option=$(explicit_evidence_option "$value")
                [[ -z "${present[$option]+x}" ]] ||
                    fail "the active terminal contains duplicate evidence options."
                present["$option"]=1
                updated+=("$option" "$value")
                ;;
            *) updated+=("$argument") ;;
        esac
    done
    [[ -z "${present[$selected_option]+x}" ]] ||
        fail "a source of this type is already attached. Use /case to replace the case, or reopen a folder containing the intended source set."
    if ((${#updated[@]} == 0)) || [[ "${updated[0]}" != tui ]]; then
        updated=(tui "${updated[@]}")
    fi
    planned_agent_arguments=("${updated[@]}" "$selected_option" "$container_path")
}

set_agent_model_argument() {
    local model=$1
    shift
    local -a original=("$@")
    local -a updated=()
    local argument index

    validate_path_text "$model" "the active model identifier"
    [[ "$model" != *[[:space:]]* ]] ||
        fail "the active model identifier contains whitespace."
    [[ "$model" != -* ]] ||
        fail "the active model identifier must not begin with '-'."
    for ((index = 0; index < ${#original[@]}; index++)); do
        argument=${original[index]}
        case "$argument" in
            -m|--model)
                ((index + 1 < ${#original[@]})) ||
                    fail "$argument requires a model identifier."
                index=$((index + 1))
                ;;
            -m=*|--model=*) ;;
            *) updated+=("$argument") ;;
        esac
    done
    agent_arguments=("${updated[@]}" --model "$model")
}

set_agent_resume_argument() {
    local conversation_id=$1
    shift
    local -a original=("$@")
    local -a updated=()
    local argument index

    validate_path_text "$conversation_id" "the active investigation identifier"
    [[ "$conversation_id" != *[[:space:]]* && "$conversation_id" != -* ]] ||
        fail "the active investigation identifier is invalid."
    for ((index = 0; index < ${#original[@]}; index++)); do
        argument=${original[index]}
        case "$argument" in
            --resume)
                ((index + 1 < ${#original[@]})) ||
                    fail "--resume requires an investigation identifier."
                index=$((index + 1))
                ;;
            --continue|--resume=*) ;;
            *) updated+=("$argument") ;;
        esac
    done
    agent_arguments=("${updated[@]}" --resume "$conversation_id")
}

host_case_handoff_exit_code=75
session_startup_failure_exit_code=78
handoff_preparation_cancelled_exit_code=79
host_case_handoff_schema=dfir-agent-host-case-v3
handoff_directory="$RUNS/.host-case-handoff"
mkdir -p -- "$handoff_directory"
[[ ! -L "$handoff_directory" ]] ||
    fail "the host case handoff directory must not be a symbolic link."

evidence_rollback_pending=0
rollback_agent_arguments=()
rollback_evidence=
rollback_evidence_mount_arguments=()
rollback_authorized_evidence_paths=()
rollback_evidence_selection_kind=
rollback_evidence_entry_file=
rollback_evidence_selection_source_path=
rollback_converted_case_path=
rollback_case_label=

clear_pending_evidence_rollback() {
    evidence_rollback_pending=0
    rollback_agent_arguments=()
    rollback_evidence=
    rollback_evidence_mount_arguments=()
    rollback_authorized_evidence_paths=()
    rollback_evidence_selection_kind=
    rollback_evidence_entry_file=
    rollback_evidence_selection_source_path=
    rollback_converted_case_path=
    rollback_case_label=
}

snapshot_evidence_rollback() {
    ((evidence_rollback_pending == 0)) ||
        fail "an evidence change is already awaiting session startup."
    rollback_agent_arguments=("${agent_arguments[@]}")
    rollback_evidence=$EVIDENCE
    rollback_evidence_mount_arguments=("${evidence_mount_arguments[@]}")
    rollback_authorized_evidence_paths=("${authorized_evidence_paths[@]}")
    rollback_evidence_selection_kind=$evidence_selection_kind
    rollback_evidence_entry_file=$evidence_entry_file
    rollback_evidence_selection_source_path=$evidence_selection_source_path
    rollback_converted_case_path=$converted_case_path
    rollback_case_label=$DFA_CASE_LABEL
    evidence_rollback_pending=1
}

restore_pending_evidence_rollback() {
    ((evidence_rollback_pending == 1)) ||
        fail "the previous evidence selection is not available."

    if [[ "$rollback_evidence_selection_kind" == files ]]; then
        [[ -n "$rollback_evidence_entry_file" ]] ||
            fail "the previous evidence entry file is not available."
        ((${#rollback_authorized_evidence_paths[@]} > 0)) ||
            fail "the previous evidence file set is not available."
        set_evidence_mount_file_set \
            "$rollback_evidence_entry_file" \
            "${rollback_authorized_evidence_paths[@]}"
    else
        clear_private_evidence_root
    fi

    agent_arguments=("${rollback_agent_arguments[@]}")
    EVIDENCE=$rollback_evidence
    evidence_mount_arguments=("${rollback_evidence_mount_arguments[@]}")
    authorized_evidence_paths=("${rollback_authorized_evidence_paths[@]}")
    evidence_selection_kind=$rollback_evidence_selection_kind
    evidence_entry_file=$rollback_evidence_entry_file
    evidence_selection_source_path=$rollback_evidence_selection_source_path
    converted_case_path=$rollback_converted_case_path
    DFA_CASE_LABEL=$rollback_case_label
    export EVIDENCE DFA_CASE_LABEL
    clear_pending_evidence_rollback
}

write_active_evidence_state() {
    local state_file=$1

    umask 077
    {
        declare -p agent_arguments
        declare -p EVIDENCE
        declare -p evidence_mount_arguments
        declare -p authorized_evidence_paths
        declare -p evidence_selection_kind
        declare -p evidence_entry_file
        declare -p evidence_selection_source_path
        declare -p converted_case_path
        declare -p DFA_CASE_LABEL
    } >"$state_file" ||
        fail "the prepared evidence state could not be recorded."
}

prepare_host_evidence_change() {
    local requested_action=$1
    local requested_host_path=$2
    local state_file=$3
    local confirmation attachment_entry attachment_container_path
    local previous_evidence_entry_file evidence_file
    local -a previous_authorized_evidence_paths=()
    local -a attachment_files=()
    local -a requested_paths=()

    validate_path_text "$requested_host_path" "the requested evidence path"
    case "$requested_host_path" in
        "~") requested_host_path=$HOME ;;
        "~/"*) requested_host_path="$HOME/${requested_host_path#\~/}" ;;
    esac
    if [[ "$requested_host_path" != /* ]]; then
        requested_host_path="$launcher_working_directory/$requested_host_path"
    fi
    if [[ ! -e "$requested_host_path" ]]; then
        printf 'Evidence path not found on the host: %s\n' \
            "$requested_host_path" >&2
        printf '%s\n' \
            "The terminal remains open with the previous evidence selection." >&2
        exit "$handoff_preparation_cancelled_exit_code"
    fi
    if [[ -L "$requested_host_path" ]]; then
        printf 'Evidence path must not be a symbolic link: %s\n' \
            "$requested_host_path" >&2
        printf '%s\n' \
            "The terminal remains open with the previous evidence selection." >&2
        exit "$handoff_preparation_cancelled_exit_code"
    fi
    requested_host_path=$(realpath -- "$requested_host_path")

    if [[ "$requested_action" == attach-* ]]; then
        if [[ ! -f "$requested_host_path" ]]; then
            printf '%s\n' \
                "/attach requires one evidence file. To discover a folder, use /case <path>." >&2
            exit "$handoff_preparation_cancelled_exit_code"
        fi
        previous_authorized_evidence_paths=("${authorized_evidence_paths[@]}")
        previous_evidence_entry_file=$evidence_entry_file
        collect_segmented_evidence_files "$requested_host_path"
        attachment_entry=$evidence_entry_file
        attachment_files=("${authorized_evidence_paths[@]}")
        authorized_evidence_paths=("${previous_authorized_evidence_paths[@]}")
        evidence_entry_file=$previous_evidence_entry_file
        attachment_container_path="/evidence/$(basename -- "$attachment_entry")"
        if [[ "$evidence_selection_kind" == directory &&
            "$attachment_entry" == "${authorized_evidence_paths[0]}/"* ]]; then
            attachment_container_path="/evidence/${attachment_entry#"${authorized_evidence_paths[0]}/"}"
        fi
        add_evidence_launch_arguments \
            "$attachment_container_path" \
            "$requested_action" \
            "${agent_arguments[@]}"

        printf 'The terminal requested read-only access to:\n'
        printf '  %s\n' "${attachment_files[@]}"
        printf 'Allow this host access? [y/N] '
        confirmation=
        IFS= read -r confirmation || confirmation=
        case "${confirmation,,}" in
            y|yes) ;;
            *)
                printf '%s\n' \
                    "Host access denied. Reopening the terminal with the previous evidence selection."
                exit "$handoff_preparation_cancelled_exit_code"
                ;;
        esac

        add_evidence_mount_file_set \
            "$attachment_entry" \
            "${attachment_files[@]}"
        assert_evidence_sources_separated_from_writable_roots
        agent_arguments=("${planned_agent_arguments[@]}")
        EVIDENCE=$(realpath -- "$EVIDENCE")
        dfa_reject_nested_mounts "$EVIDENCE"
        dfa_verify_evidence_access_without_supplementary_groups "$EVIDENCE"
        for evidence_file in "${authorized_evidence_paths[@]}"; do
            dfa_verify_evidence_access_without_supplementary_groups "$evidence_file"
        done
        assert_separate_paths "$EVIDENCE" EVIDENCE "$RUNS" RUNS
        assert_separate_paths "$EVIDENCE" EVIDENCE "$CONFIG" CONFIG
        assert_separate_paths "$EVIDENCE" EVIDENCE "$WORK" WORK
        export EVIDENCE
        write_active_evidence_state "$state_file"
        return 0
    fi

    if [[ -d "$requested_host_path" ]]; then
        requested_paths=("$requested_host_path")
    else
        previous_authorized_evidence_paths=("${authorized_evidence_paths[@]}")
        previous_evidence_entry_file=$evidence_entry_file
        collect_segmented_evidence_files "$requested_host_path"
        requested_paths=("${authorized_evidence_paths[@]}")
        authorized_evidence_paths=("${previous_authorized_evidence_paths[@]}")
        evidence_entry_file=$previous_evidence_entry_file
    fi
    printf 'The terminal requested read-only access to:\n'
    printf '  %s\n' "${requested_paths[@]}"
    printf 'Allow this host access? [y/N] '
    confirmation=
    IFS= read -r confirmation || confirmation=
    case "${confirmation,,}" in
        y|yes) ;;
        *)
            printf '%s\n' \
                "Host access denied. Reopening the terminal with the previous evidence selection."
            exit "$handoff_preparation_cancelled_exit_code"
            ;;
    esac

    convert_case_path "$requested_host_path" ||
        fail "the requested case path does not exist: $requested_host_path"
    EVIDENCE=$(realpath -- "$EVIDENCE")
    dfa_reject_nested_mounts "$EVIDENCE"
    dfa_verify_evidence_access_without_supplementary_groups "$EVIDENCE"
    for evidence_file in "${authorized_evidence_paths[@]}"; do
        if [[ -f "$evidence_file" ]]; then
            dfa_verify_evidence_access_without_supplementary_groups "$evidence_file"
        fi
    done
    assert_separate_paths "$EVIDENCE" EVIDENCE "$RUNS" RUNS
    assert_separate_paths "$EVIDENCE" EVIDENCE "$CONFIG" CONFIG
    assert_separate_paths "$EVIDENCE" EVIDENCE "$WORK" WORK
    assert_evidence_sources_separated_from_writable_roots
    export EVIDENCE
    set_evidence_launch_arguments \
        "$converted_case_path" \
        "$requested_action" \
        "${agent_arguments[@]}"
    write_active_evidence_state "$state_file"
}

DFA_SUPPRESS_BANNER=0
export DFA_SUPPRESS_BANNER

while true; do
    # The evidence selection changes on the handoff path below, so the host
    # roots the console displays are restated for every run rather than once.
    set_host_mount_variables
    handoff_token=$(
        od -An -N16 -tx1 /dev/urandom | tr -d '[:space:]'
    )
    [[ "$handoff_token" =~ ^[a-f0-9]{32}$ ]] ||
        fail "a secure host-path handoff token could not be generated."
    handoff_file="$handoff_directory/$handoff_token.request"
    rm -f -- "$handoff_file"
    DFA_HOST_CASE_REQUEST_TOKEN=$handoff_token
    DFA_HOST_CASE_REQUEST_FILE="/runtime/.host-case-handoff/$handoff_token.request"
    export DFA_HOST_CASE_REQUEST_TOKEN DFA_HOST_CASE_REQUEST_FILE

    set +e
    # No --project-name: docker-compose.yml names the project, so one checkout
    # and its re-clone share the one image instead of each building their own.
    docker compose \
        --progress quiet \
        --project-directory "$project_root" \
        --file "$compose_file" \
        "${DFA_DOCKER_OVERRIDE_ARGS[@]}" \
        run --rm --remove-orphans --no-deps \
        "${tty_arguments[@]}" \
        "${evidence_mount_arguments[@]}" \
        console "${agent_arguments[@]}"
    docker_status=$?
    set -e

    if ((docker_status == host_case_handoff_exit_code)); then
        # Reaching a later handoff proves that the pending evidence selection
        # started successfully. It is now the state a subsequent request must
        # preserve.
        clear_pending_evidence_rollback
        DFA_SUPPRESS_BANNER=1
        export DFA_SUPPRESS_BANNER
    elif ((docker_status == session_startup_failure_exit_code &&
        evidence_rollback_pending == 1)); then
        rm -f -- "$handoff_file"
        restore_pending_evidence_rollback
        printf '%s\n' \
            "The requested evidence could not start a new investigation. Reopening the previous investigation with its prior evidence selection." >&2
        continue
    else
        rm -f -- "$handoff_file"
        clear_private_evidence_root
        exit "$docker_status"
    fi
    [[ -f "$handoff_file" ]] ||
        fail "the terminal requested a host path without producing a valid handoff."
    [[ ! -L "$handoff_file" ]] ||
        fail "the terminal host-path handoff must not be a symbolic link."

    mapfile -t request_lines <"$handoff_file"
    rm -f -- "$handoff_file"
    ((${#request_lines[@]} == 6)) ||
        fail "the terminal produced an invalid host-path handoff."
    [[ "${request_lines[0]}" == "$host_case_handoff_schema" ]] ||
        fail "the terminal produced an unknown host-path handoff."
    [[ "${request_lines[1]}" == "$handoff_token" ]] ||
        fail "the terminal host-path handoff could not be authenticated."

    requested_action=${request_lines[2]}
    case "$requested_action" in
        case|disk|memory|network|\
        attach-disk|attach-memory|attach-network) ;;
        *) fail "the terminal requested an unsupported evidence action." ;;
    esac
    set_agent_model_argument "${request_lines[3]}" "${agent_arguments[@]}"
    if [[ -n "${request_lines[4]}" ]]; then
        set_agent_resume_argument "${request_lines[4]}" "${agent_arguments[@]}"
    fi
    snapshot_evidence_rollback
    handoff_state_file="$handoff_directory/$handoff_token.state"
    rm -f -- "$handoff_state_file"

    set +e
    (
        set -Eeuo pipefail
        prepare_host_evidence_change \
            "$requested_action" \
            "${request_lines[5]}" \
            "$handoff_state_file"
    )
    handoff_preparation_status=$?
    set -e

    if ((handoff_preparation_status ==
        handoff_preparation_cancelled_exit_code)); then
        rm -f -- "$handoff_state_file"
        restore_pending_evidence_rollback
        continue
    fi
    if ((handoff_preparation_status != 0)); then
        rm -f -- "$handoff_state_file"
        restore_pending_evidence_rollback
        printf '%s\n' \
            "The requested evidence could not be prepared safely. Reopening the previous investigation with its prior evidence selection." >&2
        continue
    fi
    if [[ ! -f "$handoff_state_file" || -L "$handoff_state_file" ]]; then
        rm -f -- "$handoff_state_file"
        restore_pending_evidence_rollback
        printf '%s\n' \
            "The requested evidence state was not recorded safely. Reopening the previous investigation with its prior evidence selection." >&2
        continue
    fi

    set +e
    # The file contains only declare output emitted by
    # write_active_evidence_state in the isolated preparation process.
    source "$handoff_state_file"
    handoff_state_status=$?
    set -e
    rm -f -- "$handoff_state_file"
    if ((handoff_state_status != 0)); then
        restore_pending_evidence_rollback
        printf '%s\n' \
            "The requested evidence state could not be loaded. Reopening the previous investigation with its prior evidence selection." >&2
        continue
    fi
    export EVIDENCE DFA_CASE_LABEL
    continue
done
