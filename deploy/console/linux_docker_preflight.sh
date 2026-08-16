#!/usr/bin/env bash
#
# Shared Linux Docker checks for the installer and console launcher.
# This file is sourced; it is not an independent command.

# shellcheck shell=bash

dfa_preflight_error() {
    printf '%s: %s\n' "${DFA_ERROR_PREFIX:-dfir-agent}" "$*" >&2
    return 1
}

dfa_require_local_docker() {
    local context_name endpoint

    command -v docker >/dev/null 2>&1 ||
        dfa_preflight_error "Docker was not found. Install Docker Engine and the Compose plugin." ||
        return 1
    docker compose version >/dev/null 2>&1 ||
        dfa_preflight_error "Docker Compose is unavailable. Install the Docker Compose plugin." ||
        return 1

    if [[ -n ${DOCKER_CONTEXT:-} ]]; then
        context_name=$DOCKER_CONTEXT
        endpoint=$(
            docker context inspect "$context_name" \
                --format '{{.Endpoints.docker.Host}}' 2>/dev/null
        ) ||
            dfa_preflight_error "Docker context '$context_name' could not be inspected." ||
            return 1
    elif [[ -n ${DOCKER_HOST:-} ]]; then
        context_name=DOCKER_HOST
        endpoint=$DOCKER_HOST
    else
        context_name=$(docker context show 2>/dev/null) ||
            dfa_preflight_error "The active Docker context could not be determined." ||
            return 1
        [[ -n "$context_name" ]] ||
            dfa_preflight_error "The active Docker context has an empty name." ||
            return 1
        endpoint=$(
            docker context inspect "$context_name" \
                --format '{{.Endpoints.docker.Host}}' 2>/dev/null
        ) ||
            dfa_preflight_error "Docker context '$context_name' could not be inspected." ||
            return 1
    fi

    case "$endpoint" in
        unix:///*) ;;
        "")
            dfa_preflight_error \
                "Docker context '$context_name' did not report a daemon endpoint." ||
                return 1
            ;;
        *)
            dfa_preflight_error \
                "Docker context '$context_name' uses '$endpoint'. DFIR Agent requires a local Unix Docker socket because evidence and runtime directories are bind-mounted from this workstation." ||
                return 1
            ;;
    esac

    docker info >/dev/null 2>&1 ||
        dfa_preflight_error "The Docker daemon is unavailable or the current user cannot access it." ||
        return 1

    DFA_DOCKER_CONTEXT=$context_name
    DFA_DOCKER_ENDPOINT=$endpoint
    export DFA_DOCKER_CONTEXT DFA_DOCKER_ENDPOINT
}

dfa_select_container_identity() {
    local security_options

    security_options=$(
        docker info --format '{{json .SecurityOptions}}' 2>/dev/null
    ) ||
        dfa_preflight_error "Docker security options could not be inspected." ||
        return 1

    if [[ "$security_options" == *rootless* ]]; then
        # In rootless Docker, container UID 0 maps to the invoking unprivileged
        # host user. Using the host numeric UID here would map to a subordinate
        # UID and make host-owned bind mounts unwritable.
        DFA_UID=0
        DFA_GID=0
        DFA_DOCKER_IDENTITY_MODE=rootless
    elif [[ "$security_options" == *userns* ]]; then
        dfa_preflight_error \
            "Docker userns-remap is enabled. Portable ownership mapping for writable bind mounts cannot be derived safely. Use rootless Docker, or a daemon without userns-remap, for DFIR Agent." ||
            return 1
    else
        DFA_UID=$(id -u)
        DFA_GID=$(id -g)
        DFA_DOCKER_IDENTITY_MODE=host
    fi

    export DFA_UID DFA_GID DFA_DOCKER_IDENTITY_MODE
}

dfa_set_compose_project_name() {
    local project_root=$1
    local digest digest_line

    if command -v sha256sum >/dev/null 2>&1; then
        digest_line=$(printf '%s' "$project_root" | sha256sum) ||
            dfa_preflight_error "The project directory hash could not be calculated." ||
            return 1
        digest=${digest_line%% *}
    elif command -v shasum >/dev/null 2>&1; then
        digest_line=$(printf '%s' "$project_root" | shasum -a 256) ||
            dfa_preflight_error "The project directory hash could not be calculated." ||
            return 1
        digest=${digest_line%% *}
    else
        dfa_preflight_error "sha256sum or shasum is required to derive the Docker project name." ||
            return 1
    fi
    [[ "$digest" =~ ^[[:xdigit:]]{64}$ ]] ||
        dfa_preflight_error "The project directory hash has an invalid format." ||
        return 1

    DFA_COMPOSE_PROJECT_NAME="dfir-agent-${digest:0:12}"
    export DFA_COMPOSE_PROJECT_NAME
}

dfa_selinux_mode() {
    local mode

    if command -v getenforce >/dev/null 2>&1; then
        mode=$(getenforce 2>/dev/null || true)
        printf '%s\n' "${mode:-Unknown}"
        return 0
    fi
    if [[ -r /sys/fs/selinux/enforce ]]; then
        mode=$(< /sys/fs/selinux/enforce)
        if [[ "$mode" == 1 ]]; then
            printf 'Enforcing\n'
        else
            printf 'Permissive\n'
        fi
        return 0
    fi
    printf 'Disabled\n'
}

dfa_prepare_selinux_security() {
    local project_root=$1
    local allow_value mode override_file

    DFA_DOCKER_OVERRIDE_ARGS=()
    mode=$(dfa_selinux_mode)
    if [[ "${mode,,}" != enforcing ]]; then
        return 0
    fi

    allow_value=${DFA_ALLOW_SELINUX_LABEL_DISABLE:-}
    case "${allow_value,,}" in
        1|true|yes)
            # Disabling the container label avoids :z/:Z and therefore avoids
            # changing the SELinux label of evidence. This weakens SELinux
            # isolation, so it is never enabled implicitly.
            override_file="$project_root/deploy/console/compose.selinux-label-disable.yml"
            [[ -f "$override_file" ]] ||
                dfa_preflight_error "The SELinux Compose override is missing: $override_file" ||
                return 1
            DFA_DOCKER_OVERRIDE_ARGS=(--file "$override_file")
            ;;
        *)
            dfa_preflight_error \
                "SELinux is enforcing. DFIR Agent will not relabel forensic evidence. If policy permits reduced SELinux confinement for this container, set DFA_ALLOW_SELINUX_LABEL_DISABLE=1 and run the command again." ||
                return 1
            ;;
    esac
}

dfa_decode_findmnt_field() {
    local remaining=$1
    local decoded= byte

    if [[ "${remaining,,}" == *'\x0a'* || "${remaining,,}" == *'\x0d'* ]]; then
        dfa_preflight_error "Mount paths containing line breaks are not supported." ||
            return 2
    fi
    while [[ "$remaining" =~ ^([^\\]*)\\x([[:xdigit:]]{2})(.*)$ ]]; do
        decoded+=${BASH_REMATCH[1]}
        printf -v byte '%b' "\\x${BASH_REMATCH[2]}"
        decoded+=$byte
        remaining=${BASH_REMATCH[3]}
    done
    decoded+=$remaining
    printf '%s\n' "$decoded"
}

dfa_filesystem_coordinate() {
    local requested_path=$1
    local anchor suffix component
    local device filesystem_root mount_target relative coordinate

    command -v findmnt >/dev/null 2>&1 ||
        dfa_preflight_error "findmnt is required to verify bind-mount boundaries." ||
        return 2

    anchor=$requested_path
    suffix=
    while [[ ! -e "$anchor" ]]; do
        [[ "$anchor" != / ]] ||
            dfa_preflight_error "No existing ancestor could be found for: $requested_path" ||
            return 2
        component=$(basename -- "$anchor")
        if [[ -n "$suffix" ]]; then
            suffix="$component/$suffix"
        else
            suffix=$component
        fi
        anchor=$(dirname -- "$anchor")
    done
    anchor=$(realpath -- "$anchor") ||
        dfa_preflight_error "The existing path ancestor could not be resolved: $anchor" ||
        return 2

    device=$(findmnt --target "$anchor" --noheadings --first-only --raw \
        --output MAJ:MIN 2>/dev/null) ||
        dfa_preflight_error "The containing mount could not be identified: $anchor" ||
        return 2
    filesystem_root=$(findmnt --target "$anchor" --noheadings --first-only --raw \
        --output FSROOT 2>/dev/null) ||
        dfa_preflight_error "The filesystem root could not be identified: $anchor" ||
        return 2
    mount_target=$(findmnt --target "$anchor" --noheadings --first-only --raw \
        --output TARGET 2>/dev/null) ||
        dfa_preflight_error "The mount target could not be identified: $anchor" ||
        return 2
    filesystem_root=$(dfa_decode_findmnt_field "$filesystem_root") || return $?
    mount_target=$(dfa_decode_findmnt_field "$mount_target") || return $?
    [[ -n "$device" && -n "$filesystem_root" && -n "$mount_target" ]] ||
        dfa_preflight_error "Incomplete mount metadata was returned for: $anchor" ||
        return 2

    if [[ "$anchor" == "$mount_target" ]]; then
        relative=
    elif [[ "$mount_target" == / && "$anchor" == /* ]]; then
        relative=${anchor#/}
    elif [[ "$anchor" == "$mount_target/"* ]]; then
        relative=${anchor#"$mount_target/"}
    else
        dfa_preflight_error \
            "The mount target '$mount_target' does not contain '$anchor'." ||
            return 2
    fi

    coordinate=$filesystem_root
    [[ -z "$relative" ]] || coordinate="${coordinate%/}/$relative"
    [[ -z "$suffix" ]] || coordinate="${coordinate%/}/$suffix"
    coordinate="/${coordinate#/}"
    [[ "$coordinate" == / ]] || coordinate=${coordinate%/}
    printf '%s\t%s\n' "$device" "$coordinate"
}

dfa_paths_share_identity_or_ancestry() {
    local first=$1
    local second=$2
    local first_record second_record
    local first_device first_coordinate second_device second_coordinate

    first_record=$(dfa_filesystem_coordinate "$first") || return $?
    second_record=$(dfa_filesystem_coordinate "$second") || return $?
    IFS=$'\t' read -r first_device first_coordinate <<<"$first_record"
    IFS=$'\t' read -r second_device second_coordinate <<<"$second_record"

    [[ "$first_device" == "$second_device" ]] || return 1
    if [[ "$first_coordinate" == / || "$second_coordinate" == / ]]; then
        return 0
    fi
    [[
        "$first_coordinate" == "$second_coordinate" ||
            "$first_coordinate" == "$second_coordinate/"* ||
            "$second_coordinate" == "$first_coordinate/"*
    ]]
}

dfa_reject_nested_mounts() {
    local evidence=$1
    local mount_listing mount_target resolved_target

    command -v findmnt >/dev/null 2>&1 ||
        dfa_preflight_error "findmnt is required to verify evidence mount boundaries." ||
        return 1
    mount_listing=$(findmnt --noheadings --raw --output TARGET 2>/dev/null) ||
        dfa_preflight_error "Mounted filesystems could not be enumerated." ||
        return 1
    while IFS= read -r mount_target; do
        [[ -n "$mount_target" ]] || continue
        mount_target=$(dfa_decode_findmnt_field "$mount_target") || return $?
        resolved_target=$(realpath -- "$mount_target" 2>/dev/null || true)
        [[ -n "$resolved_target" ]] || continue
        if [[ "$resolved_target" == "$evidence/"* ]]; then
            dfa_preflight_error \
                "Evidence contains the nested mount '$resolved_target'. Nested mounts are rejected because recursive read-only enforcement varies by kernel and Docker version." ||
                return 1
        fi
    done <<<"$mount_listing"
}

dfa_verify_writable_bind_ownership() {
    local directory owner group mode group_bits current_uid primary_gid
    local supplemental_groups

    current_uid=$(id -u)
    primary_gid=$(id -g)
    supplemental_groups=" $(id -G) "
    for directory in "$@"; do
        [[ -w "$directory" && -x "$directory" ]] ||
            dfa_preflight_error "The current user cannot write to the runtime directory: $directory" ||
            return 1
        [[ "$DFA_DOCKER_IDENTITY_MODE" == host ]] || continue

        owner=$(stat -Lc '%u' -- "$directory") ||
            dfa_preflight_error "The runtime directory owner could not be read: $directory" ||
            return 1
        group=$(stat -Lc '%g' -- "$directory") ||
            dfa_preflight_error "The runtime directory group could not be read: $directory" ||
            return 1
        mode=$(stat -Lc '%a' -- "$directory") ||
            dfa_preflight_error "The runtime directory mode could not be read: $directory" ||
            return 1
        group_bits=$(((8#$mode >> 3) & 7))

        if [[ "$owner" != "$current_uid" &&
            "$group" != "$primary_gid" &&
            "$supplemental_groups" == *" $group "* &&
            $((group_bits & 3)) -eq 3 ]]; then
            dfa_preflight_error \
                "The runtime directory '$directory' is writable only through supplementary group $group, which Docker Compose does not propagate to this container. Use a directory owned by UID $current_uid or primary GID $primary_gid." ||
                return 1
        fi
    done
}

dfa_verify_evidence_access_without_supplementary_groups() {
    local evidence=$1
    local entry owner group mode required_bits group_bits other_bits
    local current_uid primary_gid supplemental_groups
    local -a entries

    current_uid=$(id -u)
    primary_gid=$(id -g)
    supplemental_groups=" $(id -G) "
    shopt -s nullglob dotglob
    entries=("$evidence" "$evidence"/*)
    shopt -u nullglob dotglob

    for entry in "${entries[@]}"; do
        [[ -L "$entry" ]] && continue
        owner=$(stat -Lc '%u' -- "$entry") ||
            dfa_preflight_error "The evidence owner could not be read: $entry" ||
            return 1
        group=$(stat -Lc '%g' -- "$entry") ||
            dfa_preflight_error "The evidence group could not be read: $entry" ||
            return 1
        mode=$(stat -Lc '%a' -- "$entry") ||
            dfa_preflight_error "The evidence mode could not be read: $entry" ||
            return 1
        if [[ -d "$entry" ]]; then
            required_bits=5
        else
            required_bits=4
        fi
        group_bits=$(((8#$mode >> 3) & 7))
        other_bits=$((8#$mode & 7))

        [[ "$owner" == "$current_uid" ]] && continue
        if [[ "$group" == "$primary_gid" &&
            $((group_bits & required_bits)) -eq required_bits ]]; then
            continue
        fi
        if (((other_bits & required_bits) == required_bits)); then
            continue
        fi
        if [[ "$supplemental_groups" == *" $group "* &&
            $((group_bits & required_bits)) -eq required_bits ]]; then
            dfa_preflight_error \
                "Evidence '$entry' is accessible only through supplementary group $group, which Docker Compose does not propagate to this container. Grant read access to UID $current_uid, primary GID $primary_gid, or another safe read-only path." ||
                return 1
        fi
        if [[ ! -r "$entry" || (-d "$entry" && ! -x "$entry") ]]; then
            dfa_preflight_error "The current user cannot read the evidence path: $entry" ||
                return 1
        fi
    done
}
