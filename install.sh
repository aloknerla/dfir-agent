#!/usr/bin/env bash
#
# Install the containerized DFIR Agent launcher for one Linux user.

set -Eeuo pipefail

usage() {
    cat <<'EOF'
Usage: ./install.sh [options]

Options:
  --skip-build          Register the launcher without rebuilding the image.
  --install-root PATH   Store managed launcher files below PATH.
  --bin-dir PATH        Register the dfir-agent command in PATH.
  --no-path-update      Do not add the default user bin directory to the shell profile.
  --force               Replace an existing unmanaged dfir-agent command.
  -h, --help            Show this help message.
EOF
}

fail() {
    printf 'dfir-agent install: %s\n' "$*" >&2
    exit 1
}

install_root_option=
bin_directory_option=
install_root_set=0
bin_directory_set=0
skip_build=0
no_path_update=0
force=0

while (($# > 0)); do
    case "$1" in
        --skip-build)
            skip_build=1
            shift
            ;;
        --install-root)
            (($# >= 2)) || fail "--install-root requires a path."
            install_root_option=$2
            install_root_set=1
            shift 2
            ;;
        --install-root=*)
            install_root_option=${1#*=}
            install_root_set=1
            shift
            ;;
        --bin-dir)
            (($# >= 2)) || fail "--bin-dir requires a path."
            bin_directory_option=$2
            bin_directory_set=1
            shift 2
            ;;
        --bin-dir=*)
            bin_directory_option=${1#*=}
            bin_directory_set=1
            shift
            ;;
        --no-path-update)
            no_path_update=1
            shift
            ;;
        --force)
            force=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

home_directory=${HOME:-}
[[ -n "$home_directory" ]] || fail "HOME is not set."

if ((install_root_set == 1)); then
    install_root=$install_root_option
else
    install_root="${XDG_DATA_HOME:-$home_directory/.local/share}/dfir-agent"
fi
if ((bin_directory_set == 1)); then
    bin_directory=$bin_directory_option
else
    bin_directory="$home_directory/.local/bin"
fi
[[ -n "$install_root" ]] || fail "--install-root must not be empty."
[[ -n "$bin_directory" ]] || fail "--bin-dir must not be empty."
[[ "$install_root" == /* ]] || fail "--install-root must be an absolute path."
[[ "$bin_directory" == /* ]] || fail "--bin-dir must be an absolute path."
[[ "$install_root" != *$'\n'* && "$install_root" != *$'\r'* ]] ||
    fail "--install-root contains a forbidden control character."
[[ "$bin_directory" != *$'\n'* && "$bin_directory" != *$'\r'* ]] ||
    fail "--bin-dir contains a forbidden control character."

script_source=$(readlink -f -- "${BASH_SOURCE[0]}") ||
    fail "the installer path could not be resolved."
project_root=$(cd -- "$(dirname -- "$script_source")" && pwd -P)
[[ "$project_root" != *$'\n'* && "$project_root" != *$'\r'* ]] ||
    fail "the project path contains a forbidden control character."
compose_file="$project_root/docker-compose.yml"
launcher_source="$project_root/deploy/console/launch.sh"
preflight_source="$project_root/deploy/console/linux_docker_preflight.sh"

[[ -f "$compose_file" ]] || fail "docker-compose.yml is missing from the project root."
[[ -f "$launcher_source" ]] || fail "deploy/console/launch.sh is missing."
[[ -f "$preflight_source" ]] ||
    fail "deploy/console/linux_docker_preflight.sh is missing."

# shellcheck source=deploy/console/linux_docker_preflight.sh
source "$preflight_source"
DFA_ERROR_PREFIX="dfir-agent install"
dfa_require_local_docker
dfa_select_container_identity
dfa_prepare_selinux_security "$project_root"
# No --project-name: docker-compose.yml names the project, so a re-clone or a
# moved checkout reuses the one built image instead of leaving another behind.
docker compose \
    --project-directory "$project_root" \
    --file "$compose_file" \
    "${DFA_DOCKER_OVERRIDE_ARGS[@]}" \
    config --quiet ||
    fail "docker-compose.yml is invalid for the installed Docker Compose version."

ensure_private_directory() {
    local directory=$1
    if [[ -L "$directory" ]]; then
        fail "managed runtime directories must not be symbolic links: $directory"
    fi
    if [[ -e "$directory" && ! -d "$directory" ]]; then
        fail "expected a directory but found another file type: $directory"
    fi
    if [[ ! -d "$directory" ]]; then
        mkdir -m 0700 -p -- "$directory"
    fi
}

managed_directories=(
    "$project_root/evidence"
    "$project_root/runs"
    "$project_root/config"
    "$project_root/work"
)
for managed_directory in "${managed_directories[@]}"; do
    ensure_private_directory "$managed_directory"
done

for ((first_index = 0; first_index < ${#managed_directories[@]}; first_index++)); do
    for ((second_index = first_index + 1;
        second_index < ${#managed_directories[@]};
        second_index++)); do
        first_directory=${managed_directories[first_index]}
        second_directory=${managed_directories[second_index]}
        if dfa_paths_share_identity_or_ancestry \
            "$first_directory" "$second_directory"; then
            fail "managed runtime directories must not overlap or alias one another: $first_directory and $second_directory"
        else
            identity_status=$?
            ((identity_status == 1)) ||
                fail "managed runtime directory identities could not be verified."
        fi
    done
done

if ((skip_build == 0)); then
    docker compose \
        --project-directory "$project_root" \
        --file "$compose_file" \
        "${DFA_DOCKER_OVERRIDE_ARGS[@]}" \
        build console ||
        fail "the dfir-agent Docker image could not be built."
fi

install -d -m 0755 "$install_root/bin" "$bin_directory"
install_root=$(cd -- "$install_root" && pwd -P)
bin_directory=$(cd -- "$bin_directory" && pwd -P)

managed_launcher="$install_root/bin/dfir-agent"
root_record="$install_root/bin/project-root.txt"
command_path="$bin_directory/dfir-agent"

temporary_launcher=$(mktemp "$install_root/bin/.dfir-agent.XXXXXX")
temporary_root_record=$(mktemp "$install_root/bin/.project-root.XXXXXX")
cleanup() {
    rm -f -- "$temporary_launcher" "$temporary_root_record"
}
trap cleanup EXIT

install -m 0755 "$launcher_source" "$temporary_launcher"
printf '%s\n' "$project_root" >"$temporary_root_record"
chmod 0644 "$temporary_root_record"
mv -f -- "$temporary_launcher" "$managed_launcher"
mv -f -- "$temporary_root_record" "$root_record"
trap - EXIT

if [[ "$command_path" != "$managed_launcher" ]]; then
    if [[ -e "$command_path" || -L "$command_path" ]]; then
        existing_target=$(readlink -f -- "$command_path" 2>/dev/null || true)
        if [[ "$existing_target" != "$managed_launcher" ]]; then
            if ((force == 0)); then
                fail "an unmanaged command already exists at $command_path; use --force to replace it."
            fi
            rm -f -- "$command_path"
        fi
    fi
    ln -sfn -- "$managed_launcher" "$command_path"
fi

path_updated=0
case ":${PATH:-}:" in
    *":$bin_directory:"*) ;;
    *)
        if ((no_path_update == 0)) &&
            [[ "$bin_directory" == "$home_directory/.local/bin" ]]; then
            shell_name=$(basename -- "${SHELL:-sh}")
            case "$shell_name" in
                bash)
                    profile="$home_directory/.bashrc"
                    path_line='export PATH="$HOME/.local/bin:$PATH"'
                    ;;
                zsh)
                    profile="$home_directory/.zshrc"
                    path_line='export PATH="$HOME/.local/bin:$PATH"'
                    ;;
                fish)
                    profile="$home_directory/.config/fish/conf.d/dfir-agent.fish"
                    path_line='fish_add_path --global "$HOME/.local/bin"'
                    mkdir -p -- "$(dirname -- "$profile")"
                    ;;
                *)
                    profile="$home_directory/.profile"
                    path_line='export PATH="$HOME/.local/bin:$PATH"'
                    ;;
            esac
            if [[ ! -f "$profile" ]] || ! grep -Fqx -- "$path_line" "$profile"; then
                {
                    printf '\n# Added by the DFIR Agent installer\n'
                    printf '%s\n' "$path_line"
                } >>"$profile"
            fi
            path_updated=1
        fi
        ;;
esac

printf '\nDFIR Agent was installed successfully.\n'
printf 'Evidence directory: %s\n' "$project_root/evidence"
printf 'Runtime directory:  %s\n' "$project_root/runs"
printf 'Config directory:   %s\n' "$project_root/config"
printf 'Scratch directory:  %s\n' "$project_root/work"
printf 'The command remains linked to this project directory.\n'
printf 'Run install.sh again if the project directory is moved.\n\n'

if [[ ":${PATH:-}:" == *":$bin_directory:"* ]]; then
    printf 'Run:\n  dfir-agent\n'
elif ((path_updated == 1)); then
    printf 'Open a new terminal, then run:\n  dfir-agent\n'
else
    printf 'Add the command directory to PATH, then run dfir-agent:\n'
    printf '  export PATH=%q:"$PATH"\n' "$bin_directory"
fi
