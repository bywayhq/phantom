#!/usr/bin/env bash
# Run one Cargo command for Linux in WSL, against this checkout.
#
# Code under cfg(target_os = "linux") or cfg(not(windows)) never compiles on
# a Windows host. This runs Cargo inside a WSL distribution, on the same
# source tree, so a Windows checkout can check that code before CI does. It
# sets DOCS_RS=1, which makes the btls-sys build script generate bindings
# without compiling BoringSSL, so the command can check but not link: use
# `cargo check` or `cargo clippy`. Builds go to a Linux target directory in
# the distribution, $HOME/.cache/phantom-gate/<checkout>/<name>, one per
# checkout, apart from the Windows target/.
#
# Usage: scripts/dev/wsl-cargo.sh [--distro NAME] [--target-name NAME] <cargo arguments...>
#
#   --distro NAME       WSL distribution (default: PHANTOM_WSL_DISTRO, else
#                       WSL's default distribution).
#   --target-name NAME  Target directory under the checkout's cache
#                       (default: check).
set -euo pipefail

usage() {
  sed -n '/^# Usage:/,/^#  *(default: check)/s/^# \{0,1\}//p' "${BASH_SOURCE[0]}"
}

distro=${PHANTOM_WSL_DISTRO:-}
target_name=check
while [[ $# -gt 0 ]]; do
  case $1 in
    --distro) distro=${2:?$1 needs a name}; shift 2 ;;
    --target-name) target_name=${2:?$1 needs a name}; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
if [[ $# -eq 0 ]]; then
  usage >&2
  exit 64
fi
if ! [[ $target_name =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "wsl-cargo: --target-name takes letters, digits, '.', '_', and '-'" >&2
  exit 64
fi
for tool in wsl.exe cygpath; do
  if ! command -v "$tool" >/dev/null; then
    echo "wsl-cargo: $tool not found; run this from Git Bash on a Windows host with WSL" >&2
    exit 69
  fi
done

root=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
# One cache directory per checkout: its name, and a checksum of its path that
# keeps two checkouts with one name apart.
checkout="$(basename "$root")-$(printf '%s' "$root" | cksum | cut -d ' ' -f 1)"
distro_args=()
[[ -z $distro ]] || distro_args=(-d "$distro")

# A login shell, so the distribution's rustup is on PATH.
# shellcheck disable=SC2016 # The WSL shell expands its own variables.
exec wsl.exe "${distro_args[@]}" --cd "$(cygpath -w "$root")" -e bash -lc '
  export DOCS_RS=1 CARGO_INCREMENTAL=0 CARGO_TERM_COLOR=never
  export CARGO_TARGET_DIR="$HOME/.cache/phantom-gate/$1/$2"
  shift 2
  exec cargo "$@"' wsl-cargo "$checkout" "$target_name" "$@"
