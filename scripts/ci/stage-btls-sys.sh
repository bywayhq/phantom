#!/usr/bin/env bash
# Materialize the reviewed native source without a Git submodule at build time.
set -euo pipefail
destination=${1:?usage: stage-btls-sys.sh DESTINATION}
[[ ! -e "$destination" ]] || { echo "destination exists: $destination" >&2; exit 1; }
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
staging=$(mktemp -d "${TMPDIR:-/tmp}/phantom-native-source.XXXXXX")
trap 'rm -rf "$staging"' EXIT
revision=f478ea16a4b2f6ebbd221ce7cafdec10a32028eb
boringssl=f1f2556a5dfa59e147d9d47279cc3f7f8a18b433
fetch() {
  local url=$1 output=$2 checksum=$3 actual
  curl --fail --location --silent --show-error --retry 3 "$url" -o "$output"
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$output" | awk '{print $1}')
  else
    actual=$(shasum -a 256 "$output" | awk '{print $1}')
  fi
  [[ "$actual" == "$checksum" ]] || { echo "checksum mismatch: $url" >&2; exit 1; }
}
fetch "https://codeload.github.com/bywayhq/btls/tar.gz/$revision" \
  "$staging/native.tar.gz" e9c2fd9f12a995afc8adcd31b86effa9d767570d9e4e52efee68b5ffc2d626cf
fetch "https://codeload.github.com/google/boringssl/tar.gz/$boringssl" \
  "$staging/boringssl.tar.gz" 0a92d2306442146e4994409aefc1bb50d4b664750f4bdd7faf14c6b0a6a04e7e
tar -xzf "$staging/native.tar.gz" -C "$staging"
mkdir -p "$(dirname "$destination")"
cp -R "$staging/btls-$revision/btls-sys" "$destination"
mkdir -p "$destination/deps/boringssl"
tar -xzf "$staging/boringssl.tar.gz" --strip-components=1 -C "$destination/deps/boringssl"
while IFS= read -r patch; do
  # Keep discovery of a parent repository from silently skipping these paths.
  (cd "$destination" && git --git-dir="$staging/no-repository" apply --check "$root/vendor/btls-sys/patches/$patch")
  (cd "$destination" && git --git-dir="$staging/no-repository" apply "$root/vendor/btls-sys/patches/$patch")
  cp "$root/vendor/btls-sys/patches/$patch" "$destination/patches/$patch"
done < "$root/vendor/btls-sys/patches/series"
cp "$root/vendor/btls-sys/patches/series" "$destination/patches/series"
