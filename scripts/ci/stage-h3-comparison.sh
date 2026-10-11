#!/usr/bin/env bash
set -euo pipefail

repository=${1:?usage: stage-h3-comparison.sh REPOSITORY DESTINATION}
destination=${2:?usage: stage-h3-comparison.sh REPOSITORY DESTINATION}
repository=$(cd "$repository" && pwd -P)
source="$repository/vendor/h3"

die() {
  echo "stage-h3-comparison: $*" >&2
  exit 1
}

[[ ! -e "$destination" && ! -L "$destination" ]] \
  || die "destination already exists"
[[ -f "$source/LICENSE" && ! -L "$source/LICENSE" ]] \
  || die "shared LICENSE must be a regular file"

packages=(h3-datagram h3-quinn h3-webtransport h3)
entries=$(git -C "$repository" ls-files --stage -- vendor/h3) \
  || die "cannot read tracked H3 entries"
links=$(printf '%s\n' "$entries" | awk '$1 == "120000" { print $4 }')
expected_links=$(printf 'vendor/h3/%s/LICENSE\n' "${packages[@]}")
[[ "$links" == "$expected_links" ]] \
  || die "expected exactly the four tracked H3 LICENSE links"

observation=$(mktemp "${TMPDIR:-/tmp}/phantom-h3-link.XXXXXX")
trap 'rm -f "$observation"' EXIT
license_exclusions=()
for package in "${packages[@]}"; do
  path="vendor/h3/$package/LICENSE"
  [[ -d "$source/$package" && ! -L "$source/$package" ]] \
    || die "package directory must be a regular directory for $path"
  entry=$(git -C "$repository" ls-files --stage -- "$path") \
    || die "cannot read tracked entry for $path"
  read -r mode object stage name <<< "$entry"
  [[ "$mode $object $stage"$'\t'"$name" == "$entry" \
    && "$mode" == 120000 && "$stage" == 0 && "$name" == "$path" ]] \
    || die "unexpected tracked mode or stage for $path"
  git -C "$repository" cat-file blob "$object" > "$observation" \
    || die "cannot read tracked link target for $path"
  cmp -s "$observation" <(printf '%s' '../LICENSE') \
    || die "tracked link target changed for $path"

  if [[ -L "$repository/$path" ]]; then
    readlink "$repository/$path" > "$observation" \
      || die "cannot read checkout link for $path"
    cmp -s "$observation" <(printf '%s\n' '../LICENSE') \
      || die "checkout link target changed for $path"
  else
    [[ -f "$repository/$path" ]] \
      || die "missing checkout placeholder for $path"
    cmp -s "$repository/$path" <(printf '%s' '../LICENSE') \
      || die "checkout placeholder bytes changed for $path"
  fi

  license_exclusions+=("--exclude=./$package/LICENSE")
done

# Compare the referenced license content, while leaving the checkout's Git
# symlinks or Windows placeholders untouched.
mkdir "$destination"
destination=$(cd "$destination" && pwd -P)
tar --exclude=target "${license_exclusions[@]}" -cf - -C "$source" . \
  | tar -xf - -C "$destination"
for package in "${packages[@]}"; do
  cp "$source/LICENSE" "$destination/$package/LICENSE"
done
