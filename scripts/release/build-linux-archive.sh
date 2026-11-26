#!/usr/bin/env bash
# Build the locked Linux static release binary and package it as a reproducible tar.gz
# plus an adjacent SHA256 checksum. This script never tags or publishes anything.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"

target=x86_64-unknown-linux-musl
out_dir=${KV_RELEASE_DIST:-$root/target/release-artifacts}
version=$(awk '
  $0 == "[workspace.package]" { in_package = 1; next }
  /^\[/ { in_package = 0 }
  in_package && $1 == "version" {
    gsub(/"/, "", $3)
    print $3
    exit
  }
' Cargo.toml)

if [[ -z "$version" ]]; then
  echo "could not read the workspace version from Cargo.toml" >&2
  exit 1
fi

metadata=$(cargo metadata --no-deps --format-version 1)
target_dir=$(printf '%s' "$metadata" | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
if [[ -z "$target_dir" ]]; then
  echo "could not determine Cargo's target directory" >&2
  exit 1
fi

cargo_home=${CARGO_HOME:-$HOME/.cargo}
toml_cargo_home=${cargo_home//\\/\\\\}
toml_cargo_home=${toml_cargo_home//\"/\\\"}
remap_config="build.rustflags=[\"--remap-path-prefix=$toml_cargo_home/registry/src=/cargo/registry/src\"]"

# Use Cargo's own rustflags machinery rather than RUSTFLAGS or a rustc wrapper:
# the array form preserves spaces, participates in Cargo's build fingerprint, and
# merges with array-valued rustflags from Cargo configuration without affecting
# host build-script compilations.
cargo --config "$remap_config" build --release --locked --target "$target" -p kv-cli

binary=$target_dir/$target/release/kv
if [[ ! -x "$binary" ]]; then
  echo "expected release binary is missing: $binary" >&2
  exit 1
fi

version_output=$("$binary" version)
if [[ "$version_output" != "kv $version" ]]; then
  echo "binary version mismatch: got '$version_output', expected 'kv $version'" >&2
  exit 1
fi

command -v readelf >/dev/null 2>&1 || {
  echo "readelf is required to verify static linkage" >&2
  exit 1
}
readelf_output=$(readelf -d "$binary" 2>&1) || {
  echo "readelf could not inspect the release binary; static linkage is unverified" >&2
  exit 1
}
if grep -q '(NEEDED)' <<<"$readelf_output"; then
  echo "release binary is dynamically linked; a static musl binary is required" >&2
  exit 1
fi

name=kv-$version-$target
archive_name=$name.tar.gz
checksum_name=$archive_name.sha256
mkdir -p "$out_dir"
staging=$(mktemp -d "$out_dir/staging.XXXXXX")
trap 'rm -rf "$staging"' EXIT

mkdir "$staging/$name"
install -m 0755 "$binary" "$staging/$name/kv"
rm -f "$out_dir/$archive_name" "$out_dir/$checksum_name"
tar \
  --sort=name \
  --mtime='UTC 1970-01-01' \
  --mode='u=rwX,go=rX' \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -czf "$out_dir/$archive_name" \
  -C "$staging" \
  "$name"

(
  cd "$out_dir"
  sha256sum "$archive_name" > "$checksum_name"
  sha256sum -c "$checksum_name"
)

archive_sha256=$(awk '{print $1; exit}' "$out_dir/$checksum_name")
printf 'archive=%s\nchecksum=%s\nsha256=%s\n' \
  "$out_dir/$archive_name" \
  "$out_dir/$checksum_name" \
  "$archive_sha256"
