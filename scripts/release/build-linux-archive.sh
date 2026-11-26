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
path_remap="--remap-path-prefix=$cargo_home/registry/src=/cargo/registry/src"

helper_dir=$(mktemp -d "${TMPDIR:-/tmp}/kv-release-rustflags.XXXXXX")
staging=
cleanup() {
  rm -rf "$helper_dir"
  if [[ -n "$staging" ]]; then
    rm -rf "$staging"
  fi
}
trap cleanup EXIT

probe_dir=$helper_dir/probe
mkdir -p "$probe_dir/src"
cp scripts/release/cargo-rustflags-probe.rs "$probe_dir/build.rs"
: > "$probe_dir/src/lib.rs"
cat > "$probe_dir/Cargo.toml" <<'PROBE_EOF'
[package]
name = "kv-release-rustflags-probe"
version = "0.0.0"
edition = "2021"
build = "build.rs"

[workspace]
PROBE_EOF

probe_output=$helper_dir/rustflags-encoded
KV_RUSTFLAGS_PROBE_OUT="$probe_output" cargo build --quiet --offline \
  --manifest-path "$probe_dir/Cargo.toml" \
  --release \
  --target "$target" \
  --target-dir "$helper_dir/probe-target"
if [[ ! -f "$probe_output" ]]; then
  echo "Cargo did not expose effective rustflags through the probe build script" >&2
  exit 1
fi

if [[ "$path_remap" == *$'\x1f'* ]]; then
  echo "CARGO_HOME cannot contain the CARGO_ENCODED_RUSTFLAGS separator" >&2
  exit 1
fi

# Ask Cargo itself for the effective target flags through an isolated probe in
# this working directory, then append the release remap in Cargo's encoded
# representation. The encoding preserves array entries containing spaces and
# avoids merging an array-valued override into a string-valued config key.
probe_rustflags=$(cat "$probe_output" && printf x)
probe_rustflags=${probe_rustflags%x}
if [[ -n "$probe_rustflags" ]]; then
  CARGO_ENCODED_RUSTFLAGS="$probe_rustflags"$'\x1f'"$path_remap"
else
  CARGO_ENCODED_RUSTFLAGS=$path_remap
fi
export CARGO_ENCODED_RUSTFLAGS
cargo build --release --locked --target "$target" -p kv-cli

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
