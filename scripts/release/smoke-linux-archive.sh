#!/usr/bin/env bash
# Verify a release archive in a fresh, networkless Linux runtime with no repository,
# Python installation, or build tools. The runtime uses only the copied archive,
# checksum and this smoke harness; vault material and captured command output stay
# inside the disposable container and are never printed.
set -euo pipefail

image=${KV_SMOKE_IMAGE:-debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e}
smoke_work=

log() {
  printf 'smoke: %s\n' "$*"
}

fail() {
  printf 'smoke failure: %s\n' "$*" >&2
  exit 1
}

inside_runtime() {
  local archive=$1
  local checksum=$2
  local package binary home project
  local pass secret

  for tool in python python3 cargo rustc gcc cc clang make; do
    if command -v "$tool" >/dev/null 2>&1; then
      fail "unexpected build/runtime tool is installed in the clean runtime: $tool"
    fi
  done

  smoke_work=$(mktemp -d /tmp/kv-smoke.XXXXXX)
  trap 'rm -rf "$smoke_work"' EXIT

  local archive_dir archive_base checksum_base
  archive_dir=$(dirname "$archive")
  archive_base=$(basename "$archive")
  checksum_base=$(basename "$checksum")
  (
    cd "$archive_dir"
    sha256sum -c "$checksum_base" >/dev/null
  ) || fail "archive checksum verification failed"
  log "checksum verified in clean runtime"

  package=$(basename "$archive_base" .tar.gz)
  mkdir "$smoke_work/unpack"
  tar -xzf "$archive" -C "$smoke_work/unpack" || fail "archive did not unpack"
  binary=$smoke_work/unpack/$package/kv
  [[ -x "$binary" ]] || fail "archive did not contain the expected executable kv binary"
  log "archive unpacked; repository and build tree are absent"

  home=$smoke_work/home
  project=$smoke_work/project
  mkdir -p "$home" "$project"
  cd "$project"
  export HOME=$home
  export NO_COLOR=1

  pass='correct horse battery staple'
  secret='kv-smoke-dummy-value'

  run_pty() {
    local name=$1
    local expected_rc=$2
    shift 2

    local -a pairs=()
    while [[ $# -gt 0 && $1 != "--" ]]; do
      pairs+=("$1")
      shift
    done
    [[ "${1:-}" == "--" ]] || fail "$name has an internal malformed prompt list"
    shift
    if ((${#pairs[@]} == 0 || ${#pairs[@]} % 2 != 0)); then
      fail "$name has an internal odd prompt/answer list"
    fi

    local command
    printf -v command '%q ' "$@"

    local out=$smoke_work/$name.out
    local fifo=$smoke_work/$name.in
    rm -f "$out" "$fifo"
    mkfifo "$fifo"
    (
      exec 3>"$fifo"
      local i pattern answer deadline
      for ((i = 0; i < ${#pairs[@]}; i += 2)); do
        pattern=${pairs[i]}
        answer=${pairs[i + 1]}
        deadline=$((SECONDS + 20))
        until grep -F -q -- "$pattern" "$out" 2>/dev/null; do
          if ((SECONDS >= deadline)); then
            exit 1
          fi
          sleep 0.1
        done
        printf '%s\n' "$answer" >&3
      done
      exec 3>&-
    ) &
    local writer=$!

    local rc
    set +e
    timeout 45 script -q -e -c "$command" /dev/null <"$fifo" >"$out" 2>&1
    rc=$?
    set -e
    wait "$writer" 2>/dev/null || true

    if [[ "$rc" -ne "$expected_rc" ]]; then
      fail "$name exited $rc, expected $expected_rc"
    fi
  }

  run_plain() {
    local name=$1
    local expected_rc=$2
    shift 2

    local out=$smoke_work/$name.out
    local rc
    set +e
    timeout 20 "$@" >"$out" 2>&1
    rc=$?
    set -e
    if [[ "$rc" -ne "$expected_rc" ]]; then
      fail "$name exited $rc, expected $expected_rc"
    fi
  }

  check_step() {
    local name=$1
    shift
    local out=$smoke_work/$name.out
    local text

    [[ -f "$out" ]] || fail "$name produced no captured output"
    if grep -F -q -- "$pass" "$out"; then
      fail "$name echoed the passphrase"
    fi
    if grep -F -q -- "$secret" "$out"; then
      fail "$name echoed the dummy secret value"
    fi
    for text in "$@"; do
      if ! grep -F -q -- "$text" "$out"; then
        fail "$name output did not contain expected text: $text"
      fi
    done
    rm -f "$out"
  }

  run_pty init 0 \
    'Passphrase:' "$pass" \
    'Confirm:' "$pass" \
    'Type saved' 'saved' \
    -- "$binary" init --location project
  check_step init "vault created"
  if grep -q 'recovery_delivery_pending' .secrets/config.json; then
    fail "init did not complete the disposable recovery-key acknowledgement"
  fi
  log "init passed without printing the passphrase"

  run_pty set 0 \
    'Passphrase:' "$pass" \
    'Value:' "$secret" \
    -- "$binary" set SMOKE_KEY
  check_step set "SMOKE_KEY" "saved"
  log "set passed without echoing the dummy value"

  run_pty list 0 \
    'Passphrase:' "$pass" \
    -- "$binary" ls
  check_step list "dev (1 secret)" "SMOKE_KEY"
  log "list passed and showed only the secret name"

  # Config approval is required before the daemon will start. It is part of the
  # smoke harness only so that lock proves a real daemon shutdown rather than the
  # trivial already-locked path.
  run_pty approve 0 \
    'Passphrase:' "$pass" \
    'Approve this exact authority?' 'y' \
    -- "$binary" vault approve-config
  check_step approve "Config authority approved"

  run_pty unlock 0 \
    'Passphrase:' "$pass" \
    -- "$binary" unlock
  check_step unlock "vault unlocked" "protected session"

  run_plain status-unlocked 0 "$binary" status
  check_step status-unlocked "vault unlocked" "agent running" "1 secret"

  run_plain lock 0 "$binary" lock
  check_step lock "vault locked" "secrets cleared from memory"

  run_plain status-locked 0 "$binary" status
  check_step status-locked "vault locked"
  log "unlock/status/lock passed; final state is locked"

  log "all checks passed; no Python, repository, build tools, network, or real secrets used"
}

if [[ "${1:-}" == "--inside" ]]; then
  shift
  if [[ $# -ne 2 ]]; then
    fail "--inside requires ARCHIVE and CHECKSUM paths"
  fi
  inside_runtime "$1" "$2"
  exit 0
fi

if [[ $# -ne 1 ]]; then
  echo "usage: $0 path/to/kv-VERSION-x86_64-unknown-linux-musl.tar.gz" >&2
  exit 2
fi

archive=$(readlink -f "$1")
checksum=$archive.sha256
[[ -f "$archive" ]] || fail "archive does not exist: $archive"
[[ -f "$checksum" ]] || fail "adjacent checksum does not exist: $checksum"
command -v docker >/dev/null 2>&1 || fail "docker is required to create the clean runtime"

payload=$(mktemp -d)
chmod 0755 "$payload"
trap 'rm -rf "$payload"' EXIT
script_copy=$payload/$(basename "$0")
cp "$0" "$script_copy"
chmod 0755 "$script_copy"
cp "$archive" "$payload/"
cp "$checksum" "$payload/"

archive_base=$(basename "$archive")
checksum_base=$(basename "$checksum")
script_base=$(basename "$script_copy")

docker run \
  --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,exec,nosuid,size=128m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user 65534:65534 \
  -v "$payload:/payload:ro" \
  "$image" \
  "/payload/$script_base" --inside "/payload/$archive_base" "/payload/$checksum_base"
