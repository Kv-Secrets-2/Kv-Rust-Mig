# Standalone Linux Rust v1 release guide

This guide describes the locked standalone Linux v1 surface of the Rust `kv`
binary in this repository. It is not a Python migration guide and it does not
describe the broader migration plan. It defines the release gate: an
intermediate `main` commit is not v1-ready until every behavior described here
is implemented in that commit.

## What v1 is

- **One standalone Linux binary.** The release archive contains a single
  statically linked `x86_64-unknown-linux-musl` `kv` executable. The same
  executable provides the command-line interface and the local background
  service.
- **Linux-only.** Linux is the only supported v1 installation target. macOS
  and Windows builds or tests are development coverage, not supported v1
  installation targets.
- **No Python dependency.** Running the v1 binary does not require a Python
  interpreter, Python package, Python virtual environment, or Python vault.
  Python parity fixtures and test harnesses in the repository are development
  tooling only and are not part of the installed product.
- **A narrow brokered-provider journey.** v1 proves one fixed built-in
  operation: the local service, not the caller, uses the vault-stored
  `ANTHROPIC_API_KEY` to call Anthropic's token-counting endpoint after an
  owner approves one exact call.

## What v1 is not

v1 deliberately excludes these surfaces:

- `kv mcp-server`, MCP/IDE integration, and IDE hooks. Invoking
  `kv mcp-server` is expected to fail as unavailable in Linux v1.
- Python feature parity, Python vault migration, old vault/key migration,
  `KV_MASTER_KEY` vaults, and legacy v1-v3 key files.
- Raw-key injection into a caller, child process, shell, or tool environment.
- Arbitrary shell command execution, `kv run`, standing grants, run grants,
  POST wallets, database/Redis/SSH providers, custom provider definitions,
  arbitrary HTTP methods/paths/headers, and cloud sync.
- Two-factor approval. A vault with two-factor configuration cannot use the
  v1 local approval path.
- A protected owner approval channel. `protected-approval` mode blocks local
  approval commands because that channel is not implemented in v1;
  list/deny/block-style refusal paths remain available.
- A published GitHub Release, signature infrastructure, macOS packages, and
  Windows packages. The current packaging workflow only builds, smokes, and
  uploads the Linux archive as a CI artifact; it does not tag or publish a
  release.

Some development builds may still contain code or hidden compatibility paths
for broader migration work. Their presence in the repository does not make
them supported v1 surfaces.

## Install the Linux archive

The packaging workflow builds a reproducible archive named:

```text
kv-<version>-x86_64-unknown-linux-musl.tar.gz
kv-<version>-x86_64-unknown-linux-musl.tar.gz.sha256
```

The workflow uploads those files in the `kv-linux-static-archive` CI artifact
after smoking the exact archive in a clean networkless Linux runtime without
Python or build tools. Download the archive and its adjacent checksum from a
trusted run or release location, then verify and install it:

```sh
# Replace the version with the archive version, then run these commands from
# the directory containing both files.
KV_VERSION=0.5.0-dev
ARCHIVE="kv-${KV_VERSION}-x86_64-unknown-linux-musl.tar.gz"

sha256sum -c "${ARCHIVE}.sha256"
tar -xzf "$ARCHIVE"
install -D -m 0755 \
  "kv-${KV_VERSION}-x86_64-unknown-linux-musl/kv" \
  "$HOME/.local/bin/kv"

"$HOME/.local/bin/kv" version
```

The final command must print `kv $KV_VERSION`. `install -D` creates
`~/.local/bin` when needed, and invoking the installed path directly avoids
accidentally checking a different `kv` earlier on `PATH`. Do not use the
archive when checksum verification fails.

Before the first-run journey, put the new installation first on `PATH` and
confirm that bare `kv` resolves to it:

```sh
export PATH="$HOME/.local/bin:$PATH"
command -v kv
```

`command -v kv` must print exactly `$HOME/.local/bin/kv` (with `$HOME`
expanded). If it prints another path, do not continue with bare `kv` commands
until `PATH` is corrected.

Install bubblewrap with the operating-system package manager before first
use. On Debian/Ubuntu, for example:

```sh
sudo apt-get install bubblewrap
```

`kv doctor` treats a missing, untrusted, or non-working bubblewrap
installation as an error. It must be a trusted root-owned system installation,
not an arbitrary user-writable executable named `bwrap`.

No Python installation is needed for installation or normal use. Network
access is not needed to install, initialize, unlock, or lock a vault; it is
needed only when an approved Anthropic operation is executed.

## First-run journey

Run these commands from the project directory that should use the vault. A
project vault is discoverable from that directory and its subdirectories.

### 1. Check the host before setup

```sh
kv doctor
```

`kv doctor` is read-only and safe before `kv init`. A fresh machine with no
vault is expected state, not an error. The command checks the Linux platform,
the bubblewrap sandbox, whether `HOME` can maintain `~/.kv`, and the structure
and metadata of any `.secrets` vault found from the working directory upward.

Doctor is intentionally metadata-only: it does not open or parse the vault key,
configuration, marker, ignore file, or drawer contents. It therefore detects
missing files, wrong types, unsafe ownership/modes, and unmaintainable state,
but not semantic corruption inside otherwise nonempty encrypted content or
moved-vault provenance. It exits zero when no errors are found and nonzero
when any error is found; warnings alone do not make it fail.

### 2. Create the vault

```sh
kv init --location project
```

Use `--location project` for a vault rooted in the current project.
`--location global` creates one under the home directory, and
`--location custom --path PATH` chooses another root. The command creates a
`.secrets` directory containing a passphrase-wrapped v4 key, drawer storage,
and a default `dev` environment.

The passphrase and confirmation are read interactively without echo. A strong
passphrase is required; it encrypts the vault master key at rest.

Initialization also creates a recovery key. When standard output is a terminal,
that key is shown once and must be copied somewhere safe before typing
`saved`. If the key is not shown or not confirmed, later vault access warns
that recovery delivery is incomplete. Losing both the passphrase and the
recovery key can make the vault unrecoverable.

### 3. Store the Anthropic credential

```sh
kv set ANTHROPIC_API_KEY
```

Use the form without `=`. `kv` prompts for the vault passphrase and then reads
the secret at a hidden `Value:` prompt, so the secret is not placed in command
arguments, shell history, or echoed terminal output. The value is stored
encrypted in the default `dev` environment unless `--env` selects another
environment.

The fixed v1 Anthropic operation looks for exactly the name
`ANTHROPIC_API_KEY` in the selected environment.

Although the broader secret CLI can parse `NAME=value`, do not use that form
for real credentials: it exposes the value to shell history and process
argument inspection.

### 4. Choose the approval mode deliberately

New vaults start with approval mode unset, and the approval inbox warns about
that state. Unset does not block the current local approval implementation,
but it leaves the security choice implicit. To make the terminal-based v1
journey explicit, choose local approval before approving the configuration:

```sh
kv approval-mode set local-convenience
```

Choose `local-convenience` only when an agent cannot control this computer's
browser, terminal, mouse, keyboard, or desktop. If an agent may control those
surfaces, do not use local approval as a protected decision boundary.
`protected-approval` mode intentionally refuses local approval in v1 because
no protected owner channel ships yet. `kv approvals deny` remains available as
a refusal path.

### 5. Approve the vault authority

```sh
kv vault approve-config
```

The first daemon start requires this owner review. Enter the vault passphrase,
inspect the proposed authority, and answer `y` only if the origins, secret
bindings, and policy are exactly what you expect. This approval binds the
configuration authority before the service is allowed to use it. Make security
mode and policy choices before this approval so the reviewed authority is the
one you intend the service to use.

### 6. Unlock the local service

```sh
kv unlock
```

Enter the passphrase at the hidden prompt. A successful unlock starts the
local background service and prints that the vault is unlocked. `kv status`
can confirm that the service is running.

The service keeps secrets in memory only while unlocked. If unlock fails after
a fresh init, run `kv vault approve-config` first and then retry.

### 7. Request the fixed Anthropic operation

```sh
kv api anthropic-count-tokens -- 'count these tokens'
```

This is a fixed built-in operation, not a general HTTP client. The caller
supplies only the input text, an optional environment, and later a permit ID.
The daemon owns the provider choice, endpoint, method, headers, model, payload
shape, and secret injection:

- provider: `anthropic`
- method/path: `POST /v1/messages/count_tokens`
- fixed production origin: `https://api.anthropic.com`
- model: `claude-3-5-haiku-latest`
- secret name: `ANTHROPIC_API_KEY`
- input limit: 1 to 16,384 bytes

The first invocation normally exits nonzero with `permit_required`. It prints
a request ID, the permit ID that becomes spendable only after owner approval,
and the exact command to run after approval. No provider request is sent by
this step.

### 8. Review the request

```sh
kv approvals list
```

The inbox shows the pending one-call permit, including the fixed provider and
method. Open the owner review with:

```sh
# Copy the full request ID printed by the request step or inbox.
REQUEST_ID=permit_request_...
kv approvals approve "$REQUEST_ID"
```

The approval command requires an owner terminal and the vault passphrase. It
shows the exact request facts for review, including the provider, method, URL,
body size/hash, expiry, caller headers, and bounded plaintext body. Answer `y`
only when those facts are exactly what you intend. A successful approval signs
and registers a one-call permit; it does not send the provider request by itself.

A permit is exact and short-lived: the current v1 lifetime is 600 seconds
from request creation. It is bound to the same vault session, operation,
provider, method, path, body bytes, and final non-secret request facts.

If the request should not proceed, use the explicit denial command instead of
only closing the review:

```sh
# Copy the full request ID printed by the request step or inbox.
REQUEST_ID=permit_request_...
kv approvals deny "$REQUEST_ID"
```

Denial also requires the owner terminal and passphrase. It is terminal in the
daemon's permit state machine: the denied permit cannot later be registered,
matched, or spent.

### 9. Execute the approved call once

Use the exact retry printed by the request step, substituting the approved
permit ID:

```sh
# Copy the full permit ID from the successful approval output.
PERMIT_ID=permit_...
kv api anthropic-count-tokens \
  --permit-id "$PERMIT_ID" \
  -- 'count these tokens'
```

On success, the daemon sends exactly one authenticated HTTPS request to the
fixed endpoint and prints the provider response as JSON, for example an object
containing `input_tokens`. The raw `ANTHROPIC_API_KEY` is never placed in the
CLI command line, printed in the response, or exposed to the calling process.

These cases must send no additional provider request:

- replaying the same permit after it was spent;
- changing even one byte of the approved input;
- using the permit after expiry;
- using a denied permit;
- using the permit after `kv lock`;
- audit admission, journal verification, or durable checkpoint failure.

A new or changed input requires a new owner-reviewed request.

### 10. Lock the vault

```sh
kv lock
```

A confirmed lock stops the local service, clears secrets from memory, ends
unused passes/permits for calls not yet made, and prints `vault locked` plus
`secrets cleared from memory`. If the service is already stopped, lock reports
that the vault is already locked.

Lock prevents later use of an unspent permit. It is not a rollback mechanism
for a provider call already sent, and a call already under way is not
retroactively undone. After locking, the fixed operation cannot use the vault
secret again until the owner unlocks the vault and completes a fresh approval
flow.

## Audit verification

v1 has two distinct audit-verification layers.

### Runtime fail-closed verification

For the privileged broker operation, the daemon uses an authenticated
newline-delimited JSON chain. Each record is canonical JSON and carries a
full-width HMAC-SHA256 chain tag, sequence number, previous head, format
version, and vault identity digest. Chain keys are derived from vault key
material in the daemon and are not printed.

Before a privileged provider effect, the daemon:

1. serializes the audit lock;
2. independently loads the durable checkpoint;
3. verifies the complete journal from the first record to that checkpoint;
4. durably appends a `privileged_admission` record;
5. durably publishes the advanced checkpoint; and
6. only then allows the provider send to proceed.

After the effect reaches a definite terminal state, the daemon records a
separate `privileged_outcome`. If completion is uncertain or the process is
interrupted, no outcome is guessed: that admission remains unknown rather
than being treated as safe to repeat. Missing, truncated, corrupted,
rolled-back, replaced, or merely unverifiable audit state fails closed, and
the provider request is not sent.

The ordinary CLI audit log and the privileged admission journal are separate.
Runtime state lives under `~/.kv`; the privileged journal directory and
checkpoint names include the project hash and a vault-generation value, so a
recreated vault at the same path does not inherit the old vault's chain
position.

### Manual verifier status in v1

The repository also builds a crate-local diagnostic binary named
`kv-audit-verify`. It is **not** a `kv` subcommand and is **not** included in
the Linux release archive. It is intended for source-tree development and
forensic verification when complete trust material is already available:

```sh
cargo run -p kv-audit --bin kv-audit-verify -- \
  --directory /path/to/audit-directory \
  --trust-file /path/to/trust.json
```

The trust input must contain the secret chain key, raw vault identity, and an
independently trusted head/count. Because that material is sensitive and v1
does not provide a supported user-facing export for it, do not construct a
trust file by copying files out of the audit directory or by guessing values.
Without complete trust state the verifier reports `missing_trust_state`, which
is inconclusive rather than valid.

Accordingly, the standalone archive's supported audit guarantee in v1 is the
daemon's automatic fail-closed verification. A packaged manual audit-verifier
command remains outside the v1 installation surface.

## Troubleshooting

- `not a kv project (no .secrets/ found)`: run commands from the vault root or
  one of its subdirectories, or initialize a project vault there.
- `kv doctor` reports missing/untrusted bubblewrap: install the distribution's
  bubblewrap package and rerun doctor.
- `failed to unlock` immediately after init: review and approve configuration
  with `kv vault approve-config`, then retry `kv unlock`.
- `permit_required`: this is the normal first step, not a failed provider
  call. Review the inbox and approve or deny the exact request.
- `permit` is expired, missing, denied, spent, or does not match: request a
  fresh permit for the exact input instead of editing the retry command.
- `could not be recorded durably`: the broker correctly refused the privileged
  effect because audit admission or checkpoint publication was not durable.
  Fix the filesystem, permissions, free space, or checkpoint state; do not
  treat repeated retries as a workaround.
- `kv mcp-server` is unavailable: this is expected in v1. Use the fixed
  brokered operation instead; MCP/IDE integration is explicitly out of scope.
