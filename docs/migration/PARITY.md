# Mandatory Python parity gate

The owner selected this slice after the [baseline audit](BASELINE-2026-11-06.md):
require live Python comparisons in CI and correct Unicode passphrase digit
classification. These checks cover the current implementation; they do not
establish completion of every migration stage.

The [6 November validation record](PARITY-VALIDATION-2026-11-06.md) records the
four passing local lanes and remaining platform/release limits.

## Reference contract

- Reference: `Kv-Secrets-2/kv-secrets`, version `0.4.0`, commit
  `9a497d91a0f6e95b0949deaf8f5c431f9a4333c0`.
- Canonical transcripts: CPython **3.10.22**. Existing masks for paths, run IDs
  and other generated fields remain in place.
- Semantic lanes: CPython **3.11, 3.12 and 3.13**. The only additional transcript
  normalization accepts the interpreter's complete integer-conversion error
  template with `limit (4300 digits)` in place of `limit (4300)`. Both numerical
  values and all other text must still match. Negative controls reject unrelated
  wording changes. Python versions newer than 3.13 are outside this gate.
- Passphrase policy: Python 3.10 **Unicode 13.0.0** `str.isdigit()` definitions,
  fixed independently of the Rust compiler's Unicode database. Fractions and
  Roman numerals do not trigger the all-digit refusal. Superscript, circled and
  non-ASCII decimal digits still do. Digits added after Unicode 13 are outside
  this fixed predicate, even when a newer Python recognizes them.
- CI installs `cryptography==50.0.2`. It records the actual reference runtime,
  imports and dependency version in its report.

The Unicode generator checks every code point against the canonical interpreter;
the live Rust differential test covers 947 passphrases using every canonical digit,
range neighbors, numeric non-digits and length/precedence cases. The newer Python
lanes check that stable corpus; they do not claim equality with newer Unicode
databases over all code points.

## Running locally on Linux

Install the pinned Rust toolchain from `rust-toolchain.toml`. Use a clean Python
reference checkout and an isolated environment outside that checkout:

```sh
git clone https://github.com/Kv-Secrets-2/kv-secrets.git /tmp/kv-python-reference
git -C /tmp/kv-python-reference checkout --detach 9a497d91a0f6e95b0949deaf8f5c431f9a4333c0
python3.10 -m venv /tmp/kv-parity-python
/tmp/kv-parity-python/bin/python -m pip install /tmp/kv-python-reference cryptography==50.0.2
export KV_PY_REF=/tmp/kv-parity-python/bin/python
export TMPDIR=/var/tmp
python3 -I scripts/test_parity_gate.py
python3 -I scripts/parity_gate.py \
  --reference-repo /tmp/kv-python-reference \
  --python-version 3.10.22 --mode canonical \
  --output /tmp/kv-parity-results
```

Cloning a private reference requires your existing GitHub read access. The CI
credential described below belongs in GitHub Actions secrets; it is not needed
in these commands when Git authentication is already configured.

For a semantic lane, install the reference in a separate environment for that
Python version, change `KV_PY_REF`, and select e.g. `--python-version 3.12
--mode semantic`. Use a distinct output directory for each run. A runner that
does not reap orphaned children should run the gate beneath an init/subreaper
such as `tini -s`.

Ordinary `cargo test --workspace` remains useful without Python. Missing reference
configuration emits `KV_PARITY_SKIP` when output is shown. A configured empty or
unusable interpreter always fails. To require a reference for a targeted Rust run:

```sh
KV_PARITY_REQUIRED=1 cargo test --release --locked -p kv-crypto \
  passphrase_strength_matches_python_reference_digit_corpus -- --show-output
```

Targeted runs do not substitute for the full gate's source attestation and inventory
checks. Use release tests for live daemon comparisons: production scrypt settings
can exceed existing startup deadlines in an unoptimized build. The gate preserves
those settings and deadlines. Unix fixtures use private random directories with
short names and explicitly verify the socket path fits the macOS/Linux limit.
`TMPDIR=/var/tmp` also avoids long default macOS temporary paths.

## What must pass

1. Attest the reference checkout's commit and cleanliness, installed distribution
   and module version, interpreter version, and hashes of all 79 imported Python
   source files against the pinned Git blobs. Inherited Python import overrides
   are removed; the reference probe runs in isolated mode.
2. Build all workspace test executables in one locked release build. Run every
   discovered test in each executable, with a finite process-group deadline.
3. Require every test to complete successfully and every comparison in
   [`scripts/parity_inventory.json`](../../scripts/parity_inventory.json) to emit
   exactly one validated-reference marker under its test name. Missing tests,
   skipped comparisons, ignored tests, duplicate markers, unexpected comparison
   markers and inconsistent result summaries fail. The inventory currently has
   **29 comparison tests**; individual tests contain many cases.
4. Produce Rust crypto vectors and require Python to open them. On the canonical
   lane, also exhaustively verify the generated Unicode digit table.
5. Write `report.json` plus build, discovery, test and reverse-check logs. A failed
   gate exits nonzero. CI retains these artifacts even on failure.

The Rust commit and working-tree status are recorded so an uncommitted local run
is not mistaken for validation of the commit alone. Logs should be retained with
the corresponding patch when validating local edits. The shared Rust subprocess
helper kills and reaps its direct child on timeout; the outer Linux gate bounds
the test process group. This is test harness behavior, not a production IPC fix.

The gate's negative controls exercise missing/empty/unusable references, wrong
source/runtime/package versions, hidden source edits, and incomplete or fabricated
test-result evidence. Reference selection is in the test-only `kv-test-support`
crate; it is not linked into the product.

When adding a live comparison, call `kv_test_support::python_reference()` from the
test and add its exact test name under `package/target` in the inventory. Increase
the reviewed comparison floor when coverage grows. Renames/removals require an
explicit inventory change. The gate refuses an unrecorded comparison marker.

## CI and coverage limits

The parity matrix is unconditional for pull requests and pushes to `main`; failure
fails the workflow. GitHub branch protection or rulesets must require these checks
to prevent merging after failures. This change does not modify repository settings.
The reference checkout uses the repository Actions secret
`KV_REFERENCE_READ_TOKEN`, configured by the owner. Its fine-grained token needs
only read access to Contents in `Kv-Secrets-2/kv-secrets`; the reference repository
can stay private. The token is passed only to that checkout, with
`persist-credentials: false`, and is not exported to build or test steps. Renew
the stored secret when its token expires. A remote workflow run must verify its
repository access and any organization approval requirements.

Events that do not receive this secret, including ordinary fork pull requests,
fail the parity checkout instead of silently skipping comparisons. External
contributions need maintainer review before validation on a trusted branch. Do
not expose the credential to unreviewed fork code through `pull_request_target`.

Native Linux/macOS/Windows tests, doctests, formatting, Clippy and dependency checks
remain separate jobs. Live cross-language parity currently runs only on Linux.
MCP comparisons exercise Python and Rust frontends against the same Rust daemon;
matching an unsupported backend reply does not prove that operation is implemented.
The existing accepted owner-endpoint divergence and missing broker authority,
sandbox, hook, CLI and platform work are recorded in the baseline audit.
