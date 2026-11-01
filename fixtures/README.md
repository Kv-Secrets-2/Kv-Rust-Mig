# kv-secrets 0.4.0 golden fixtures

The fixtures in `v0.4.0/` were produced by the installed Python `kv-secrets`
0.4.0 package from reference commit
`9a497d91a0f6e95b0949deaf8f5c431f9a4333c0`. They are compatibility inputs for
the Rust implementation, not values copied from an independently reimplemented
cryptographic algorithm. The generator invokes the reference package for every
derived value, encryption, decryption and recorded Python outcome; it only
constructs fixed test inputs and byte mutations itself.

## Regenerate and verify

Use Python 3.10 and install the pinned reference checkout in a virtual
environment. The generator refuses a different reference commit, refuses to
import `kv` from the checkout, prints `kv.__file__`, and must be run outside
the reference checkout:

```sh
python3.10 -m venv /var/tmp/kv-ref-venv
/var/tmp/kv-ref-venv/bin/pip install ~/repos/kv-secrets
cd /var/tmp
/var/tmp/kv-ref-venv/bin/python \
  ~/repos/Kv-Rust-Mig/fixtures/gen/generate_v040.py
/var/tmp/kv-ref-venv/bin/python \
  ~/repos/Kv-Rust-Mig/fixtures/gen/check_v040.py
```

If the reference checkout is elsewhere, set `KV_REFERENCE_REPO` to its absolute
path for both commands. The generator uses fixed keys, text and KDF settings.
Nonces, salts, generated recovery/backup/TOTP material, and the real vault's
identity and record IDs are obtained from `os.urandom` through kv and therefore
change on regeneration. Fixed derived-key vectors and the fixed-input TOTP
codes/URIs remain stable.

`manifest.json` contains SHA-256 hashes, sizes and filesystem modes for every
generated file except itself (a manifest cannot contain its own SHA-256 without
a self-reference). It records the reference commit and runtime versions.

## File formats and fields

All byte strings in JSON are lowercase hex unless a field is explicitly named
`*_base64` or contains a human-readable token. `manifest.json` is generated
after all fixtures and lists the exact file inventory.

* `labeled_keys.json` has one top-level `vectors` array. Each element has
  `master_key_name`, its `master_key_hex`, and six test `vectors`. Each test
  vector's `label` and ordered `parts` are exactly the arguments passed to kv;
  every part has `type` (`str` or `bytes`) and either the exact string `value`
  or byte `hex`. `derived_key_hex` is the return value of kv.
* `aead.json` has `vectors` and `tampered` arrays. A positive vector has
  `name`, `key_hex`, string `aad`, `plaintext_hex`, and `blob_hex` (the
  concatenated nonce, ciphertext and authentication tag). A tampering vector
  has `field` (nonce, ciphertext or tag), the shared valid
  `original_blob_hex`, the altered `tampered_blob_hex`, and
  `python_outcome` (`InvalidTag`).
* `keys.json` has `positive` and `negative` arrays. A positive item has
  `name`, `file_name` (relative to `keys/`), `passphrase`, `location_hex`,
  three-byte `setting` (`log2 N`, `r`, `p`), and `expected`. `expected` has
  the successfully unwrapped `master_key_hex`, `owner_seed_hex` and
  `local_approval_id_hex`. The corresponding `.kvw` file is the raw key-file
  byte sequence. A negative item has `name`, relative `file_name`,
  `python_outcome` (`ok`, `invalid_tag` or `value_error:<message>`) and
  `rust_expected` (`header_error`, `auth_error` or `unsupported_version`).
  Negative blobs include the specified header mutations, byte flips,
  truncation/extension and real v2/v3 legacy encodings.
* `totp.json` has four arrays. `codes` entries contain `secret`, Unix `time`
  and reference `code`. `uris` entries contain `name`, `secret`, `account`,
  `issuer` and the generated `uri`. `encrypted_v3` entries contain base32
  `secret`, `secret_length`, `passphrase`, three-byte `setting`,
  `blob_base64` (the API's returned text) and the decoded raw `blob_hex`.
  `negative` entries identify the test with `name`, include a `passphrase`
  and `blob_base64`, and record the actual `python_outcome`; the v2 case also
  records its plaintext `secret`.
* `recovery.json` has `wrapped_keys` and `malformed_tokens`. Each wrapped-key
  item has `master_key_name`, `master_key_hex`, generated `token`,
  `parsed_recovery_key_hex` and `wrapped_base64`. Each malformed-token item
  has `name`, test `token` and actual `python_outcome`.
* `backup_codes.json` has four arrays. Each `codes` entry has `source`
  (`fixed` or `generated`), one-based `index`, original `code`, kv's
  `normalized` spelling and `sha256_hex`. Each `passphrase_strength` entry
  has the tested `passphrase`, boolean `ok` and reason string `reason`.
  `key_export_import` entries have `name`, `master_key_hex`, exported `token`
  and `imported_key_hex`. Each `malformed_key_tokens` entry has `name`,
  invalid `token` and actual `python_outcome`.
* `vaults/basic/.secrets/` is copied real drawer-vault data: the v4 key,
  configuration, `.gitignore`, drawer indexes and encrypted records.
  `vaults/basic.expected.json` has `passphrase`, canonical source `realpath`,
  authenticated `location_hex`, a map of live `live_secrets` by environment,
  `removed_name`, `api_key_generation` and the `env_id` map. The key is
  location-authenticated, so the checker opens the source vault at
  `/var/tmp/kv-fixture-vaults/basic`, compares every included copied file and
  mode, then decrypts and lists the source vault's secrets.
* `manifest.json` records `reference` (`commit`, package name and
  `package_version`, `python_version`, and `cryptography_version`), and
  `files`, a map from each output-relative path to its SHA-256, `size_bytes`
  and filesystem `mode`. `excluded_vault_paths` gives each excluded source
  path and reason. `manifest_note` explains why the manifest does not hash
  itself.

The basic vault is initialized with `(14, 8, 1)` before init. It writes
`API_KEY` twice (generation 2), sets Unicode and multiline values, removes
`GONE`, and sets a production `DB_URL`. The expected live values omit `GONE`.
For each environment, `env_id` is computed by calling the backend's `_env_id`
and asserted to match the drawer directory name.

## Excluded local-only vault files

The generator excludes these files from the copied `.secrets/` tree and records
the exclusions and reasons in `manifest.json`:

* `.secrets/vault-marker`: machine-local provenance bound to the source
  directory object, not vault-format data.
* `.secrets/storage.lock`: machine-local synchronization lock, not vault-format
  data.
* `.secrets/config.lock`: machine-local configuration writer lock, not
  vault-format data.

The format-bearing `key`, `config.json`, `.gitignore` and all drawer files are
included. No fixture is sourced from outside the generator's calls to the
installed reference package and the fixed inputs in `generate_v040.py`.
