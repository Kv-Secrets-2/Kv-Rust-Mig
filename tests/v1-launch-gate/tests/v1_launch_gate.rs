//! Standalone Rust-only release gate for the locked standalone-Linux v1 launch contract.
//!
//! The product-flow tests are ignored until the Rust vertical slice lands: running a
//! missing command as if it passed would be false evidence. The harness self-tests,
//! plus PTY init/set no-echo/audit interoperability tests run in normal CI.
#![cfg(target_os = "linux")]

use kv_v1_launch_gate::audit;
use kv_v1_launch_gate::harness::{
    ENDPOINT_OVERRIDE_ENV, PROVIDER, PROVIDER_PATH, RELEASE_GATE_ENV, Scratch,
    assert_secret_absent, assert_success, kv_bin, synthetic_secret,
};
use kv_v1_launch_gate::mock_provider::MockProvider;
use kv_v1_launch_gate::pty::{self, Interaction};
use std::process::{Command, Output};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);

// ── v1 contract adapter ────────────────────────────────────────────────────
// These are the only places the exact CLI spelling is encoded. They intentionally
// use the direct `kv api` shape required by v1 (no shell and no raw-key injection).
// If the implementation lands under another spelling, align these functions and the
// contract-alignment note in the PR rather than scattering changes through the tests.
// Open contract points before unignoring the product-flow tests:
// 1. exact provider-call spelling and permit retry spelling (`kv api` is provisional);
// 2. whether `kv init` starts enough broker state for the locked path, which omits `kv unlock`;
// 3. how tests bound permit lifetime without waiting minutes (`--ttl` is provisional);
// 4. the secure owner-visible loopback endpoint mechanism for fixed built-in providers;
// 5. whether interactive "no" is the v1 denial surface or a separate deny subcommand is required.

fn provider_call_args(body: &str, permit_id: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "api".to_owned(),
        PROVIDER.to_owned(),
        "--method".to_owned(),
        "POST".to_owned(),
        "--path".to_owned(),
        PROVIDER_PATH.to_owned(),
        "--body-json".to_owned(),
        body.to_owned(),
    ];
    if let Some(permit_id) = permit_id {
        args.push("--permit".to_owned());
        args.push(permit_id.to_owned());
    }
    args
}

fn approve_args(request_id: &str, ttl_seconds: Option<u64>) -> Vec<String> {
    let mut args = vec![
        "approvals".to_owned(),
        "approve".to_owned(),
        request_id.to_owned(),
    ];
    if let Some(ttl_seconds) = ttl_seconds {
        args.push("--ttl".to_owned());
        args.push(ttl_seconds.to_string());
    }
    args
}

fn gate_envs(scratch: &Scratch, provider: &MockProvider) -> Vec<(String, String)> {
    vec![
        (
            "HOME".to_owned(),
            scratch.home().to_string_lossy().into_owned(),
        ),
        (RELEASE_GATE_ENV.to_owned(), "1".to_owned()),
        (ENDPOINT_OVERRIDE_ENV.to_owned(), provider.origin()),
    ]
}

fn plain(scratch: &Scratch, provider: &MockProvider, args: &[String]) -> Output {
    let mut command = Command::new(kv_bin());
    command
        .args(args)
        .current_dir(scratch.proj())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("NO_COLOR", "1")
        .env("TERM", "dumb");
    for (name, value) in gate_envs(scratch, provider) {
        command.env(name, value);
    }
    command.output().expect("run kv without a terminal")
}

fn extract_request_id(output: &Output) -> Option<String> {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for word in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if word.starts_with("permit_request_") && word.len() == "permit_request_".len() + 32 {
            return Some(word.to_owned());
        }
    }
    None
}

fn init_vault(scratch: &Scratch, provider: &MockProvider) -> pty::PtyOutput {
    let args = vec![
        "init".to_owned(),
        "--location".to_owned(),
        "project".to_owned(),
    ];
    let output = pty::run_stdout_to_null(
        &kv_bin(),
        &args,
        &scratch.proj(),
        &gate_envs(scratch, provider),
        &[
            Interaction {
                prompt: "Passphrase: ",
                answer: scratch.passphrase(),
            },
            Interaction {
                prompt: "Confirm: ",
                answer: scratch.passphrase(),
            },
        ],
        TIMEOUT,
    )
    .expect("drive kv init on the Rust PTY harness");
    assert!(
        output.status.success(),
        "kv init failed with {}; captured terminal output suppressed ({} bytes)",
        output.status,
        output.transcript.len()
    );
    output
}

fn set_secret(scratch: &Scratch, provider: &MockProvider, secret: &str) -> pty::PtyOutput {
    // Deliberately no `NAME=value`: v1 requires `kv set` to take the value at a
    // hidden terminal prompt so it never appears in argv or shell history.
    let args = vec![
        "set".to_owned(),
        kv_v1_launch_gate::harness::SECRET_NAME.to_owned(),
    ];
    let output = pty::run(
        &kv_bin(),
        &args,
        &scratch.proj(),
        &gate_envs(scratch, provider),
        &[
            Interaction {
                prompt: "Passphrase: ",
                answer: scratch.passphrase(),
            },
            Interaction {
                prompt: "Value: ",
                answer: secret,
            },
        ],
        TIMEOUT,
    )
    .expect("drive kv set on the Rust PTY harness");
    assert!(
        output.status.success(),
        "kv set failed with {}; captured terminal output suppressed ({} bytes)",
        output.status,
        output.transcript.len()
    );
    output
}

fn lock_vault(scratch: &Scratch, provider: &MockProvider) -> Output {
    plain(scratch, provider, &["lock".to_owned()])
}

fn approve_permit(
    scratch: &Scratch,
    provider: &MockProvider,
    request_id: &str,
    ttl_seconds: Option<u64>,
    approve: bool,
) -> pty::PtyOutput {
    pty::run(
        &kv_bin(),
        &approve_args(request_id, ttl_seconds),
        &scratch.proj(),
        &gate_envs(scratch, provider),
        &[
            Interaction {
                prompt: "Passphrase: ",
                answer: scratch.passphrase(),
            },
            Interaction {
                prompt: "Sign this one-call permit? [y/N] ",
                answer: if approve { "y" } else { "n" },
            },
        ],
        TIMEOUT,
    )
    .expect("drive owner permit decision on the Rust PTY harness")
}

fn synthetic_body(marker: &str) -> String {
    format!(
        r#"{{"model":"kv-v1-release-gate","max_tokens":1,"messages":[{{"role":"user","content":"{marker}"}}]}}"#
    )
}

fn assert_loopback_secret_call(provider: &MockProvider, secret: &str, body: &str) {
    // The public provider-call CLI is synchronous. A short settle time only covers
    // loopback socket scheduling; it must not hide a second outbound call.
    std::thread::sleep(Duration::from_millis(100));
    let requests = provider.requests();
    assert_eq!(
        requests.len(),
        1,
        "approved one-shot call must reach the loopback provider exactly once"
    );
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, PROVIDER_PATH);
    assert!(
        request.header("x-api-key") == Some(secret),
        "built-in anthropic auth must be injected by the broker, not the caller"
    );
    assert_eq!(request.body, body.as_bytes());
}

fn assert_recovery_output_excluded(label: &str, bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    for marker in [
        "kvrecovery_",
        "Recovery key generated.",
        "Type saved when you have stored the key:",
    ] {
        assert!(
            !text.contains(marker),
            "recovery output marker {marker:?} appeared in {label}"
        );
    }
}

fn audit_log_path(scratch: &Scratch) -> std::path::PathBuf {
    scratch.home().join(".kv").join("audit.jsonl")
}

// ── tests that run now ─────────────────────────────────────────────────────

#[test]
fn rust_harness_can_init_and_set_without_echoing_the_secret() {
    let provider = MockProvider::start();
    let scratch = Scratch::new("init-set");
    let secret = synthetic_secret();
    let init = init_vault(&scratch, &provider);
    let set = set_secret(&scratch, &provider, &secret);
    let audit_records = audit::verify_file(&audit_log_path(&scratch))
        .expect("current kv audit output must pass the independent Rust verifier");
    assert!(audit_records > 0);
    assert_recovery_output_excluded("kv init pty transcript", &init.transcript);
    assert_secret_absent(
        &secret,
        &[
            ("kv init pty transcript", &init.transcript),
            ("kv set pty transcript", &set.transcript),
        ],
        &[(
            "kv set",
            &[
                "set".to_owned(),
                kv_v1_launch_gate::harness::SECRET_NAME.to_owned(),
            ],
        )],
        &[&scratch.home(), &scratch.proj()],
    );
    assert_secret_absent(
        scratch.passphrase(),
        &[
            ("kv init pty transcript", &init.transcript),
            ("kv set pty transcript", &set.transcript),
        ],
        &[],
        &[&scratch.home(), &scratch.proj()],
    );
}

// ── locked v1 contract tests, wired but ignored until the product slice lands ──

#[test]
#[ignore = "UNTESTED: v1 direct brokered provider-call CLI is not implemented yet"]
fn v1_one_shot_approval_sends_exactly_one_authenticated_loopback_call() {
    let provider = MockProvider::start();
    let scratch = Scratch::new("approved-call");
    let secret = synthetic_secret();
    let marker = "release-gate-one-shot";
    let body = synthetic_body(marker);
    let mut transcripts: Vec<(String, Vec<u8>)> = Vec::new();
    let mut argv: Vec<(String, Vec<String>)> = Vec::new();

    let doctor_args = vec!["doctor".to_owned()];
    let doctor = plain(&scratch, &provider, &doctor_args);
    assert_success(&doctor, "kv doctor");
    transcripts.push(("kv doctor stdout".to_owned(), doctor.stdout));
    transcripts.push(("kv doctor stderr".to_owned(), doctor.stderr));
    argv.push(("kv doctor".to_owned(), doctor_args));

    let init = init_vault(&scratch, &provider);
    transcripts.push(("kv init pty transcript".to_owned(), init.transcript));
    argv.push((
        "kv init".to_owned(),
        vec![
            "init".to_owned(),
            "--location".to_owned(),
            "project".to_owned(),
        ],
    ));
    let set = set_secret(&scratch, &provider, &secret);
    transcripts.push(("kv set pty transcript".to_owned(), set.transcript));
    argv.push((
        "kv set".to_owned(),
        vec![
            "set".to_owned(),
            kv_v1_launch_gate::harness::SECRET_NAME.to_owned(),
        ],
    ));

    let request_args = provider_call_args(&body, None);
    let request = plain(&scratch, &provider, &request_args);
    let request_id = extract_request_id(&request).unwrap_or_else(|| {
        panic!(
            "provider call did not request a one-shot permit; stdout ({} bytes) and stderr ({} bytes) suppressed",
            request.stdout.len(),
            request.stderr.len()
        )
    });
    transcripts.push(("provider-call request stdout".to_owned(), request.stdout));
    transcripts.push(("provider-call request stderr".to_owned(), request.stderr));
    argv.push(("provider-call request".to_owned(), request_args.clone()));

    let approved = approve_permit(&scratch, &provider, &request_id, None, true);
    assert!(
        approved.status.success(),
        "owner approval failed with {}; captured terminal output suppressed ({} bytes)",
        approved.status,
        approved.transcript.len()
    );
    transcripts.push((
        "permit approval pty transcript".to_owned(),
        approved.transcript,
    ));

    let call_args = provider_call_args(&body, Some(&request_id));
    let call = plain(&scratch, &provider, &call_args);
    assert_success(&call, "approved brokered provider call");
    transcripts.push(("approved provider-call stdout".to_owned(), call.stdout));
    transcripts.push(("approved provider-call stderr".to_owned(), call.stderr));
    argv.push(("approved provider call".to_owned(), call_args.clone()));
    assert_loopback_secret_call(&provider, &secret, &body);

    // Replay of the same permit must add no second provider request.
    let replay = plain(&scratch, &provider, &call_args);
    transcripts.push(("permit replay stdout".to_owned(), replay.stdout));
    transcripts.push(("permit replay stderr".to_owned(), replay.stderr));
    assert_eq!(
        provider.count(),
        1,
        "replaying the spent permit reached the provider"
    );

    let audit_path = audit_log_path(&scratch);
    let records = audit::verify_file(&audit_path)
        .unwrap_or_else(|error| panic!("hash-chained audit verification failed: {error}"));
    assert!(records > 0, "audit verifier accepted an empty chain");

    let lock = lock_vault(&scratch, &provider);
    assert_success(&lock, "kv lock");
    transcripts.push(("kv lock stdout".to_owned(), lock.stdout));
    transcripts.push(("kv lock stderr".to_owned(), lock.stderr));

    let transcript_refs: Vec<(&str, &[u8])> = transcripts
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    let argv_refs: Vec<(&str, &[String])> = argv
        .iter()
        .map(|(name, args)| (name.as_str(), args.as_slice()))
        .collect();
    assert_secret_absent(
        &secret,
        &transcript_refs,
        &argv_refs,
        &[&scratch.home(), &scratch.proj()],
    );
}

fn zero_call_case(case: &str, prepare: impl FnOnce(&Scratch, &MockProvider, &str, &str)) {
    let provider = MockProvider::start();
    let scratch = Scratch::new(case);
    let secret = synthetic_secret();
    let body = synthetic_body(case);
    let _init = init_vault(&scratch, &provider);
    let _set = set_secret(&scratch, &provider, &secret);
    prepare(&scratch, &provider, &secret, &body);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(provider.count(), 0, "{case} reached the loopback provider");
}

#[test]
#[ignore = "UNTESTED: v1 direct brokered provider-call CLI is not implemented yet"]
fn v1_denial_expiry_payload_change_and_lock_send_zero_provider_calls() {
    // Denial: owner answers no; the request must never be spent.
    zero_call_case("denial", |scratch, provider, _secret, body| {
        let request = plain(scratch, provider, &provider_call_args(body, None));
        let request_id = extract_request_id(&request).expect("denial case needs a permit request");
        let denied = approve_permit(scratch, provider, &request_id, None, false);
        assert!(
            denied.status.success(),
            "denial command failed with {}; captured terminal output suppressed ({} bytes)",
            denied.status,
            denied.transcript.len()
        );
        let retry = plain(
            scratch,
            provider,
            &provider_call_args(body, Some(&request_id)),
        );
        assert!(
            !retry.status.success(),
            "denied permit retry unexpectedly succeeded"
        );
    });

    // Expiry: one-second permit lifetime elapses before the identical retry.
    zero_call_case("expiry", |scratch, provider, _secret, body| {
        let request = plain(scratch, provider, &provider_call_args(body, None));
        let request_id = extract_request_id(&request).expect("expiry case needs a permit request");
        let approved = approve_permit(scratch, provider, &request_id, Some(1), true);
        assert!(approved.status.success(), "short-lived approval failed");
        std::thread::sleep(Duration::from_secs(2));
        let retry = plain(
            scratch,
            provider,
            &provider_call_args(body, Some(&request_id)),
        );
        assert!(
            !retry.status.success(),
            "expired permit retry unexpectedly succeeded"
        );
    });

    // Payload change: the owner approved the original bytes; changing any byte voids it.
    zero_call_case("payload-change", |scratch, provider, _secret, body| {
        let request = plain(scratch, provider, &provider_call_args(body, None));
        let request_id = extract_request_id(&request).expect("payload case needs a permit request");
        let approved = approve_permit(scratch, provider, &request_id, None, true);
        assert!(approved.status.success(), "payload approval failed");
        let changed = body.replacen("release", "changed-release", 1);
        let retry = plain(
            scratch,
            provider,
            &provider_call_args(&changed, Some(&request_id)),
        );
        assert!(
            !retry.status.success(),
            "changed payload retry unexpectedly succeeded"
        );
    });

    // Locked vault: even an unspent valid permit is dead once `kv lock` purges broker keys.
    zero_call_case("locked-vault", |scratch, provider, _secret, body| {
        let request = plain(scratch, provider, &provider_call_args(body, None));
        let request_id = extract_request_id(&request).expect("lock case needs a permit request");
        let approved = approve_permit(scratch, provider, &request_id, None, true);
        assert!(approved.status.success(), "lock-case approval failed");
        let lock = lock_vault(scratch, provider);
        assert_success(&lock, "kv lock before permit use");
        let retry = plain(
            scratch,
            provider,
            &provider_call_args(body, Some(&request_id)),
        );
        assert!(
            !retry.status.success(),
            "locked-vault permit retry unexpectedly succeeded"
        );
    });
}
