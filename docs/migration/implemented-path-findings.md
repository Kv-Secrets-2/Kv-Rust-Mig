# Implemented-path source review

Reviewed Rust commit: `3a9c3c7d1cc9ee34ab801ff02ffb64114561dc16` on `codex/migration-baseline-audit`.

Python reference: `/workspace/kv-secrets`, release candidate commit `9a497d91a0f6e95b0949deaf8f5c431f9a4333c0`.

**Evidence status: static source review only.** The four findings below were identified by reading implementation and reference code. This reviewer did not reproduce them with running processes, execute tests, or modify either repository. Acceptance checks below are proposals, not completed validation. Baseline test results and separately reproduced findings belong in the root audit report.

Scope: bounded review of daemon authorization routing, broker policy-to-secret-lookup ordering, owner-message checking, IPC framing/liveness, HTTP transport guards, and the implemented API audit writer. This is not a complete security assessment.

## F1 — Client exchanges have no deadline

Rust evidence:

- `crates/kv-proto/src/lib.rs:404`: `exchange` opens a blocking Unix socket with `UnixStream::connect` at line 408.
- `crates/kv-proto/src/lib.rs:414`: request write, write-side shutdown, and `read_reply` execute without a socket timeout or shared absolute deadline.
- `crates/kv-proto/src/lib.rs:466`: `read_reply` reads until EOF. Its byte cap limits size, not time.
- `crates/kv-proto/src/lib.rs:441`: ordinary requests first use this same unbounded exchange for the enforcement probe.

Impact: a local endpoint that accepts and then stops reading, never replies, or replies without closing can indefinitely block a calling thread. This affects the protocol client and owner-channel exchange paths that use it. It is an availability defect; this review does not establish credential disclosure or authentication bypass. Reaching a substituted endpoint requires control of or access to the relevant local runtime endpoint; a broken genuine daemon can also trigger the behavior.

Reference gap: Python bounds the service probe in `kv/agent.py:3287` and the reply reader in `kv/agent.py:2940`. The reader computes the remaining time on each read from an absolute deadline, rather than granting each fragment a fresh budget.

Proposed acceptance checks:

1. A private Unix test listener accepts a client and sends no reply: the exchange fails within its configured budget and closes its connection.
2. A peer sends a valid response but holds the connection open: the selected public API's documented completion semantics and deadline match Python.
3. A peer trickles incomplete JSON fragments, each arriving before an individual socket timeout: total time still cannot exceed the shared exchange budget.
4. Cover blocked send/connection behavior as well as stalled reads. A successful response near the deadline remains accepted.
5. Run existing Rust/Python channel and client differential checks with `KV_PY_REF` set; explicitly verify those comparisons ran.

## F2 — Worker lifetime and shutdown are not bounded

Rust evidence:

- `crates/kv-agent/src/lib.rs:665`: one `Vec` retains all worker join handles for the daemon lifetime.
- `crates/kv-agent/src/lib.rs:683`: every accepted connection spawns a thread, before parsing or authenticating its request. No admission bound or periodic completed-worker collection is present in the accept loop.
- `crates/kv-agent/src/lib.rs:1086`: request handling sets per-read/per-write socket timeouts and calls `kv_proto::read_request`.
- `crates/kv-proto/src/lib.rs:327`: the request reader repeatedly reads until a complete JSON document or failure, without an absolute time budget.
- `crates/kv-agent/src/lib.rs:714`: shutdown synchronously joins every retained worker without a bound; runtime-file cleanup follows the joins.
- `crates/kv-agent/src/lib.rs:931`: the stop response advertises `wait_seconds:10`.

Impact: an incomplete request sent in fragments can keep a worker occupied well beyond the advertised stop wait. The message-size ceiling eventually limits total bytes but does not supply a practical time bound. A stop request can return while daemon termination and runtime cleanup remain blocked by another worker. Even normal completed requests leave retained handle bookkeeping until shutdown, producing growth with lifetime request count. This is a local availability/resource issue, not proof of permission escalation.

Reference gap: Python also creates a per-connection thread, so this review does **not** claim the Python implementation already has a connection concurrency cap. However, Python marks request threads as daemon threads (`kv/agent.py:8437`), cleans runtime files before its bounded committed-work drain (`kv/agent.py:8460` and `kv/agent.py:8470`), and explicitly uses the remaining chosen stop budget. Rust's source comment at `crates/kv-agent/src/lib.rs:604` defers draining to Stage 6, but the current API broker already performs concurrent work and should not promise a shutdown bound it cannot satisfy.

Proposed acceptance checks:

1. Hold one unauthenticated connection with a deliberately incomplete JSON document while making a valid stop request on another connection. Observe process exit and removal of its owned socket/token/PID files within the defined shutdown budget.
2. Repeat while trickling fragments often enough to defeat a per-read timeout; the absolute request/stop budget still wins.
3. Exercise a genuine in-flight broker call during stop. Verify the chosen wait/cutoff behavior against Python and ensure no new request is admitted after stop begins.
4. Send many completed short requests and demonstrate that completed worker state is reclaimed. If a concurrency bound is introduced, test overload refusal/recovery without blocking the stop control path.
5. Confirm shutdown only removes runtime files still belonging to the terminating daemon, preserving the existing replacement-identity protections.

## F3 — API audit writes follow symlinks and modify the linked target

Rust evidence:

- `crates/kv-agent/src/lib.rs:1385`: the audit directory is formed as `HOME/.kv`, then created and chmodded by path.
- `crates/kv-agent/src/lib.rs:1389`: `OpenOptions` opens `audit.jsonl` for read/append/create using its full path, without a no-follow flag or a pinned directory descriptor.
- `crates/kv-agent/src/lib.rs:1394`: permissions are changed on the opened target; there is no preceding owner/type/identity check.

Impact: a symlink at the audit directory or file can redirect permission changes and audit appends to another file accessible to the daemon's account. The daemon can therefore alter an unintended owner-accessible target while handling an otherwise legitimate API request. This review does not claim access beyond the process account's existing filesystem authority. The relevant boundary is preservation of local files and correct attribution of audit writes in the presence of linked/replaced paths.

Reference gap: Python explicitly refuses linked audit folders and opens a checked directory descriptor in `kv/audit.py:679`. Its documentation at lines 682–692 states that subsequent operations are relative to that held descriptor and must not read or write through a replacement folder. The file-open path also uses no-follow/descriptor checks in the surrounding audit helpers; Rust's API audit function does not port them.

Proposed acceptance checks:

1. Point `HOME/.kv` at a synthetic external directory. An API audit attempt must not change that directory's mode, create files inside it, or alter its contents.
2. Make `audit.jsonl` a symlink to a sentinel file; verify its content and mode remain byte-for-byte unchanged.
3. Replace the directory name after the safe opener has acquired its descriptor. Later operations must remain bound to the validated directory or refuse, never follow the replacement.
4. Reject non-regular audit targets and unsafe ownership without blocking on a FIFO or changing a target's mode before it is validated.
5. Preserve ordinary successful private-file creation, append behavior, and observable audit-failure reporting.

## F4 — Audit chain updates are not coordinated across processes

Rust evidence:

- `crates/kv-agent/src/lib.rs:1379`: a static `Mutex` serializes only threads in the current process.
- `crates/kv-agent/src/lib.rs:1395`: the writer reads the existing shared `HOME/.kv/audit.jsonl` and derives the previous hash.
- `crates/kv-agent/src/lib.rs:1479`: the new entry's digest is calculated from that previous hash.
- `crates/kv-agent/src/lib.rs:1498`: the entry is appended without an interprocess lock spanning read, hash calculation, and append.
- `crates/kv-agent/src/lib.rs:912`: the caller discards the audit writer's `Result`.

Impact: two vault daemons under the same account share this audit path but not its mutex. They can read the same last hash and then both append entries with that predecessor, breaking the sequential hash chain. The issue does not depend on an attacker or a hash collision. Filesystem failures can also silently omit API audit records because the caller discards the error; this is a related observability gap, not evidence that API authorization itself is bypassed.

Reference gap: Python describes the cross-process requirement explicitly at `kv/audit.py:1568`. It holds a filesystem lock from before the tail read through the health update (`kv/audit.py:1593`), refuses unlocked appends, and records/warns about losses when the lock is unavailable (`kv/audit.py:1599`). Rust currently implements neither cross-process serialization nor corresponding loss reporting in this path.

Proposed acceptance checks:

1. Run two independent daemon processes with distinct synthetic vaults and one private audit home. Concurrently trigger API audit records, then verify a single continuous chain and exactly the expected records.
2. Make the race deterministic with a supported test seam around the tail-read/write transaction; a thread-only test is insufficient because the existing mutex would hide the defect.
3. Verify interoperability with a concurrent Python audit writer if both versions may share the same audit path; lock filename/protocol must agree.
4. Hold or replace the lock file while writing. The implementation must follow the reference's bounded refusal/uncertain-write behavior, with no unlocked append and a visible loss indication.
5. Inject write/flush failures and verify audit loss is reported without accidentally exposing request credentials or silently claiming complete coverage.

## Deliberately unsupported surfaces — not authorization bypass findings

- `crates/kv-agent/src/lib.rs:828` recognizes `run`, `cap_api`, `permit_requests`, pause, and dashboard command names, but unimplemented cases return the unsupported error at line 937.
- `crates/kv-agent/src/lib.rs:1012` refuses owner endpoints other than `owner_channel` as unsupported.
- `crates/kv-agent/src/lib.rs:1306` rejects an API permit as missing/expired, and line 1317 rejects supplied permits for otherwise allowed calls. A working one-call-permit lifecycle is not present.
- There is no `kv-sandbox` or `kv-hook` crate at this commit.
- `crates/kv-cli/src/main.rs:12` exposes only version and MCP-server commands.
- `crates/kv-agent/src/lib.rs:724` explicitly refuses Windows daemon startup.

These omissions establish remaining migration work. They must not be presented as proven exploit paths or as completed Stage 5/6/8/9/10 gates. The MCP frontend can reproduce Python presentation against the same incomplete Rust daemon without proving the missing backend behavior.

## Suggested corrective sequence and review limits

Complete and record the baseline audit/test run first, including actual execution of Python differential tests. Then agree a small corrective slice for F1/F2 (IPC deadlines, worker lifecycle, and bounded stop behavior), followed by F3/F4 (audit filesystem boundary and cross-process serialization). The next feature slice remains Stage 5b's one-call-permit lifecycle, with positive admission, consumption, denial, and replay checks before capability/sandbox expansion.

This review did not establish an authentication or HTTP route-policy bypass. It did not exhaustively inspect cryptography, signing canonicalization, every filesystem race, every HTTP parsing case, or macOS/Windows behavior. Findings beyond the four above require their own evidence. The root audit separately investigates reproduced baseline/parity failures; they are intentionally not claimed as reproduced by this document.
