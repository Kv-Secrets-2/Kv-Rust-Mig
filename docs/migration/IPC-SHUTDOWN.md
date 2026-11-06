# IPC and daemon shutdown migration

This slice follows the pinned Python 0.4.0 source at
`9a497d91a0f6e95b0949deaf8f5c431f9a4333c0` and builds on PR #15's verified
head, `14e5cf5e192897a16ddd750465f5bf0ceb52d94e`.

## Compatibility decisions

The baseline audit proposed one absolute deadline for every exchange and
request frame. Reading the actual callers showed that this would change the
reference's behavior. The implemented contract is:

| Operation | Budget and completion |
|---|---|
| Ordinary `agent_request` | 30 seconds per socket operation; read through EOF |
| Explicit request override | Caller-selected duration; `None` disables timeouts |
| Enforcement preflight | 5-second connect and send budgets, then a fresh absolute 5-second reply deadline; accept complete JSON before EOF |
| MCP status probe | One 2-second connect/send budget, then a fresh absolute 2-second reply deadline; accept complete JSON before EOF |
| Daemon request frame | Python's 130-second per-read timeout; shutdown closes idle framing sockets |
| Stop without a choice | Retire admission; report committed work and await the owner if work remains |
| Stop `wait` | One 135-second committed-work drain |
| Stop `now`, SIGTERM, SIGINT, SIGHUP | One 10-second committed-work drain |
| Missing owner choice | After 135 seconds, begin the short drain |

These are distinct budgets. In particular, a generic `api` request is not
silently assigned the explicit Python SDK caller's 120-second timeout. The new
`agent_request_with_timeout` API allows each migrated caller to choose its own
reference timeout. Ordinary reads can still take longer than 30 seconds when
each fragment arrives in time; this is intentional Python compatibility.

Connect and send use nonblocking Unix sockets with deadline-aware waits. A full
Linux Unix-socket backlog is retried as an uncompleted connect, never mistaken
for a successful writable socket. Probe reads preserve the 4 MiB received-byte
cap, accept fragmented UTF-8, and reject already-buffered trailing documents.

## Shutdown ownership

Provider and ordinary reply admission share a lock with retirement. A provider
window opens after validation and custom URL-safety checks, immediately before
entering HTTP transport, and closes when the operation returns. A normal reply
must obtain its own window. Neither a prepared request nor an accepted socket
grants permission to send after retirement.

The first stop deadline stands. Later choices or signals may shorten it but
cannot restart or extend it. `cut_off` records the committed count at the drain
boundary and remains stable if a worker finishes just afterward. Invalid
non-null choices, including non-string JSON values, are refused without stopping
the daemon. Requests arriving while a choice is pending receive `agent_stopping`;
already-dispatched ordinary replies follow the reference's hard-lock replacement
path. Stop and enforcement control replies carry no work authority.

The foreground closes its listener and removes matching runtime files before
draining. Idle partial-frame readers are closed. The drain is followed by at
most two seconds for stop answers and prepared retirement refusals. Completed
workers are reaped during normal service rather than retained for its lifetime.
Accept/spawn failures follow the same cleanup path. Each daemon session owns its
signal flag, so overlapping in-process sessions do not reset one another's flags.

Runtime cleanup opens token/PID files without following symlinks or blocking on
FIFOs, reads only the expected length, and checks the opened/named inode before
removing a matching file. Socket removal retains its identity check.

## Limits

A synchronous system resolver cannot be forcibly cancelled safely. A provider
operation already committed before retirement may physically send or complete
after the drain deadline. A cut-off request may already have succeeded at its
provider; the reply must not claim otherwise. As in Python, a bounded foreground
return does not imply that every background worker has ended or every secret has
already been erased. Retired workers explicitly retain their join handles,
keys, and vault-folder pins until completion; no pin is closed beneath them.

This slice does not add a connection concurrency cap or an absolute total frame
deadline to the running daemon. It does not implement subprocess execution,
permits, capabilities, audit hardening, Windows daemon transport, or full
hard-lock lifecycle parity for filesystem changes. Those remain separate gates.

## Validation

The parity inventory now requires 35 live comparison tests, up from 29. New
comparisons cover transport framing and timeouts plus invalid stop choices,
idle clients, in-flight HTTPS wait/cutoff, signal cleanup, and a URL-safety check
that returns after retirement. Tests use private local sockets, a temporary
HTTPS CA, independent process homes, and bounded child-process collection.

The original audit remains historical evidence. Validation results for this
slice are recorded separately when the full gate completes.
