# Native Command Bounds Design

## Purpose

AegisForge V0.1 invokes `/usr/bin/codesign` during macOS signature inspection. The current runner uses `Command::output()`, so a stalled child can block a scan indefinitely and an unexpectedly noisy child can consume unbounded memory. This module bounds each native invocation without changing signature facts, verdicts, evidence, or the public runner contract.

## Scope

This module will:

- impose a 30-second post-spawn supervision deadline on each native command, with synchronous spawn time charged against it immediately when `spawn()` returns;
- cap stdout and stderr independently at 1 MiB;
- keep stdin null, stdout/stderr separate, and arguments as atomic `OsString` values;
- terminate and reap the child when the deadline or either stream limit is exceeded;
- report timeout, output-limit, reader, termination, and wait failures as `NativeCommandError::Io`;
- retain `NativeCommandError::Unavailable` for executable-not-found spawn failures;
- preserve raw output bytes, exit status, and existing codesign reconciliation for commands that finish within the bounds.

It will not add a total-scan deadline, concurrency, cancellation UI, configuration flags, telemetry, shell support, a new async runtime, or Homebrew/V0.2 work.

## Considered Approaches

### 1. Dependency-free bounded process runner — selected

Replace `Command::output()` with `spawn()`, two pipe-reader threads, `try_wait()` deadline polling, and explicit termination/reaping. This keeps the existing architecture and dependencies while bounding both time and memory.

### 2. External timeout wrapper — rejected

Wrapping commands with a platform `timeout` executable would reduce Rust code, but macOS does not provide a consistent built-in command, and wrapping would add another executable boundary and complicate the existing exact-argument guarantee.

### 3. Async runtime or process-management crate — rejected

An async runtime or new crate could provide timeout primitives, but it would materially increase dependency and build complexity for two sequential codesign queries. The required behavior is small enough to implement and test with the standard library plus the already-present Unix `libc` dependency.

## Architecture

`NativeCommandRunner` and `NativeCommandOutput` remain unchanged. `SystemCommandRunner` remains the production unit struct so current construction sites do not change.

`src/macos/command.rs` gains private limits and helpers:

- `NativeCommandLimits` holds the deadline and per-stream byte cap;
- production constants provide 30 seconds and 1 MiB per stream;
- `run_with_limits` exists privately so tests can use short deadlines and small caps;
- a bounded reader owns one pipe, uses a fixed-size temporary buffer, retains at most the configured cap, and emits one structured outcome: complete output at EOF, stream overflow, or read error; after reporting overflow it continues draining/discarding until EOF so a non-hostile child cannot block on a full pipe;
- the parent loop polls child state, reader outcomes, and elapsed time every 10 milliseconds;
- normal success requires the direct child to exit and both readers to reach EOF without error or overflow before the same deadline;
- cleanup terminates the child/process group as supported, reaps the direct child, and gives readers a fixed close grace period before returning;
- reader handles are joined only after their completion is known, so an escaped descendant retaining a pipe cannot make cleanup block forever;
- fully bounded successful completion constructs the existing raw-byte output model.

On Unix, the child starts in its own process group using the safe `CommandExt::process_group(0)` API. Cleanup sends `SIGTERM` to `-child_pid`, polls for a fixed 100-millisecond grace interval, then sends `SIGKILL` to that process group and reaps the direct child if it has not already been reaped. `ESRCH` is benign when the group has already exited. This terminates descendants that remain in the child's process group; it is not containment against a program that deliberately escapes the group or session. After forced termination, readers receive a separate fixed 100-millisecond pipe-close grace interval. A handle whose reader still has not completed is detached rather than joined, preserving the runner's return bound. On non-Unix targets, cleanup uses `Child::kill()`, reaps the direct child, and applies the same nonblocking reader-completion rule. AegisForge's production native caller remains macOS-only and fixed to `/usr/bin/codesign`.

Unix-only imports and signaling are isolated behind `#[cfg(unix)]`; limits, readers, state supervision, and direct-child cleanup compile on other targets. No `pre_exec` closure is required.

## Data Flow

1. Build `Command` from the exact program path and `OsString` arguments.
2. Set null stdin and piped stdout/stderr; create a separate Unix process group.
3. Start a monotonic deadline immediately before spawning the child, preserving the existing NotFound-versus-I/O classification. Synchronous OS process creation cannot itself be interrupted, but its elapsed time counts against the deadline as soon as `spawn()` returns.
4. Move stdout and stderr into independent bounded readers. Failure to acquire a pipe or spawn either reader initiates cleanup immediately.
5. Poll structured reader events and the child with `try_wait()` every 10 milliseconds. Track child status separately so an already-reaped child is never waited twice.
6. Continue polling after direct-child exit until both readers report complete EOF. Only child exit plus two complete reader outcomes before the deadline is success.
7. Treat these as abnormal terminal conditions:
   - either stream observes a byte count greater than 1 MiB, including if the child has already exited;
   - either reader reports an I/O error or its event channel disconnects;
   - the deadline expires before child exit and both reader EOFs;
   - child-state polling fails.
8. On an abnormal condition, terminate the process group/direct child, force escalation after the fixed grace period, reap when needed, and wait only a bounded interval for reader completion. Discard all partial output and return `NativeCommandError::Io` with operation context.
9. On success, join the already-completed readers and return raw bytes plus the recorded status. Reader join failure overrides success and returns `Io`.

Partial or truncated output is never passed to the codesign parser, so bounded failures cannot create misleading signature facts.

## Error Handling

- Spawn `NotFound` stays `Unavailable`.
- Other spawn failures stay `Io`.
- Deadline expiry returns an `Io` message naming the executable and timeout duration. The deadline covers child execution and both streams reaching EOF; pipes still open at the deadline are a timeout even when the direct child already exited.
- Stdout/stderr overflow returns an `Io` message naming the stream and byte cap. Exactly 1 MiB is accepted; the first byte beyond the cap is overflow.
- Pipe acquisition, read, poll, kill, wait, or reader-join failures return `Io` with the executable and failed operation.
- Cleanup is attempted for every post-spawn failure. A cleanup error is included without hiding the original timeout/overflow reason.
- Overflow and reader errors take precedence over an otherwise successful exit. No scheduling race may expose truncated output to parsing.
- No recoverable production path panics or unwraps.

The codesign layer already maps runner `Io` failures to `NativeCheckStatus::Error` and typed diagnostics, so no reconciliation or reporting changes are required.

## Testing

Tests will use the same production code path with private short limits. Controlled helper tests invoke the current Rust test executable through an absolute path and an exact test filter; helper behavior is encoded in dedicated test functions, uses no shell, and is inert during the ordinary suite run.

- a normal command preserves separate raw streams and exit status;
- a sleeping command times out promptly and is reaped;
- a helper that ignores `SIGTERM` proves fixed-grace `SIGKILL` escalation and prompt return;
- a direct child that exits after spawning a same-group descendant holding an output pipe cannot bypass the deadline; the group is terminated and the runner returns `Io`;
- stdout and stderr helpers that emit over-cap output and then exit still return the corresponding output-limit error rather than success;
- bounded-reader unit tests cover exact-cap acceptance, the first byte beyond the cap, fixed temporary-buffer behavior, and injected read errors;
- state-supervision seams cover reader error/channel-disconnect and pipeline-setup cleanup without requiring nondeterministic OS failures;
- a nonzero command within limits still returns `NativeCommandOutput` rather than an operational error;
- missing and permission-denied spawn classification remains unchanged;
- the existing real macOS `/usr/bin/codesign` test continues to pass;
- full formatting, locked/offline check/test/build, strict Clippy, and `scripts/check-all.sh` gates remain green.

Process-execution tests are gated to Unix or macOS as appropriate; portable reader/state tests run everywhere. Tests invoke fixed absolute tools or the absolute current test executable with atomic arguments and never use a shell.

## Security and Operational Invariants

- A scanned artifact is never executed or modified.
- No shell or command-string parsing is introduced.
- Retained output memory is bounded per reader and invocation before parsing. A deliberately escaped descendant can keep a detached reader thread and its capped buffer alive after cleanup grace; global containment of a hostile process tree is outside the fixed-`codesign` V0.1 threat model.
- Timeout/overflow output is discarded rather than interpreted.
- The direct child is reaped exactly once, preventing zombies even when `try_wait()` observed its exit before a later pipe failure.
- Same-group descendants receive TERM then KILL, but deliberate process-group/session escape is outside this fixed-codesign V0.1 threat model.
- Cleanup never performs an unbounded reader join; an unfinished handle after forced close grace is detached and the operation returns `Io`.
- Signature failures remain nonfatal per target and do not influence evidence, verdict, or artifact summary counts.
- The limits are compile-time V0.1 policy, not user-controlled input.
