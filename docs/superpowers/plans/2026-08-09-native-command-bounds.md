# Native Command Bounds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound every native codesign invocation by time and per-stream memory while preserving exact arguments, raw successful output, existing error mapping, and nonfatal scan behavior.

**Architecture:** Replace `Command::output()` inside `SystemCommandRunner` with a private, dependency-free supervisor. Two bounded reader threads report structured stdout/stderr outcomes, while the parent tracks their handles and one monotonic deadline; it polls child state only after both streams reach EOF. Unix children run in a new process group. Abnormal completion uses fixed TERM/KILL, bounded best-effort direct-child reap polling, and reader-close grace periods, discards partial output, reports cleanup failures without hiding the primary error, and returns the existing `NativeCommandError::Io` type.

**Tech Stack:** Rust 2024 standard library (`std::process`, `std::thread`, `std::sync::mpsc`, `std::time`), existing Unix `libc` dependency, Cargo locked/offline test gates.

**Commit policy:** Do not commit after individual tasks. After all tasks and reviews pass, create one coherent implementation commit containing the dependency-scope comment, command supervisor, codesign integration regression, corrected design spec, and plan, then push the module branch `feature/native-command-hardening`. The completed `feature/cli-skeleton` branch remains unchanged.

---

### Task 1: Implement and Test Bounded Stream Readers

**Files:**

- Modify: `src/macos/command.rs`
- Test: `src/macos/command.rs`

- [ ] **Step 1: Add failing bounded-reader tests**

Add portable unit tests around a private reader helper using `Cursor<Vec<u8>>` and a custom `Read` implementation that returns a synthetic error. Cover:

- exactly `limit` bytes returns `ReaderEvent::Complete` with identical raw bytes;
- `limit + 1` bytes returns `ReaderEvent::LimitExceeded` for the correct `NativeStream`;
- the retained vector's length and capacity never exceed `limit` before overflow;
- an instrumented reader observes fixed 8 KiB read requests rather than requests proportional to attacker-controlled output;
- a read error returns `ReaderEvent::ReadFailed` with stream identity and operation context;
- stdout and stderr identities remain distinct;
- the thread wrapper emits exactly one overflow event before EOF, then continues consuming/discarding through EOF (use a blocking instrumented reader to prove the event arrives before the reader is released to EOF).

Use small caps such as 8 and 32 bytes. Do not allocate an unbounded fixture.

- [ ] **Step 2: Run focused tests to verify RED**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::command::tests::bounded_reader -- --nocapture
```

Expected: compilation failure because `NativeStream`, `ReaderEvent`, and the bounded reader do not exist.

- [ ] **Step 3: Add the minimal private reader model**

Add private types equivalent to:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeStream {
    Stdout,
    Stderr,
}

enum ReaderEvent {
    Complete {
        stream: NativeStream,
        bytes: Vec<u8>,
    },
    LimitExceeded {
        stream: NativeStream,
        limit: usize,
    },
    ReadFailed {
        stream: NativeStream,
        message: String,
    },
}
```

Implement one `Read`-generic bounded loop with a fixed 8 KiB stack buffer. Back retained output with fixed storage sized to `limit` (for example `vec![0; limit]` plus a retained-length cursor) so capacity cannot grow beyond the configured cap. Exactly `limit` bytes succeeds; the first byte beyond the limit emits `LimitExceeded`. The thread-backed production wrapper must send the overflow event immediately, then continue reading and discarding until EOF so a cooperative child does not block on a full pipe. A read error before overflow emits `ReadFailed`; an error after overflow does not replace the already-reported primary limit failure.

Use `std::thread::Builder::spawn` so reader-thread creation failure is an `io::Error`, not a panic.

- [ ] **Step 4: Run focused tests and formatting**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::command::tests::bounded_reader
cargo fmt --all -- --check
git diff --check
```

Expected: reader tests pass with no production panic/unwrap/expect.

---

### Task 2: Supervise Child, Deadline, and Cleanup as One State Machine

**Files:**

- Modify: `src/macos/command.rs`
- Test: `src/macos/command.rs`

- [ ] **Step 1: Add failing supervision tests and inert helper processes**

Add private limits:

```rust
#[derive(Debug, Clone, Copy)]
struct NativeCommandLimits {
    timeout: Duration,
    output_limit: usize,
    poll_interval: Duration,
    termination_grace: Duration,
    reader_close_grace: Duration,
}
```

Production values:

```text
timeout: 30 seconds
output_limit: 1 MiB per stream
poll_interval: 10 milliseconds
termination_grace: 100 milliseconds
reader_close_grace: 100 milliseconds
```

Add `#[cfg(unix)]` controlled helper tests. Create a uniquely owned temporary directory and a symlink to the absolute current Rust test executable whose filename carries an AegisForge helper marker. Invoke that marked path with `--exact <full helper test name> --nocapture`. Each helper checks both its exact test filter and marked `argv[0]`; it returns immediately during an ordinary or manually focused Cargo test run. Marker/PID files live beside the marked executable, so no unrecognized test-harness arguments or environment mutation are needed.

Cover:

1. a helper that atomically records its PID, installs a `SIGTERM` handler, records TERM receipt to a marker file from its normal loop, and deliberately remains alive: a short test deadline/grace must return timeout `Io`; assert the TERM marker exists and polling `kill(pid, 0)` reaches `ESRCH`, proving TERM preceded forced KILL;
2. a helper that spawns a second marked-test-executable helper with inherited stdout/stderr and then exits. The descendant helper atomically records its PID, installs the same TERM-recording handler, and deliberately remains alive after TERM. Direct-child exit alone must not be success; the open pipe must reach the shared deadline while the exited leader remains unreaped, group cleanup must run, and `Io` must return promptly. Assert the descendant TERM marker exists and polling `kill(pid, 0)` reaches `ESRCH`. This proves TERM and forced KILL both target the process group while its leader identity remains pinned;
3. a helper that writes more than a small cap to stdout and exits: result must be stdout-limit `Io`, never successful output;
4. the same for stderr;
5. a helper that exits nonzero with bounded separate output: return `NativeCommandOutput` with raw streams and exit code;
6. a direct `/bin/sleep` timeout returns promptly;
7. test-only supervision seams receiving a synthetic reader error, disconnected outcome channel, or one finished/panicked reader while its sibling sender remains live initiate cleanup promptly and return the reader failure as primary `Io`;
8. a test-only post-spawn setup-failure seam attempts bounded termination/reaping of a running child and confirms that the controlled helper reaches `ESRCH`;
9. cleanup/state seams prove an already recorded `ExitStatus` skips all numeric signaling and reaping, while an unreaped leader remains pinned through group TERM/KILL before direct-child kill and bounded nonblocking reap polling;
10. `run_with_limits` rejects any `output_limit` above the 1 MiB production maximum before spawn or reader allocation, returning `NativeCommandError::Io` instead of risking a reader-thread allocation panic. Zero and small test caps remain valid.
11. through the full `run_with_limits` path, an exited leader remains unreaped while its bounded, self-exiting pipe-holding descendant creates a new session. This proves signals to the recorded child PGID may be ineffective, direct-child kill/reap polling and reader cleanup still return promptly, and both helper PIDs reach confirmed `ESRCH`. Pathological `Duration::MAX` limits return structured `Io` before spawn.

Never invoke `sh`, `bash`, or a command string. Use only the absolute current test executable and fixed absolute system executables with atomic `OsString` arguments.

- [ ] **Step 2: Run focused tests to verify RED**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::command::tests -- --nocapture
```

Expected: compile-RED because the new private limits, marked-helper runner, supervision, and cleanup seams do not exist. Do not run a long-sleep helper through the old public runner before the bounded private seam compiles.

- [ ] **Step 3: Implement exact command setup and configurable private runner**

Keep the public type and trait unchanged:

```rust
pub struct SystemCommandRunner;
```

`NativeCommandRunner::run` must delegate to a private `run_with_limits(program, arguments, production_limits())`.

Before constructing or spawning a command, validate `limits.output_limit <= MAX_NATIVE_OUTPUT_BYTES`, where `MAX_NATIVE_OUTPUT_BYTES` is the same 1 MiB compile-time policy used by production. The bounded reader is private and may only be started through this validated supervision path outside its controlled unit tests. This makes pathological future/test seam limits a structured `Io` error before the reader's fixed allocation.

Build the process only as:

```rust
let mut command = Command::new(program);
command
    .args(arguments)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
```

Under `#[cfg(unix)]`, import `std::os::unix::process::CommandExt` and call `command.process_group(0)`. Do not use a shell, environment mutation, current-directory mutation, string parsing, or `pre_exec`.

Record `Instant::now()` immediately before `spawn()`. Preserve existing spawn classification exactly. After spawn returns, take both pipes and start readers; any acquisition/thread-start failure enters cleanup and returns `Io`.

- [ ] **Step 4: Implement the parent supervision loop**

Track independently:

- optional direct-child `ExitStatus`;
- optional completed stdout bytes;
- optional completed stderr bytes;
- the single shared deadline;
- reader handles and whether each has reported a terminal event.

On every iteration:

1. drain available structured reader events;
2. make overflow/read failure the primary operation failure even if child exit was already observed;
3. after draining events, inspect stream-identified reader handles; a finished handle without its terminal outcome is an immediate reader-disappearance failure even if the sibling sender remains live;
4. poll `child.try_wait()` only after both reader EOF outcomes exist, then only until an exit status has been recorded; this keeps an exited leader with open descendant pipes unreaped and its process-group identity pinned through timeout cleanup;
5. return success only when status plus both complete outputs exist;
6. if the deadline is reached first, return timeout failure;
7. sleep for at most the smaller of the poll interval and remaining deadline.

Channel disconnect before both complete outcomes is a reader failure. After cloning one sender into each reader, explicitly drop every parent-held `Sender`. Finished-handle inspection makes one reader's disappearance observable without waiting for its sibling sender to drop. Join reader handles on success only after completion events make the join nonblocking. A join panic becomes `Io` and successful output is discarded.

- [ ] **Step 5: Implement bounded cleanup**

Create a cleanup helper that receives the child, whether its exit was already observed, reader handles, and the primary failure.

On Unix:

- checked-convert `child.id()` to a positive `i32`;
- if the direct child was already reaped after both reader EOFs, skip all numeric signaling and reaping;
- send `SIGTERM` to the negative PID process group using narrowly scoped `libc::kill` with a SAFETY comment;
- treat `ESRCH` as already gone;
- keep the direct leader unreaped for `termination_grace`, then send `SIGKILL` to the same group while its PID identity remains pinned (again treating `ESRCH` as benign);
- independently call `Child::kill()` for the direct child, then use only bounded `try_wait()` polling to reap it. A failed or ineffective kill must never be followed by blocking `wait()`.

On non-Unix, use the same direct-child kill plus bounded `try_wait()` polling when not already reaped.

After termination, poll reader `JoinHandle::is_finished()` and drain events for at most `reader_close_grace`. Join only finished handles. Drop/detach an unfinished handle rather than blocking. Preserve the original timeout/output/read/setup reason and append cleanup details if kill, bounded-reap polling, or join fails.

Never return partial stdout/stderr for an abnormal operation.

- [ ] **Step 6: Run focused, full, and strict gates**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::command::tests
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
cargo fmt --all -- --check
YRX_REGENERATE_MODULES_RS=false cargo clippy --all-targets --all-features --locked --offline -- -D warnings
git diff --check
```

Expected: all new supervision cases and all existing tests pass with no warnings.

---

### Task 3: Validate codesign Integration and Complete the Module Branch

**Files:**

- Modify: `Cargo.toml` (existing Unix `libc` dependency-scope comment only)
- Modify: `src/macos/codesign.rs` (focused bounded-runner error regression only)
- Modify: `src/macos/command.rs`
- Modify: `docs/superpowers/specs/2026-08-09-native-command-bounds-design.md` (reviewed lifecycle corrections)
- Modify: `docs/superpowers/plans/2026-08-09-native-command-bounds.md`

- [ ] **Step 1: Add/confirm integration assertions**

Confirm existing tests already prove independent runner-error statuses, later-target continuation, and evidence/verdict/summary isolation. Add exactly one focused codesign regression where verification succeeds and the metadata query returns `NativeCommandError::Io("native command stderr exceeded 1048576-byte limit")`. Assert:

- presence remains `Signed` from successful verification;
- metadata status is `Error` with one typed diagnostic containing the limit reason;
- identifier, Team ID, authorities, signature kind, and runtime remain conservative/empty because `Io` carries no partial bytes;
- both calls were attempted with the existing exact arguments.

Do not duplicate command-layer process tests in `codesign.rs` and do not alter reconciliation precedence.

- [ ] **Step 2: Perform production safety searches**

Run:

```text
rg -n 'Command::new|\.output\(|sh -c|bash -c|panic!|unwrap\(|expect\(' src/macos src/scanner src/report src/main.rs
rg -n 'Evidence|determine_verdict|ScanSummary::from_artifacts' src/macos src/scanner/scan.rs
```

Confirm the only production native invocation remains `Command::new(program).args(arguments)`, `Command::output()` is gone, no shell exists, production recoverable paths contain no panic/unwrap/expect, and signature failures remain isolated from evidence/verdict/summary. The search intentionally sees `#[cfg(test)]` helpers and assertions; identify the test-module boundary and classify matches instead of treating test-only `expect`/`panic` as production violations.

- [ ] **Step 3: Run the complete automated gate**

Run fresh:

```text
cargo fmt --check
YRX_REGENERATE_MODULES_RS=false cargo check --locked --offline
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
YRX_REGENERATE_MODULES_RS=false cargo build --locked --offline
YRX_REGENERATE_MODULES_RS=false cargo clippy --all-targets --all-features --locked --offline -- -D warnings
./scripts/check-all.sh
git diff --check
git status --short
```

Expected: every command exits zero; test count is greater than 129; only the five reviewed module files named in Step 7 are modified.

- [ ] **Step 4: Perform read-only macOS smoke validation**

On macOS, rebuild and run:

```text
./target/debug/af scan ./target/debug/af
./target/debug/af scan /System/Applications/Calculator.app
```

Compare typed results with direct `/usr/bin/codesign --verify --verbose=4` and `/usr/bin/codesign -d --verbose=4` calls. The default 30-second/1-MiB bounds must not change normal host facts. Do not modify either target.

- [ ] **Step 5: Request independent final review**

Review the full diff against the design spec. Require explicit assessment of:

- direct-child exit with open descendant pipes;
- TERM/KILL/reap state and no double wait;
- timeout/output/read-error precedence;
- no unbounded reader joins;
- per-reader allocation cap;
- exact argument/no-shell invariants;
- cfg portability;
- truthful codesign diagnostics and evidence isolation.

Fix findings one at a time with a failing regression and re-review.

- [ ] **Step 6: Re-run the complete gate immediately before commit**

Repeat Step 3 after the final review. Do not rely on delegated or earlier output.

- [ ] **Step 7: Create the one implementation commit**

Stage only reviewed module files:

```text
git add Cargo.toml src/macos/command.rs src/macos/codesign.rs docs/superpowers/specs/2026-08-09-native-command-bounds-design.md docs/superpowers/plans/2026-08-09-native-command-bounds.md
git commit -m "fix(macos): bound native commands"
```

- [ ] **Step 8: Push the completed module branch**

From the hardening worktree:

```text
git status --short --branch
git rev-parse --abbrev-ref HEAD
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
git push -u origin feature/native-command-hardening
git status --short --branch
```

Before pushing, require a clean worktree and exact branch name `feature/native-command-hardening`. Expected afterward: local and remote `feature/native-command-hardening` point to the hardening commit, the worktree is clean, and `feature/cli-skeleton` remains at its completed baseline.
