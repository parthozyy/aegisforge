# Native Command Bounds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound every native codesign invocation by time and per-stream memory while preserving exact arguments, raw successful output, existing error mapping, and nonfatal scan behavior.

**Architecture:** Replace `Command::output()` inside `SystemCommandRunner` with a private, dependency-free supervisor. Two bounded reader threads report structured stdout/stderr outcomes, while the parent polls child state and one monotonic deadline. Unix children run in a new process group; abnormal completion uses fixed TERM/KILL and reader-close grace periods, discards partial output, reaps the direct child, and returns the existing `NativeCommandError::Io` type.

**Tech Stack:** Rust 2024 standard library (`std::process`, `std::thread`, `std::sync::mpsc`, `std::time`), existing Unix `libc` dependency, Cargo locked/offline test gates.

**Commit policy:** The design spec is already committed. Do not commit after individual tasks. After all tasks and reviews pass, create one coherent implementation commit and push the module branch `feature/native-command-hardening`. The completed `feature/cli-skeleton` branch remains unchanged.

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
2. a helper that spawns a second marked-test-executable helper with inherited stdout/stderr and then exits. The descendant helper atomically records its PID, installs the same TERM-recording handler, and deliberately remains alive after TERM. Direct-child exit alone must not be success; the open pipe must reach the shared deadline, group cleanup must run, and `Io` must return promptly. Assert the descendant TERM marker exists and polling `kill(pid, 0)` reaches `ESRCH`. This proves TERM and forced KILL both target the process group after its leader has exited, rather than merely killing/detaching the direct child;
3. a helper that writes more than a small cap to stdout and exits: result must be stdout-limit `Io`, never successful output;
4. the same for stderr;
5. a helper that exits nonzero with bounded separate output: return `NativeCommandOutput` with raw streams and exit code;
6. a direct `/bin/sleep` timeout returns promptly;
7. a test-only supervision seam receiving a synthetic reader error or disconnected outcome channel initiates cleanup and returns `Io`;
8. a test-only post-spawn setup-failure seam terminates and reaps a running child;
9. a cleanup/state seam with an already recorded `ExitStatus` proves neither `wait()` nor direct-child kill is invoked a second time, while process-group cleanup may still target descendants.

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
3. poll `child.try_wait()` only until an exit status has been recorded;
4. return success only when status plus both complete outputs exist;
5. if the deadline is reached first, return timeout failure;
6. sleep for at most the smaller of the poll interval and remaining deadline.

Channel disconnect before both complete outcomes is a reader failure. After cloning one sender into each reader, explicitly drop every parent-held `Sender`; this makes a reader panic/disappearance observable as channel disconnect rather than an artificial timeout. Join reader handles on success only after completion events make the join nonblocking. A join panic becomes `Io` and successful output is discarded.

- [ ] **Step 5: Implement bounded cleanup**

Create a cleanup helper that receives the child, whether its exit was already observed, reader handles, and the primary failure.

On Unix:

- checked-convert `child.id()` to a positive `i32`;
- send `SIGTERM` to the negative PID process group using narrowly scoped `libc::kill` with a SAFETY comment;
- treat `ESRCH` as already gone;
- for at most `termination_grace`, poll the unreaped direct child;
- send `SIGKILL` to the same group after grace (again treating `ESRCH` as benign);
- call `wait()` only when `try_wait()` has not already recorded/reaped the direct child.

On non-Unix, use `Child::kill()` and wait only if not already reaped.

After termination, poll reader `JoinHandle::is_finished()` and drain events for at most `reader_close_grace`. Join only finished handles. Drop/detach an unfinished handle rather than blocking. Preserve the original timeout/output/read/setup reason and append cleanup details if kill, wait, or join fails.

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

- Modify: `src/macos/codesign.rs` (focused bounded-runner error regression only)
- Verify: `src/macos/command.rs`
- Verify: `docs/superpowers/specs/2026-08-09-native-command-bounds-design.md`
- Verify: `docs/superpowers/plans/2026-08-09-native-command-bounds.md`

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

Expected: every command exits zero; test count is greater than 129; only the hardening implementation and plan are uncommitted.

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
git add src/macos/command.rs src/macos/codesign.rs docs/superpowers/plans/2026-08-09-native-command-bounds.md
git commit -m "fix(macos): bound native commands"
```

Omit `src/macos/codesign.rs` if no integration change was necessary. The already committed design spec must not be recommitted.

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
