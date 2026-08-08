# macOS Code-Signature Inspection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add read-only, structured code-signature inspection for recognized Mach-O files and `.app` bundle roots without changing security evidence or verdicts.

**Architecture:** A reusable native-command runner invokes absolute `/usr/bin/codesign` commands with explicit arguments and separate stdout/stderr capture. A focused macOS parser reconciles verification and metadata queries into typed signature facts. Discovery records app bundle roots while retaining recursive file scanning, scanner orchestration appends a uniform signature collection, and the text reporter renders the new context without changing artifact summaries.

**Tech Stack:** Rust 2024, standard-library `std::process::Command`, existing structured scan model, in-source unit tests, synthetic codesign output fixtures, read-only macOS smoke validation.

**Specification:** `docs/superpowers/specs/2026-08-08-macos-code-signature-inspection-design.md`

**Commit policy:** Preserve the handoff's module boundary. Do not commit individual tasks. After every task's focused and full tests pass, create one final commit named `feat(macos): inspect code signatures`, fast-forward `feature/cli-skeleton`, and push that branch.

---

## File Structure

- Create `src/macos/mod.rs`: initially exports the code-signature module; Task 2 adds the command module once its file exists.
- Create `src/macos/command.rs`: command request/output/error types, runner trait, and safe system implementation.
- Create `src/macos/codesign.rs`: signature domain types, codesign parser/reconciliation, target validation, platform behavior, and inspector trait/implementation.
- Modify `src/main.rs`: declare the `macos` module and update test fixtures for the extended scan result.
- Modify `src/scanner/result.rs`: add `CodeSignature` diagnostic category and the top-level signature collection.
- Modify `src/scanner/discovery.rs`: discover sorted `.app` roots without stopping recursive traversal.
- Modify `src/scanner/scan.rs`: inject a signature inspector, inspect Mach-O files and bundles, sort results, and preserve existing scan semantics.
- Modify `src/report/text.rs`: render typed file and bundle signature sections and their diagnostics with existing safe escaping.

No dependency or CLI-argument change is planned.

---

### Task 1: Add the Typed Code-Signature Result Model

**Files:**

- Create: `src/macos/mod.rs`
- Create: `src/macos/codesign.rs`
- Modify: `src/main.rs`
- Modify: `src/scanner/result.rs`
- Test: `src/macos/codesign.rs`
- Test: `src/scanner/result.rs`

- [ ] **Step 1: Write failing model tests**

Create `src/macos/mod.rs` containing `pub mod codesign;`, create `src/macos/codesign.rs`, and declare `mod macos;` in `src/main.rs` before the RED run. In `src/macos/codesign.rs`, define tests before production types. Cover stable labels and complete construction:

```rust
#[test]
fn signature_status_labels_are_stable() {
    assert_eq!(SignaturePresence::Signed.as_str(), "SIGNED");
    assert_eq!(SignaturePresence::Unsigned.as_str(), "UNSIGNED");
    assert_eq!(SignaturePresence::Unknown.as_str(), "UNKNOWN");
    assert_eq!(NativeCheckStatus::Passed.as_str(), "PASSED");
    assert_eq!(NativeCheckStatus::Failed.as_str(), "FAILED");
    assert_eq!(NativeCheckStatus::NotApplicable.as_str(), "NOT_APPLICABLE");
    assert_eq!(NativeCheckStatus::Unavailable.as_str(), "UNAVAILABLE");
    assert_eq!(NativeCheckStatus::Error.as_str(), "ERROR");
}

#[test]
fn code_signature_inspection_keeps_file_and_bundle_targets_distinct() {
    let file = CodeSignatureInspection::unknown(
        PathBuf::from("sample"),
        CodeSignatureTargetKind::MachOFile,
    );
    let bundle = CodeSignatureInspection::unknown(
        PathBuf::from("Example.app"),
        CodeSignatureTargetKind::ApplicationBundle,
    );

    assert_ne!(file.target_kind, bundle.target_kind);
}
```

In `src/scanner/result.rs`, update a `ScanResult` fixture test to require `code_signatures: Vec::new()` and assert that `DiagnosticKind::CodeSignature` is a distinct typed category.

- [ ] **Step 2: Run tests to verify RED**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::codesign::tests -- --nocapture
```

Expected: the newly registered test module is compiled and fails because the signature types do not exist. Zero matching tests is not an acceptable RED result.

- [ ] **Step 3: Implement the minimal domain model**

In `src/macos/codesign.rs`, add:

```rust
use std::path::PathBuf;

use crate::scanner::result::ScanDiagnostic;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CodeSignatureTargetKind {
    MachOFile,
    ApplicationBundle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignaturePresence {
    Signed,
    Unsigned,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeCheckStatus {
    Passed,
    Failed,
    NotApplicable,
    Unavailable,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    AdHoc,
    CertificateBacked,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignatureInspection {
    pub target: PathBuf,
    pub target_kind: CodeSignatureTargetKind,
    pub presence: SignaturePresence,
    pub verification_status: NativeCheckStatus,
    pub metadata_status: NativeCheckStatus,
    pub identifier: Option<String>,
    pub team_identifier: Option<String>,
    pub authorities: Vec<String>,
    pub signature_kind: SignatureKind,
    pub hardened_runtime: Option<bool>,
    pub verification_detail: Option<String>,
    pub diagnostics: Vec<ScanDiagnostic>,
}
```

Implement stable `as_str()` methods and an `unknown` constructor that sets both query statuses to `Error`, optional fields to `None`, authority/diagnostic vectors empty, and signature kind to `Unknown`.

Extend `DiagnosticKind` with `CodeSignature` and `ScanResult` with:

```rust
pub code_signatures: Vec<CodeSignatureInspection>,
```

Update every existing `ScanResult` test fixture with an empty vector. Do not change summary logic or artifact results.

- [ ] **Step 4: Run focused and full tests to verify GREEN**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::codesign::tests
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
cargo fmt --all -- --check
git diff --check
```

Expected: model tests and all existing 68 tests pass; formatting and diff checks pass.

---

### Task 2: Build the Safe Native-Command Runner

**Files:**

- Create: `src/macos/command.rs`
- Modify: `src/macos/mod.rs`
- Test: `src/macos/command.rs`

- [ ] **Step 1: Write failing runner tests**

Create `src/macos/command.rs` with the failing tests and add `pub mod command;` to `src/macos/mod.rs` before the RED run. Add tests for the data model and, on macOS, the real system runner:

```rust
#[cfg(target_os = "macos")]
#[test]
fn runner_captures_nonzero_status_and_stderr_without_a_shell() {
    let runner = SystemCommandRunner;
    let output = runner
        .run(
            Path::new("/usr/bin/codesign"),
            &[OsString::from("--verify"), OsString::from("definitely-missing")],
        )
        .expect("codesign should execute");

    assert!(!output.success);
    assert_ne!(output.exit_code, Some(0));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn not_found_is_classified_as_unavailable() {
    let error = classify_spawn_error(io::Error::from(io::ErrorKind::NotFound));
    assert!(matches!(error, NativeCommandError::Unavailable(_)));
}

#[test]
fn other_spawn_errors_are_classified_as_errors() {
    let error = classify_spawn_error(io::Error::from(io::ErrorKind::PermissionDenied));
    assert!(matches!(error, NativeCommandError::Io(_)));
}
```

- [ ] **Step 2: Run focused tests to verify RED**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::command::tests -- --nocapture
```

Expected: the newly registered command test module is compiled and fails because runner types and error classification are missing. Zero matching tests is not an acceptable RED result.

- [ ] **Step 3: Implement the runner**

Implement:

```rust
use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCommandOutput {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeCommandError {
    Unavailable(String),
    Io(String),
}

pub trait NativeCommandRunner {
    fn run(
        &self,
        program: &Path,
        arguments: &[OsString],
    ) -> Result<NativeCommandOutput, NativeCommandError>;
}

pub struct SystemCommandRunner;
```

`SystemCommandRunner::run` must call `Command::new(program).args(arguments).stdin(Stdio::null()).output()`. Convert the process output without merging streams. Map `io::ErrorKind::NotFound` to `Unavailable`; map every other I/O error to `Io`. Do not add environment mutation, current-directory mutation, shell support, or string command parsing.

- [ ] **Step 4: Run focused and full tests**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::command::tests
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
cargo fmt --all -- --check
git diff --check
```

Expected: runner tests pass and the existing suite remains green.

---

### Task 3: Parse and Reconcile codesign Results

**Files:**

- Modify: `src/macos/codesign.rs`
- Test: `src/macos/codesign.rs`

- [ ] **Step 1: Add failing synthetic-output parser tests**

Use helper constructors for successful/nonzero command output, a queue-backed fake runner, and an RAII temporary directory. Every fake-runner inspection test must create an actual temporary regular file for `MachOFile` or an actual temporary `.app` directory for `ApplicationBundle`, so target validation succeeds before query behavior is exercised. Add separate tests for:

1. valid ad-hoc output:

```text
Identifier=af-e1763799a2d7044d
CodeDirectory v=20400 flags=0x20002(adhoc,linker-signed)
Signature=adhoc
TeamIdentifier=not set
```

Expected: `Signed`, verification and metadata `Passed`, `AdHoc`, identifier present, no Team ID, runtime `Some(false)`.

2. certificate-backed output with CRLF, reordered `Authority=` records, one duplicate, `Authority=(unavailable)`, a real Team ID, `Signature size=...`, and `flags=...(runtime)`.

Expected: stable authority-chain order, unavailable/duplicate records removed, `CertificateBacked`, runtime `Some(true)`.

3. explicit unsigned output from both queries.

Expected: `Unsigned`, both statuses `NotApplicable`, no signature kind or identity claims.

4. invalid verification plus successful signed metadata.

Expected: `Signed`, verification `Failed`, metadata `Passed`, parsed identity retained, verification detail retained.

5. successful verification plus metadata failure.

Expected: `Signed`, verification `Passed`, metadata `Failed`, no invented optional metadata, one diagnostic.

6. contradictory signed success plus explicit unsigned output.

Expected: `Unknown`, identity/runtime cleared, per-query statuses preserved, disagreement diagnostic.

7. simultaneous ad-hoc and certificate markers.

Expected: signed presence, `Unknown` signature kind, conflict diagnostic.

8. verify runner unavailable while display runner returns an I/O error.

Expected: `Unknown`, verification `Unavailable`, metadata `Error`, diagnostics for both operations.

9. exact invocation arguments with a real temporary bundle directory named `name with spaces;$(touch nope).app`.

Expected calls:

```text
program: /usr/bin/codesign
args: [--verify, --verbose=4, <one path argument>]
program: /usr/bin/codesign
args: [-d, --verbose=4, <one path argument>]
```

- [ ] **Step 2: Run parser tests to verify RED**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::codesign::tests -- --nocapture
```

Expected: new parser/orchestration tests fail because inspection is not implemented.

- [ ] **Step 3: Implement query parsing**

Add private types such as:

```rust
struct ParsedMetadata {
    identifier: Option<String>,
    team_identifier: Option<String>,
    authorities: Vec<String>,
    explicit_adhoc: bool,
    certificate_marker: bool,
    hardened_runtime: Option<bool>,
}

struct QueryResult {
    status: NativeCheckStatus,
    positive_signed: bool,
    explicit_unsigned: bool,
    detail: Option<String>,
    metadata: ParsedMetadata,
    diagnostic: Option<ScanDiagnostic>,
}
```

Parse both byte streams line-by-line with `String::from_utf8_lossy`, trim only record separators/whitespace, and match exact key prefixes. Stable de-duplication of authorities must preserve the first occurrence. Ignore unknown records.

For a flags line, parse only the parenthesized comma-separated token list. Match the complete token `adhoc` and complete token `runtime`; do not use broad substring checks.

- [ ] **Step 4: Implement two-query orchestration and reconciliation**

Add a `CodeSignatureInspector` trait:

```rust
pub trait CodeSignatureInspector {
    fn inspect(
        &self,
        target: &Path,
        target_kind: CodeSignatureTargetKind,
    ) -> CodeSignatureInspection;
}
```

Implement `CodesignInspector<R: NativeCommandRunner>` with `/usr/bin/codesign` and the exact two argument arrays. Attempt both calls regardless of the first result. Provide the concrete constructor:

```rust
impl<R: NativeCommandRunner> CodesignInspector<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}
```

Implement the specification's precedence in one `reconcile` function:

- positive-signed plus explicit-unsigned conflict clears all identity/runtime fields;
- explicit unsigned without a positive signed result yields unsigned;
- positive signed yields signed;
- otherwise unknown;
- signature kind is calculated only for reconciled signed presence;
- query statuses remain independent;
- invalid verification never becomes an operational error or evidence.

Sort diagnostics deterministically by message after construction.

- [ ] **Step 5: Implement target validation and platform factory**

Before commands on macOS, use `symlink_metadata`:

- reject symlinks;
- require a regular file for `MachOFile`;
- require a real directory whose extension is case-insensitive `.app` for `ApplicationBundle`.

A validation failure returns `Unknown`, both statuses `Error`, cleared metadata, and one `CodeSignature` diagnostic. No command runs.

Expose a small production factory/type:

```rust
#[cfg(target_os = "macos")]
pub type PlatformCodeSignatureInspector = CodesignInspector<SystemCommandRunner>;

#[cfg(not(target_os = "macos"))]
pub struct PlatformCodeSignatureInspector;

#[cfg(target_os = "macos")]
pub fn platform_code_signature_inspector() -> PlatformCodeSignatureInspector {
    CodesignInspector::new(SystemCommandRunner)
}

#[cfg(not(target_os = "macos"))]
pub fn platform_code_signature_inspector() -> PlatformCodeSignatureInspector {
    PlatformCodeSignatureInspector
}
```

The non-macOS implementation returns `Unknown` with both statuses `Unavailable` and a platform-unavailable diagnostic, without invoking a process.

Add a `#[cfg(not(target_os = "macos"))]` test that constructs the platform inspector, passes a target path, and asserts `Unknown`, two `Unavailable` statuses, and the platform diagnostic. Because the non-macOS type owns no command runner and the test does not create an executable seam, this also proves no process is attempted.

- [ ] **Step 6: Run focused and full tests**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::codesign::tests
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
cargo fmt --all -- --check
YRX_REGENERATE_MODULES_RS=false cargo clippy --all-targets --locked --offline -- -D warnings
git diff --check
```

Expected: all parser/reconciliation tests pass, the full suite remains green, and no warning is introduced.

---

### Task 4: Discover Application Bundle Roots Without Hiding Contents

**Files:**

- Modify: `src/scanner/discovery.rs`
- Test: `src/scanner/discovery.rs`

- [ ] **Step 1: Add failing bundle-discovery tests**

Add tests that create:

```text
Root.app/
  Contents/MacOS/main
  Contents/Resources/data
nested/Helper.APP/
  Contents/MacOS/helper
ordinary/
  file.txt
```

Assert:

- direct top-level `Root.app` is included once in `app_bundles`;
- nested `Helper.APP` is included case-insensitively;
- bundle paths are sorted and de-duplicated;
- all files inside both bundles remain in `files`;
- an ordinary directory is not a bundle target;
- a symlink ending in `.app` is not included and retains the existing skip diagnostic.

Update existing `DiscoveryResult` literals in scanner tests to require `app_bundles: Vec::new()`.

- [ ] **Step 2: Run discovery tests to verify RED**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline scanner::discovery::tests -- --nocapture
```

Expected: compilation/assertion failure because discovery has no bundle collection.

- [ ] **Step 3: Implement bundle collection**

Extend:

```rust
pub struct DiscoveryResult {
    pub files: Vec<PathBuf>,
    pub app_bundles: Vec<PathBuf>,
    pub diagnostics: Vec<ScanDiagnostic>,
}
```

Add:

```rust
fn is_application_bundle(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("app"))
}
```

When the validated top-level target is a directory, add it if applicable before recursion. When a real nested directory is encountered, add it before recursively traversing it. Never add symlinks. Sort and de-duplicate both `files` and `app_bundles` before returning.

- [ ] **Step 4: Run focused and full tests**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline scanner::discovery::tests
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
cargo fmt --all -- --check
git diff --check
```

Expected: bundle discovery and all prior tests pass.

---

### Task 5: Integrate Signature Inspection Into Scan Orchestration

**Files:**

- Modify: `src/scanner/scan.rs`
- Modify: `src/scanner/result.rs`
- Test: `src/scanner/scan.rs`

- [ ] **Step 1: Write failing orchestration tests with a fake inspector**

Implement a test-only fake `CodeSignatureInspector` that records `(PathBuf, CodeSignatureTargetKind)` calls in a `RefCell` and returns queued inspections.

Add tests proving:

- a content-classified Mach-O file invokes inspection exactly once as `MachOFile`;
- a non-Mach-O file never invokes code signing;
- each discovered `.app` root invokes inspection exactly once as `ApplicationBundle` while its files still produce artifact results;
- the inspector invocation order is all sorted Mach-O targets first, followed by all sorted bundle targets;
- reported signature results are sorted by path then kind even though invocation remains grouped;
- an unavailable/failed inspection is retained, its diagnostics are retained inside that inspection, and later targets still run;
- code-signature results do not change evidence, verdict, or artifact summary counts;
- malformed Mach-O parser errors do not suppress code-signature inspection when content classification is Mach-O;
- the static scan phase returns all artifact results and pending native targets without accepting or invoking a signature inspector;
- the native enrichment phase accepts only a completed static-phase value and then invokes the fake inspector for every pending target.

- [ ] **Step 2: Run scanner tests to verify RED**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline scanner::scan::tests -- --nocapture
```

Expected: compilation/assertion failure because scan orchestration does not accept or produce signature inspections.

- [ ] **Step 3: Split static analysis from native enrichment**

Introduce a private phase-boundary type and helper:

```rust
struct StaticScanOutput {
    artifacts: Vec<ArtifactResult>,
    diagnostics: Vec<ScanDiagnostic>,
    failed: usize,
    macho_signature_targets: Vec<PathBuf>,
    bundle_signature_targets: Vec<PathBuf>,
}

fn assemble_static_scan(
    discovery: DiscoveryResult,
    yara_engine: &YaraEngine,
) -> StaticScanOutput
```

`assemble_static_scan` must have no inspector parameter and no access to the native command module. It completes all artifact results and collects pending Mach-O plus bundle targets. Add:

```rust
fn inspect_signature_targets(
    static_output: &StaticScanOutput,
    inspector: &dyn CodeSignatureInspector,
) -> Vec<CodeSignatureInspection>
```

The final `assemble_scan_result` first obtains a complete `StaticScanOutput`, then passes that completed value to `inspect_signature_targets`, and finally constructs `ScanResult`. This type/API boundary—not a test-only hook—enforces that native inspection cannot begin inside the artifact loop. Separate target vectors preserve the required invocation order without depending on lexical paths.

Update the existing test helper to accept a fake inspector. In `scan_path`, call `platform_code_signature_inspector()` once per scan and pass the returned inspector into final assembly.

- [ ] **Step 4: Inspect applicable file and bundle targets**

Inside `assemble_static_scan`, during the existing one-artifact-at-a-time loop:

- after safe snapshot classification, record `artifact.path.clone()` in `macho_signature_targets` only when `artifact.file_type == ArtifactType::MachO`;
- keep Mach-O header/dependency failures independent;
- complete all existing structural analysis, YARA, evidence, verdict, and `ArtifactResult` construction without invoking the signature inspector.

Only after the entire artifact loop is complete, sort/de-duplicate the Mach-O target vector and separately sort/de-duplicate `discovery.app_bundles` into `bundle_signature_targets`. Return both groups in `StaticScanOutput` without invoking the inspector. `inspect_signature_targets` must invoke every Mach-O path first as `MachOFile`, then every bundle path as `ApplicationBundle`. Only after invocation does it sort the returned signature records by `target`, then `target_kind`, for deterministic reporting.

Populate `ScanResult.code_signatures`. Keep `ScanSummary::from_artifacts(failed, &artifacts)` unchanged so bundles do not affect artifact counts.

Add `DiagnosticKind::CodeSignature` to the existing diagnostic rank function without moving signature diagnostics into evidence.

- [ ] **Step 5: Run focused and full tests**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline scanner::scan::tests
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
cargo fmt --all -- --check
YRX_REGENERATE_MODULES_RS=false cargo clippy --all-targets --locked --offline -- -D warnings
git diff --check
```

Expected: all orchestration tests pass; artifact counts/verdicts remain unchanged; no warning is introduced.

---

### Task 6: Render Terminal-Safe Signature Sections

**Files:**

- Modify: `src/report/text.rs`
- Modify: `src/main.rs`
- Test: `src/report/text.rs`
- Test: `src/main.rs`

- [ ] **Step 1: Add failing reporter tests**

Extend report fixtures with representative Mach-O and application-bundle inspections. Assert exact section headings and key lines:

```text
Mach-O code signatures:
  <path> | presence: SIGNED | verification: PASSED | metadata: PASSED | kind: AD_HOC
  Identifier: ...
  Team ID: not available
  Hardened runtime: no

Application bundle signatures:
  <path> | presence: SIGNED | verification: FAILED | metadata: PASSED | kind: CERTIFICATE_BACKED
```

Also assert:

- authority order is preserved;
- unknown optional values render conservatively;
- verification detail is rendered only when present;
- signature diagnostics go to stderr once, not stdout;
- paths and every metadata/detail string escape newline, bidi, line-separator, and other existing unsafe characters;
- summary text is byte-for-byte unchanged;
- empty signature collections add no empty headings;
- writer/flush failures still propagate.

- [ ] **Step 2: Run reporter tests to verify RED**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline report::text::tests -- --nocapture
```

Expected: assertions fail because signature sections are not rendered.

- [ ] **Step 3: Implement rendering**

Add a small `write_signature_section`/`write_signature` helper rather than expanding `write_text` with duplicated branches. Filter the already sorted collection by target kind and emit a heading only when at least one matching entry exists.

Use existing `escape_path` for target paths and `escape_line` for identifier, Team ID, authorities, and verification detail. Render:

- optional identifier/Team ID as `not available`;
- hardened runtime as `yes`, `no`, or `unknown`;
- signature kind/status through stable `as_str()` methods.

After scan-level and artifact diagnostics, iterate signature diagnostics exactly once and send them through `write_diagnostic` to stderr.

Update `main.rs` test fixtures with `code_signatures: Vec::new()` if not already covered by Task 1.

- [ ] **Step 4: Run focused and full tests**

Run:

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline report::text::tests
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
cargo fmt --all -- --check
YRX_REGENERATE_MODULES_RS=false cargo clippy --all-targets --locked --offline -- -D warnings
git diff --check
```

Expected: reporter tests pass, output remains terminal-safe, and all previous tests remain green.

---

### Task 7: Complete macOS Validation, Review, and the Module Commit

**Files:**

- Modify only if a verified defect is found in Tasks 1-6.
- Verify: all Phase 2 files and existing regression script.

- [ ] **Step 1: Review production safety invariants**

Use targeted searches and diff inspection:

```text
rg -n 'Command::new|sh -c|bash -c|println!|eprintln!|panic!|unwrap\(|expect\(' src/macos src/scanner src/report src/main.rs
git diff --check
git status --short
```

Confirm:

- production native invocation exists only in `src/macos/command.rs`;
- the executable is `/usr/bin/codesign` and paths remain distinct `OsString` arguments;
- no scanned object is executed or modified;
- no code-signature result creates `Evidence` or changes `Verdict`;
- nonfatal signature failures continue;
- app bundle contents remain scanned;
- no Homebrew/V0.2/entitlement/Gatekeeper work is present;
- production recoverable paths contain no panic/unwrap/expect.

- [ ] **Step 2: Run the complete automated gate**

Run fresh and read every exit status:

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

Expected: all commands exit zero; test count is greater than 68; Clippy reports no warnings; only Phase 2 implementation files and this plan are changed.

- [ ] **Step 3: Perform read-only macOS smoke validation**

On macOS only, run the built CLI against:

```text
./target/debug/af scan ./target/debug/af
./target/debug/af scan /System/Applications/Calculator.app
```

Also invoke `/usr/bin/codesign --verify --verbose=4` and `/usr/bin/codesign -d --verbose=4` directly on the same targets to compare the typed output to host facts. Do not require Calculator verification to pass; record its actual status. Do not modify either target.

Use the automated fake-runner unsigned-Mach-O test as the required unsigned validation. Only use a real unsigned Mach-O fixture if a disposable harmless copy already exists or can be prepared without modifying user/system artifacts.

- [ ] **Step 4: Request independent code review**

Dispatch a fresh reviewer with the design spec, this plan, exact diff, and verification output. Require review of status reconciliation, command safety, target races, bundle recursion, diagnostic/evidence separation, deterministic reporting, and scope.

If issues are found, apply them one at a time with a failing regression test, re-run focused/full gates, and request re-review.

- [ ] **Step 5: Re-run final verification immediately before commit**

Repeat the complete automated gate from Step 2 after the final review fix. Do not rely on earlier or delegated test output.

- [ ] **Step 6: Create the one coherent module commit**

Stage only reviewed Phase 2 files:

```text
git add src/macos/mod.rs src/macos/command.rs src/macos/codesign.rs src/main.rs src/scanner/result.rs src/scanner/discovery.rs src/scanner/scan.rs src/report/text.rs docs/superpowers/plans/2026-08-08-macos-code-signature-inspection.md
git commit -m "feat(macos): inspect code signatures"
```

Expected: one implementation commit with no unrelated changes. The already committed design spec must not be recommitted.

- [ ] **Step 7: Fast-forward and push the requested branch**

From the primary `feature/cli-skeleton` worktree:

```text
git merge --ff-only codex/macos-code-signing
git push origin feature/cli-skeleton
git status --short --branch
```

Expected: `feature/cli-skeleton` and `origin/feature/cli-skeleton` point to the new module commit and the worktree is clean.
