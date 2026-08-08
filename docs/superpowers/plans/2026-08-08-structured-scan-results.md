# Structured Scan Results Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Return complete structured scan results, preserve partial detector findings, and render the current text interface outside scanner orchestration.

**Architecture:** `scanner::scan` will assemble typed `ScanResult` values from discovery, metadata, Mach-O, and detector outcomes. `detection::analyzer` will return partial evidence plus operational diagnostics instead of failing the whole artifact. `report::text` will render results through injected writers, leaving `main` responsible only for CLI dispatch and fatal exit handling.

**Tech Stack:** Rust 2024, standard library I/O/filesystem APIs, existing Clap/Goblin/SHA-256/YARA-X dependencies, in-source Rust unit tests, Bash regression gate.

---

## File Structure

- Create `src/scanner/result.rs`: result, summary, diagnostic, and detector-status domain types.
- Create `src/report/mod.rs`: report module boundary.
- Create `src/report/text.rs`: deterministic human-readable renderer with injected stdout/stderr writers.
- Modify `src/scanner/mod.rs`: export the result module.
- Modify `src/scanner/artifact.rs`: derive traits required by structured result assertions.
- Modify `src/scanner/file_type.rs`: derive value traits required by artifact equality.
- Modify `src/scanner/path.rs`: derive value traits and provide stable text for target type.
- Modify `src/scanner/macho.rs`: derive traits required by result assertions.
- Modify `src/scanner/macho_dependencies.rs`: derive traits required by result assertions.
- Modify `src/detection/evidence.rs`: make evidence cloneable and comparable.
- Modify `src/scanner/discovery.rs`: return deterministic files and typed diagnostics instead of printing.
- Modify `src/detection/analyzer.rs`: return partial evidence, statuses, and YARA diagnostics.
- Modify `src/scanner/scan.rs`: assemble and return `ScanResult` without presentation calls.
- Modify `src/main.rs`: invoke scan and text reporting, mapping fatal failures to exit code 1.

## Commit Policy

Tasks 1–5 form one coherent Phase 1 module. Run targeted tests after every red-green cycle, but do not commit partially integrated states. After Task 6 passes the complete repository gate, create and push exactly one implementation commit:

```text
refactor(scanner): introduce structured scan results
```

### Task 1: Structured Result Domain Model

**Files:**
- Create: `src/scanner/result.rs`
- Modify: `src/scanner/mod.rs`
- Modify: `src/scanner/artifact.rs`
- Modify: `src/scanner/file_type.rs`
- Modify: `src/scanner/path.rs`
- Modify: `src/scanner/macho.rs`
- Modify: `src/scanner/macho_dependencies.rs`
- Modify: `src/detection/evidence.rs`
- Test: `src/scanner/result.rs`

- [ ] **Step 1: Create the exported test module and write failing summary/status tests**

Create `src/scanner/result.rs`, export it with `pub mod result;` in `src/scanner/mod.rs`, and add tests that build three artifact results with `Unknown`, `Suspicious`, and `Malicious` verdicts, then assert the summary invariants. The file deliberately refers to the not-yet-defined production types so the RED command must compile this test module and fail:

```rust
#[test]
fn summary_counts_analyzed_failed_and_verdicts() {
    let artifacts = vec![
        artifact_result("unknown", Verdict::Unknown),
        artifact_result("suspicious", Verdict::Suspicious),
        artifact_result("malicious", Verdict::Malicious),
    ];

    let summary = ScanSummary::from_artifacts(4, &artifacts);

    assert_eq!(summary.discovered, 4);
    assert_eq!(summary.analyzed, 3);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.unknown, 1);
    assert_eq!(summary.suspicious, 1);
    assert_eq!(summary.malicious, 1);
}

#[test]
fn detector_status_records_explicit_outcome() {
    let status = DetectorStatus::new(Detector::Yara, DetectorOutcome::Failed);

    assert_eq!(status.detector, Detector::Yara);
    assert_eq!(status.outcome, DetectorOutcome::Failed);
}
```

The local `artifact_result` test helper constructs a minimal `ArtifactResult` with no Mach-O data, evidence, diagnostics, or statuses.

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
cargo test scanner::result::tests -- --nocapture
```

Expected: compilation fails inside the exported `scanner::result::tests` module because `ScanSummary` and the related production types are not defined yet.

- [ ] **Step 3: Add minimal result types and required derives**

Create these public types in `src/scanner/result.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticKind {
    Discovery,
    Metadata,
    MachOHeader,
    MachODependencies,
    Yara,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanDiagnostic {
    pub kind: DiagnosticKind,
    pub path: Option<PathBuf>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detector {
    FileTypeMismatch,
    MachOHeader,
    MachODependencies,
    RiskyRpath,
    Yara,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorOutcome {
    Completed,
    Skipped,
    NotApplicable,
    Unavailable,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorStatus {
    pub detector: Detector,
    pub outcome: DetectorOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactResult {
    pub artifact: Artifact,
    pub macho: Option<MachOInfo>,
    pub macho_dependencies: Option<MachODependencies>,
    pub evidence: Vec<Evidence>,
    pub verdict: Verdict,
    pub detector_statuses: Vec<DetectorStatus>,
    pub diagnostics: Vec<ScanDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSummary {
    pub discovered: usize,
    pub analyzed: usize,
    pub failed: usize,
    pub unknown: usize,
    pub suspicious: usize,
    pub malicious: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub target: PathBuf,
    pub target_type: PathType,
    pub artifacts: Vec<ArtifactResult>,
    pub diagnostics: Vec<ScanDiagnostic>,
    pub summary: ScanSummary,
}
```

Add small `new` constructors for diagnostics/statuses and implement `ScanSummary::from_artifacts(discovered, artifacts)`. Count verdicts with one pass and compute `failed` as `discovered.saturating_sub(analyzed)`.

Derive `Clone`, `PartialEq`, and `Eq` on the owned nested types. Derive `Copy` only for value enums. Export `pub mod result;` from `src/scanner/mod.rs`.

- [ ] **Step 4: Run the focused test and verify GREEN**

Run:

```bash
cargo test scanner::result::tests -- --nocapture
```

Expected: both new result-model tests pass.

- [ ] **Step 5: Run the existing unit suite**

Run:

```bash
cargo test
```

Expected: all existing 36 tests plus the new result tests pass.

### Task 2: Deterministic Discovery With Diagnostics

**Files:**
- Modify: `src/scanner/discovery.rs`
- Test: `src/scanner/discovery.rs`

- [ ] **Step 1: Write failing discovery behavior tests**

Add a test-only RAII temporary-directory helper using `std::env::temp_dir`, process ID, and an atomic counter. Its `Drop` implementation removes only the unique directory it created.

Add these tests:

```rust
#[test]
fn directory_results_are_sorted() {
    let fixture = TestDirectory::new();
    fixture.write("z.txt", b"z");
    fixture.write("nested/b.txt", b"b");
    fixture.write("a.txt", b"a");

    let result = discover_files_with_diagnostics(fixture.path()).unwrap();
    let relative = result.relative_paths(fixture.path());

    assert_eq!(relative, vec!["a.txt", "nested/b.txt", "z.txt"]);
}

#[cfg(unix)]
#[test]
fn nested_symlink_is_skipped_and_diagnosed() {
    let fixture = TestDirectory::new();
    fixture.write("real.txt", b"safe");
    std::os::unix::fs::symlink(
        fixture.path().join("real.txt"),
        fixture.path().join("link.txt"),
    )
    .unwrap();

    let result = discover_files_with_diagnostics(fixture.path()).unwrap();

    assert_eq!(result.files, vec![fixture.path().join("real.txt")]);
    assert!(result.diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == DiagnosticKind::Discovery
            && diagnostic.path.as_deref() == Some(fixture.path().join("link.txt").as_path())
    }));
}
```

Keep or add a direct-symlink rejection test so the top-level fatal behavior cannot regress.

On Unix, also add a failing unreadable-directory diagnostic test. Create a nested directory, install an RAII permissions guard that always restores its original mode, set the nested directory mode to `0o000`, call `discover_files_with_diagnostics`, and assert that a `Discovery` diagnostic names the unreadable directory. The test must first confirm that `fs::read_dir` returns `PermissionDenied`; if the platform can bypass the permissions, return early with a documented skip because the condition cannot be simulated reliably. Entry-level read/type failures use the same production diagnostic helper and do not need an OS-race test.

- [ ] **Step 2: Run discovery tests and verify RED**

Run:

```bash
cargo test scanner::discovery::tests -- --nocapture
```

Expected: compilation fails because discovery still returns `Vec<PathBuf>` and prints warnings.

- [ ] **Step 3: Return a typed discovery result**

Add:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryResult {
    pub files: Vec<PathBuf>,
    pub diagnostics: Vec<ScanDiagnostic>,
}
```

Add `discover_files_with_diagnostics` returning `Result<DiscoveryResult, String>`. Pass a diagnostics vector through recursion. Replace internal warning branches with `ScanDiagnostic::new(DiagnosticKind::Discovery, path, message)`. Record skipped symlinks as diagnostics. Sort `files` before returning.

Keep `discover_files` temporarily as a compatibility adapter for the existing orchestrator: call the new function, render its diagnostics with the current warning wording, and return only its files. Task 4 removes this adapter after the scanner consumes structured discovery directly. This keeps the crate green without implementing Task 4 behavior before its failing tests.

Top-level `symlink_metadata` errors, top-level symlinks, and unsupported top-level objects remain `Err`.

- [ ] **Step 4: Run discovery tests and verify GREEN**

Run:

```bash
cargo test scanner::discovery::tests -- --nocapture
```

Expected: sorted-order, symlink diagnostic, unreadable-directory diagnostic, and direct-symlink tests pass.

- [ ] **Step 5: Run the full unit suite**

Run:

```bash
cargo test
```

Expected: all tests pass through the temporary compatibility adapter; do not change `scanner::scan` yet.

### Task 3: Preserve Partial Detector Results

**Files:**
- Modify: `src/detection/analyzer.rs`
- Test: `src/detection/analyzer.rs`

- [ ] **Step 1: Write a failing regression test for YARA failure**

Define `MachODependencyContext::{NotApplicable, Available, Failed}` and `AnalysisResult` as the desired analyzer API in the test. Use a harmless in-memory YARA rule and an `Artifact` whose path does not exist but whose `.jpg` extension and Mach-O content type produce mismatch evidence:

```rust
#[test]
fn yara_failure_preserves_completed_detector_evidence() {
    let engine = YaraEngine::from_source(TEST_RULE).unwrap();
    let artifact = artifact_at_missing_path("missing.jpg", ArtifactType::MachO);

    let result = analyze_artifact_result(
        &artifact,
        &engine,
        MachODependencyContext::Failed,
    );

    assert!(result.evidence.iter().any(|finding| {
        finding.kind == EvidenceKind::FileTypeMismatch
    }));
    assert!(result.detector_statuses.contains(&DetectorStatus::new(
        Detector::Yara,
        DetectorOutcome::Failed,
    )));
    assert!(result.detector_statuses.contains(&DetectorStatus::new(
        Detector::RiskyRpath,
        DetectorOutcome::Skipped,
    )));
    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].kind, DiagnosticKind::Yara);
}
```

Add companion tests asserting `RiskyRpath` is `NotApplicable` for non-Mach-O context and `Completed` when dependencies are available but emit no evidence.

- [ ] **Step 2: Run analyzer tests and verify RED**

Run:

```bash
cargo test detection::analyzer::tests -- --nocapture
```

Expected: compilation fails because the analyzer returns `Result<Vec<Evidence>, String>` and has no dependency context or statuses.

- [ ] **Step 3: Implement the minimal structured analyzer result**

Add:

```rust
pub enum MachODependencyContext<'a> {
    NotApplicable,
    Available(&'a MachODependencies),
    Failed,
}

pub struct AnalysisResult {
    pub evidence: Vec<Evidence>,
    pub detector_statuses: Vec<DetectorStatus>,
    pub diagnostics: Vec<ScanDiagnostic>,
}
```

Add `analyze_artifact_result`; it must:

1. always run mismatch detection and record `Completed`;
2. run RPATH risk detection for `Available` and record `Completed`;
3. record `NotApplicable` or `Skipped` for the other dependency contexts;
4. run YARA last;
5. turn YARA matches into evidence and record `Completed`;
6. turn a YARA error into a `Yara` diagnostic and `Failed` status without returning `Err`.

Keep the current `analyze_artifact` signature temporarily as a compatibility adapter for `scanner::scan`. It delegates to `analyze_artifact_result`, returns the legacy YARA error when the YARA status is `Failed`, and otherwise returns the evidence vector. Task 4 removes this adapter after structured orchestration is covered by its own failing tests.

- [ ] **Step 4: Run analyzer tests and verify GREEN**

Run:

```bash
cargo test detection::analyzer::tests -- --nocapture
```

Expected: partial-evidence and all dependency-context tests pass.

- [ ] **Step 5: Run all detection tests**

Run:

```bash
cargo test detection:: -- --nocapture
```

Expected: all detection tests pass.

### Task 4: Structured Scan Orchestration

**Files:**
- Modify: `src/scanner/scan.rs`
- Test: `src/scanner/scan.rs`

- [ ] **Step 1: Write failing scan-result tests**

Extract internal `scan_path_with_yara(path, yara_engine)` and `assemble_scan_result(target, target_type, discovery, yara_engine)` seams so unit tests do not depend on the repository-relative production rule directory.

Add tests using the Task 2 temporary-directory helper pattern:

```rust
#[test]
fn non_macho_scan_marks_macho_detectors_not_applicable() {
    let fixture = TestFile::new("ordinary.txt", b"ordinary data");
    let engine = YaraEngine::from_source(NO_MATCH_RULE).unwrap();

    let result = scan_path_with_yara(fixture.path(), &engine).unwrap();
    let artifact = &result.artifacts[0];

    assert_eq!(result.summary.discovered, 1);
    assert_eq!(result.summary.analyzed, 1);
    assert_eq!(artifact.verdict, Verdict::Unknown);
    assert_status(artifact, Detector::MachOHeader, DetectorOutcome::NotApplicable);
    assert_status(
        artifact,
        Detector::MachODependencies,
        DetectorOutcome::NotApplicable,
    );
    assert_status(artifact, Detector::RiskyRpath, DetectorOutcome::NotApplicable);
}
```

Add a deterministic multi-file result test. Extract a private `assemble_scan_result(target, target_type, discovery, yara_engine)` helper and test per-file continuation by passing a `DiscoveryResult` containing one nonexistent path followed by one readable fixture path. Assert one metadata diagnostic, `discovered == 2`, `analyzed == 1`, and `failed == 1`. This avoids permission-dependent tests.

- [ ] **Step 2: Run scanner tests and verify RED**

Run:

```bash
cargo test scanner::scan::tests -- --nocapture
```

Expected: compilation fails because `scan_path` returns `()` and no test seam exists.

- [ ] **Step 3: Assemble `ScanResult` without printing**

Change the public function to:

```rust
pub fn scan_path(path: &Path) -> Result<ScanResult, String>
```

The public function must validate the target *before* initializing YARA, preserving invalid-target error precedence:

```rust
pub fn scan_path(path: &Path) -> Result<ScanResult, String> {
    let target_type = inspect_path(path)?;
    let yara_engine = YaraEngine::from_directory(Path::new("rules/yara"))?;
    let discovery = discover_files_with_diagnostics(path)?;

    assemble_scan_result(path, target_type, discovery, &yara_engine)
}
```

The test-only/internal `scan_path_with_yara` must also validate before discovery and delegate to the same assembly helper. The implementation must:

1. call `discover_files_with_diagnostics`, then remove the temporary discovery compatibility adapter;
2. continue after one metadata failure with a `Metadata` scan diagnostic;
3. inspect Mach-O headers and dependencies independently, recording exact statuses and diagnostics;
4. pass `NotApplicable`, `Available`, or `Failed` dependency context to `analyze_artifact_result`, then remove the temporary legacy analyzer adapter;
5. merge analyzer statuses and diagnostics into the artifact result;
6. determine verdict from evidence only;
7. calculate summary counts after all files;
8. return the complete `ScanResult` without `println!` or `eprintln!`.

Preserve the current scan-wide YARA initialization behavior, including fatal initialization errors. CWD-independent and zero-rule loading belong to the later YARA-hardening module.

- [ ] **Step 4: Run scanner tests and verify GREEN**

Run:

```bash
cargo test scanner::scan::tests -- --nocapture
```

Expected: non-Mach-O status, deterministic result, and supported per-file continuation tests pass.

- [ ] **Step 5: Prove the scanner layer no longer presents output**

Run:

```bash
rg -n 'println!|eprintln!' src/scanner
```

Expected: no matches.

- [ ] **Step 6: Run the full unit suite**

Run:

```bash
cargo test
```

Expected: all tests pass.

### Task 5: Text Reporter and CLI Wiring

**Files:**
- Create: `src/report/mod.rs`
- Create: `src/report/text.rs`
- Modify: `src/main.rs`
- Test: `src/report/text.rs`

- [ ] **Step 1: Create exported report test modules and write failing renderer tests**

Create `src/report/mod.rs` containing `pub mod text;`, create `src/report/text.rs`, and declare `mod report;` from `src/main.rs`. Construct a representative `ScanResult` in `text.rs` tests and render it to `Vec<u8>` stdout/stderr buffers. The test file deliberately calls the not-yet-defined renderer so the RED command compiles the module and fails:

```rust
#[test]
fn text_report_renders_identity_evidence_verdict_and_summary() {
    let result = representative_result();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_text(&result, &mut stdout, &mut stderr).unwrap();

    let stdout = String::from_utf8(stdout).unwrap();
    assert!(stdout.contains("AegisForge"));
    assert!(stdout.contains("SHA-256:"));
    assert!(stdout.contains("Evidence [MEDIUM]:"));
    assert!(stdout.contains("Verdict: SUSPICIOUS"));
    assert!(stdout.contains("1 file(s) discovered"));
}

#[test]
fn text_report_writes_diagnostics_to_stderr() {
    let result = result_with_diagnostics();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_text(&result, &mut stdout, &mut stderr).unwrap();

    assert!(String::from_utf8(stderr).unwrap().contains("Warning:"));
}

#[test]
fn text_report_propagates_writer_failure() {
    let result = representative_result();
    let mut stdout = AlwaysFailWriter;
    let mut stderr = Vec::new();

    assert!(write_text(&result, &mut stdout, &mut stderr).is_err());
}
```

- [ ] **Step 2: Run reporter tests and verify RED**

Run:

```bash
cargo test report::text::tests -- --nocapture
```

Expected: compilation fails because `write_text` does not exist. The command must report the new test module rather than succeeding with zero matched tests.

- [ ] **Step 3: Implement minimal deterministic text rendering**

Expose:

```rust
pub fn write_text<W: Write, E: Write>(
    result: &ScanResult,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<()>
```

Write the header, target and type, each artifact's identity, optional Mach-O/dependency/RPATH details, evidence, verdict, and summary to stdout. Render scan-level and artifact-level diagnostics to stderr with their affected paths when present. Preserve the current dependency and RPATH classifications by calling the existing classification functions from the reporter.

- [ ] **Step 4: Run reporter tests and verify GREEN**

Run:

```bash
cargo test report::text::tests -- --nocapture
```

Expected: all reporter tests pass.

- [ ] **Step 5: Write and run a failing CLI propagation test**

In `src/main.rs`, add a unit test for a desired `render_scan_result(result, stdout, stderr) -> Result<(), String>` helper. Pass an `AlwaysFailWriter` as stdout and assert the helper returns an error containing `Failed to write scan report`. This proves reporter I/O errors reach the same fatal `Result` path used by `main`.

Run:

```bash
cargo test tests::rendering_failure_is_returned_as_fatal_error -- --nocapture
```

Expected: compilation fails because `render_scan_result` does not exist.

- [ ] **Step 6: Wire `main` to scanner and reporter, then satisfy the CLI test**

Implement the generic `render_scan_result` helper by mapping `write_text` I/O errors to `Failed to write scan report: ...`. For the scan command:

1. call `scan_path`;
2. lock stdout and stderr;
3. call `render_scan_result` (never bypass it with a direct `write_text` call);
4. return scanner and renderer failures through one `Result<(), String>` path;
5. print `Error: ...` and exit 1 for either fatal scan failure or reporter I/O failure.

Do not add CLI options in this phase.

- [ ] **Step 7: Run focused and full tests**

Run:

```bash
cargo test report::text::tests -- --nocapture
cargo test tests::rendering_failure_is_returned_as_fatal_error -- --nocapture
cargo test
```

Expected: all tests pass.

- [ ] **Step 8: Manually verify existing CLI behavior**

Run:

```bash
cargo build
./target/debug/af --help
./target/debug/af --version
./target/debug/af scan Cargo.toml
```

Expected: help and version remain unchanged; a scan prints structured text and an `UNKNOWN` verdict for `Cargo.toml`.

### Task 6: Full Phase Gate, Commit, and Push

**Files:**
- Verify all files listed above.

- [ ] **Step 1: Run formatting**

Run:

```bash
cargo fmt --check
```

Expected: exit 0 with no diff.

- [ ] **Step 2: Run compilation checks**

Run:

```bash
cargo check
```

Expected: exit 0. Do not introduce new warnings; remove Phase 1 warnings made obsolete by the result/report usage where practical.

- [ ] **Step 3: Run all unit tests**

Run:

```bash
cargo test
```

Expected: all existing and new tests pass, with zero failures.

- [ ] **Step 4: Build the binary**

Run:

```bash
cargo build
```

Expected: exit 0.

- [ ] **Step 5: Run the regression gate**

Run:

```bash
./scripts/check-all.sh
```

Expected: `ALL AEGISFORGE CHECKS PASSED`.

- [ ] **Step 6: Validate patch hygiene and scope**

Run:

```bash
git diff --check
git status --short
git diff --stat
```

Expected: no whitespace errors; only Phase 1 source, tests, and plan-tracking changes are present.

- [ ] **Step 7: Commit the coherent module**

Stage exact Phase 1 paths only, inspect the staged diff, then commit:

```bash
git add src/main.rs src/report src/scanner src/detection/analyzer.rs src/detection/evidence.rs docs/superpowers/plans/2026-08-08-structured-scan-results.md
git diff --cached --check
git diff --cached --stat
git commit -m "refactor(scanner): introduce structured scan results"
```

Expected: one coherent Phase 1 implementation commit.

- [ ] **Step 8: Inspect and push the verified commit**

Run:

```bash
git show --stat --oneline HEAD
git status --short
git push origin feature/cli-skeleton
```

Expected: clean worktree and a successful fast-forward push to the authorized development branch. Never force push.

- [ ] **Step 9: Report the phase**

Report: phase name, behavior and files changed, tests and results, commit SHA, push status, macOS verification performed, and remaining V0.1 work.
