# Structured Scan Results Design

## Purpose

This specification defines the first AegisForge V0.1 implementation module: replacing presentation-coupled scan orchestration with structured, testable scan results. It preserves all existing scanner and detector behavior while creating the foundation required by later macOS trust, bounded-analysis, hash, and JSON-reporting modules.

The broader V0.1 release continues in the phased order established by the master handoff. Each later subsystem receives its own focused implementation plan and coherent commit rather than being combined into one large change.

## Product and Scope Constraints

- Scanning remains local, deterministic where practical, read-only, privacy-preserving, and safe by default.
- Scanned files are never executed, uploaded, modified, or passed through a shell.
- Operational failures remain distinct from security evidence.
- `UNKNOWN` remains the verdict when there is no evidence or only low-severity evidence. `CLEAN` is not enabled.
- The existing `af scan <PATH>` command and default human-readable output remain available.
- This module does not add macOS native trust inspection, JSON output, remediation, V0.2 scanning features, releases, tags, or package publication.
- Homebrew packaging is explicitly deferred to V0.2 by user direction.

## Current Problem

`src/scanner/scan.rs` currently discovers artifacts, performs analysis, calculates verdicts, and prints directly to stdout and stderr. This produces four concrete problems:

1. Scan behavior cannot be tested without capturing process output.
2. Per-detector failures cannot be represented independently from security findings.
3. A YARA error discards evidence already produced by other detectors for the artifact.
4. Later JSON reporting and macOS trust aggregation would require more presentation logic inside the scanner.

## Architecture

The scanner will return a structured `ScanResult`. Presentation will consume that result through a text reporter. Fatal setup errors remain `Err`, while nonfatal discovery or artifact-analysis problems are stored as diagnostics and scanning continues.

The data flow becomes:

```text
validated target
  -> discovery outcome
  -> artifact metadata
  -> optional Mach-O inspection
  -> detector analysis
  -> evidence + detector status + diagnostics
  -> verdict
  -> ScanResult
  -> text reporter
```

The existing binary entry point remains responsible only for parsing CLI arguments, invoking the scanner, selecting the reporter, and mapping fatal errors to exit code 1.

## Components

### Scanner Result Model

Add `src/scanner/result.rs` with focused domain types:

- `ScanResult`: target path and type, artifact results, scan-level diagnostics, and summary.
- `ArtifactResult`: artifact metadata, optional Mach-O information, optional dependency information, evidence, verdict, detector statuses, and artifact diagnostics.
- `ScanSummary`: discovered, analyzed, failed, unknown, suspicious, and malicious counts.
- `ScanDiagnostic`: stable diagnostic category, optional affected path, and human-readable message.
- `DetectorStatus`: detector identity and explicit outcome.
- `DetectorOutcome`: completed, skipped, not applicable, unavailable, or failed.

Phase 1 diagnostic categories are `Discovery`, `Metadata`, `MachOHeader`, `MachODependencies`, and `Yara`. Reporter write errors are fatal I/O errors and are not stored as scan diagnostics. Phase 1 detector identities are `FileTypeMismatch`, `MachOHeader`, `MachODependencies`, `RiskyRpath`, and `Yara`.

Detector outcomes have the following exact meaning:

- `Completed`: the detector ran successfully, including when it produced no evidence.
- `NotApplicable`: the artifact type is outside the detector's domain. All three Mach-O-specific checks use this for non-Mach-O artifacts.
- `Skipped`: the detector did not run because a prerequisite was unavailable. `RiskyRpath` uses this when Mach-O dependency parsing failed.
- `Failed`: the detector ran or attempted to run but returned an operational error. Mach-O header parsing, dependency parsing, and YARA scanning use this for their own failures.
- `Unavailable`: a required external capability is unavailable. This outcome is reserved in the shared model for later native-trust phases and is not normally produced by Phase 1.

`FileTypeMismatch` and `Yara` apply to every artifact with collected metadata. `MachOHeader` and `MachODependencies` apply only to Mach-O artifacts. `RiskyRpath` is completed after successful Mach-O dependency parsing, even if the binary has no RPATH entries or the detector emits no evidence.

Diagnostic categories and detector identities use typed enums rather than arbitrary strings. Messages include the operation and affected path where relevant.

The result model will derive the traits needed by tests and reporting. Serialization derives are deferred until the JSON module so this phase does not add unused dependencies.

### Discovery

Discovery will return both discovered file paths and nonfatal diagnostics. Directly scanning a symlink, nonexistent path, or unsupported filesystem object remains a fatal validation error. Symlinks encountered below a directory remain skipped. Unreadable directories or entries produce scan-level diagnostics and do not abort the scan.

Discovered paths will be sorted before analysis so text output and later JSON output are deterministic for the same filesystem state.

### Artifact Analysis

Each discovered file is analyzed independently. Failure to collect required artifact metadata prevents creation of an `ArtifactResult`; it adds a scan-level diagnostic and increments the failed count.

Summary counts obey these invariants:

- `discovered` is the number of paths returned by discovery.
- `analyzed` is the number of successfully created `ArtifactResult` values.
- `failed` is the number of discovered paths that failed before an `ArtifactResult` could be created.
- `discovered == analyzed + failed`.
- `unknown + suspicious + malicious == analyzed`.

For a valid artifact:

- Non-Mach-O files mark Mach-O detectors not applicable.
- Mach-O header or dependency parser failures create artifact diagnostics and failed detector statuses without aborting other analysis.
- File-mismatch and risky-RPATH evidence are preserved even if YARA fails.
- YARA failure creates a diagnostic and a failed status, never evidence.
- The verdict is calculated only from collected security evidence.

The scanner processes one artifact at a time. Concurrency is outside this module.

### Text Reporting

Add `src/report/mod.rs` and `src/report/text.rs`. The reporter renders a `ScanResult` using the existing conceptual sections and wording: target, artifact identity, Mach-O details, dependencies, RPATHs, evidence, verdict, diagnostics, and summary.

The scanner itself will not call `println!` or `eprintln!`. The text reporter writes normal scan content to an injected stdout writer and diagnostics to an injected stderr writer so tests can verify both streams without spawning the binary. Any reporter write failure is returned to the CLI as a fatal error and produces exit code 1.

The default CLI output should remain recognizably compatible, but deterministic ordering and explicit diagnostic labels are permitted improvements.

## Error Semantics

Fatal errors return `Err` and cause exit code 1:

- invalid or inaccessible top-level target;
- unsupported top-level filesystem object;
- failure to initialize a required scan-wide detector under the current V0.1 behavior.

Nonfatal problems are diagnostics and scanning continues:

- unreadable nested directories or entries;
- metadata or content-read failure for one artifact;
- malformed Mach-O data after content classification;
- individual detector failure.

No diagnostic changes a verdict. No detector failure is translated into evidence.

## Testing Strategy

Implementation follows strict red-green-refactor cycles. Every behavior change begins with a failing test and the expected failure is observed before production code is added.

Required tests for this module:

- result summary counts each verdict and failed artifact correctly;
- discovery records unreadable-entry diagnostics where the platform permits reliable simulation;
- discovery output is deterministic and symlinks remain skipped;
- a per-artifact failure does not abort later artifacts;
- a YARA failure preserves evidence from completed detectors;
- non-Mach-O artifacts mark Mach-O checks not applicable;
- text rendering reproduces artifact identity, evidence, verdict, diagnostics, and summary;
- renderer tests use in-memory writers rather than global output capture;
- the existing 36 tests and regression script remain green.

Before committing the module, run:

```text
cargo fmt --check
cargo check
cargo test
cargo build
./scripts/check-all.sh
git diff --check
git status --short
```

The module is committed as `refactor(scanner): introduce structured scan results` only after all gates pass, then pushed to `origin/feature/cli-skeleton`.

## Subsequent V0.1 Modules

After this foundation is accepted, implementation proceeds in the approved order:

1. code-signature inspection;
2. entitlement inspection;
3. Gatekeeper and explicitly supportable notarization evidence;
4. quarantine metadata;
5. macOS trust aggregation and conservative trust evidence;
6. YARA production hardening;
7. bounded Mach-O analysis;
8. local known-hash matching;
9. coverage-aware detector status cleanup;
10. text and stable-schema JSON reporting;
11. focused CLI options;
12. test hardening;
13. CI;
14. V0.1 documentation and final validation.

No V0.2 work begins until V0.1 is stable and the user explicitly approves it.
