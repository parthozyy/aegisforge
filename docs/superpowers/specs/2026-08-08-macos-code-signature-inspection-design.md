# macOS Code-Signature Inspection Design

## Purpose

This specification defines the second AegisForge V0.1 implementation module: read-only macOS code-signature inspection for recognized Mach-O files and application bundle roots. It builds on the structured scan-result foundation without adding entitlement inspection, Gatekeeper assessment, notarization claims, quarantine handling, or signature-derived security evidence.

## Product and Scope Constraints

- AegisForge continues to perform its own static inspection before native trust enrichment.
- Signature data is context, not proof that an artifact is safe.
- An unsigned object is not automatically suspicious or malicious.
- A failed or unavailable native command is a diagnostic, never security evidence.
- Scanned binaries and applications are never executed or modified.
- Native commands use `std::process::Command` with an absolute executable path and explicit argument arrays. No shell is involved.
- This module adds no Homebrew, release, remediation, entitlement, Gatekeeper, notarization, quarantine, or V0.2 work.
- No new Rust dependency is required.

## Selected Architecture

Code-signature results use one independent native-inspection collection in `ScanResult`. This collection can represent both file and directory targets without turning an application directory into a fake hashable artifact or splitting signature semantics across two models.

The data flow is:

```text
validated target
  -> discovery: regular files + .app bundle roots
  -> existing artifact snapshot analysis
  -> applicable signature targets
       - recognized Mach-O file
       - real .app directory
  -> safe native command runner
  -> codesign verification output + metadata output
  -> typed CodeSignatureInspection + diagnostics
  -> deterministic ScanResult
  -> text reporter
```

Application bundles are additional signature targets. Discovery still recursively scans their contents so bundle-level trust context never hides suspicious embedded files.

## Components

### macOS Module

Add a focused `src/macos/` module:

- `command.rs`: safe native-command request, output, error model, and production runner;
- `codesign.rs`: codesign target/result types, parser, and inspection orchestration;
- `mod.rs`: module exports.

The scanner owns scan ordering and result assembly. The macOS module owns native command invocation and parsing. The detector analyzer remains the only place that creates security evidence; Phase 2 does not add signature evidence.

### Native Command Runner

The reusable runner accepts an executable path and an ordered list of `OsStr` arguments. It returns:

- process termination status, including an optional numeric exit code;
- stdout bytes;
- stderr bytes.

It distinguishes:

- `Unavailable`: the executable could not be found;
- `Error`: another spawn or wait failure occurred;
- executed commands with a successful or unsuccessful exit status.

The runner must capture stdout and stderr separately because `codesign` commonly writes useful metadata to stderr. It must not accept a shell command string, invoke a shell, inherit interactive stdin, or execute the inspected object.

Production code uses the absolute path `/usr/bin/codesign`. Tests use a fake runner so parser and orchestration coverage do not depend on host signatures.

### Signature Targets

`CodeSignatureTargetKind` has two variants:

- `MachOFile` for files whose content snapshot was classified as Mach-O;
- `ApplicationBundle` for real directories whose extension is `.app`, matched case-insensitively.

`CodeSignatureInspection` contains:

- target path;
- target kind;
- signature presence;
- verification status;
- metadata-query status;
- identifier, when explicitly reported;
- Team Identifier, excluding the literal `not set` value;
- available authority lines, preserving chain order with stable de-duplication;
- signature kind;
- hardened-runtime flag when explicitly determinable;
- a concise verification detail when the command reports rejection;
- inspection diagnostics.

The top-level `ScanResult` owns a sorted `Vec<CodeSignatureInspection>` named `code_signatures`. Existing `ArtifactResult` values remain file-only and unchanged in meaning.

### Explicit Status Types

`SignaturePresence` is:

- `Signed`;
- `Unsigned`;
- `Unknown`.

`NativeCheckStatus` is:

- `Passed`: the check executed and succeeded;
- `Failed`: the check executed and rejected or could not describe the target;
- `NotApplicable`: there is no signature to verify, as with an explicitly unsigned applicable target;
- `Unavailable`: `/usr/bin/codesign` is unavailable on the platform;
- `Error`: the command could not be executed for another operational reason.

`SignatureKind` is deliberately conservative:

- `AdHoc` only when `Signature=adhoc` or an explicit `adhoc` flag is present;
- `CertificateBacked` when available authority data or an explicit signature-size record establishes a certificate-backed signature;
- `Unknown` otherwise.

The model does not infer Developer ID, Apple trust, or notarization merely from identifier text or a successful verification.

### codesign Invocation

For each applicable target, execute both documented queries with the path passed as one argument:

```text
/usr/bin/codesign --verify --verbose=4 <path>
/usr/bin/codesign -d --verbose=4 <path>
```

Both queries are attempted independently so partial metadata survives a verification failure and verification survives a display failure.

Interpretation rules are:

- verification exit success means `Passed` and establishes signed presence;
- the explicit phrase `code object is not signed at all` means `Unsigned` and verification `NotApplicable`;
- another verification nonzero exit means `Failed`, not unsigned and not an operational error;
- command-not-found maps to `Unavailable` plus a diagnostic;
- another runner failure maps to `Error` plus a diagnostic;
- display success is parsed for metadata;
- display nonzero with the explicit unsigned phrase confirms unsigned state;
- another display nonzero is `Failed`; metadata remains absent or partial and a diagnostic records the failed metadata query.

Verification and metadata output are parsed from both stdout and stderr. Parser matching is line-oriented and key-based, not a single brittle regular expression.

Each query keeps its own status even when the other query returns a different result. Final presence and metadata use the following precedence rules:

1. A failed pre-invocation target check produces `Unknown` presence, `Error` for both query statuses, no identity fields, and one target-change diagnostic. Neither command runs.
2. A non-macOS stub or command-not-found result produces `Unknown` presence and `Unavailable` for the affected query statuses. Another runner failure produces `Error` for the affected statuses.
3. Verification success or a successful display query establishes positive signed presence.
4. The explicit unsigned phrase establishes unsigned presence only when neither query positively establishes signed presence.
5. If one query positively establishes signed presence while either query explicitly reports unsigned, the inspection is contradictory: presence and signature kind become `Unknown`, all parsed identity/runtime fields are discarded, the per-query statuses remain truthful, and a diagnostic records the disagreement.
6. Without positive signed or explicit unsigned output, presence remains `Unknown`.

A display query that exits successfully has metadata status `Passed` and establishes `Signed` even if every recognized optional metadata field is absent. Explicit unsigned display output has metadata status `NotApplicable`. Another nonzero display exit has metadata status `Failed`, although any non-contradictory parsed lines may be retained as partial context.

Signature kind is calculated only after presence reconciliation. Explicit ad-hoc markers produce `AdHoc`; available authorities or an explicit signature-size record produce `CertificateBacked`; conflicting ad-hoc and certificate-backed markers produce `Unknown` plus a diagnostic. No signature kind is assigned to `Unsigned` or `Unknown` presence.

### Metadata Parsing

Recognized records include:

- `Identifier=`;
- `TeamIdentifier=`;
- repeated `Authority=`;
- `Signature=adhoc`;
- `Signature size=`;
- `CodeDirectory ... flags=...(...)`.

`TeamIdentifier=not set` and `Authority=(unavailable)` are absence markers rather than useful identity values. Hardened runtime is `Some(true)` only when the explicit flag list contains `runtime`, `Some(false)` when a flag list is present without it, and `None` when no flags record exists.

Unknown lines are ignored. Parsing must tolerate changed ordering, additional Apple output, CRLF, and useful content appearing in either stream. Raw output is not treated as evidence.

### Application-Bundle Discovery

`DiscoveryResult` gains a sorted, de-duplicated `app_bundles` collection.

- A direct top-level `.app` directory is included once.
- Nested real `.app` directories are included when encountered.
- Bundle contents are still traversed recursively.
- Symlinked bundles remain skipped under the existing symlink policy.
- Case-insensitive `.app` matching is used.
- Existing file ordering and discovery diagnostics remain deterministic.

The existing artifact summary counts only discovered files. Bundle-signature targets do not change `discovered`, `analyzed`, or `failed` artifact counts.

### Scanner Integration

Mach-O signature inspection runs only after the artifact has been safely collected and classified from its immutable snapshot. Application bundle inspection uses the separately discovered bundle roots. Signature results are sorted by target path and then target kind.

One signature failure never aborts later artifacts or bundles. Native failures are represented in the inspection and as `CodeSignature` diagnostics. Existing YARA, structural evidence, and verdicts are preserved exactly.

`codesign` accepts paths rather than retained file descriptors. Immediately before invocation, production inspection rechecks the target with `symlink_metadata` and refuses a symlink or an unexpected target kind. This narrows substitution risk, but it cannot provide complete hostile-tree race confinement across an external path-based Apple tool. Phase 2 must not claim stronger confinement than it implements.

### Platform Behavior

On macOS, the production inspector invokes `/usr/bin/codesign`.

On non-macOS targets, the same public API builds and returns `Unavailable` inspections without trying to execute a macOS tool. Parser tests remain platform-independent. No test may falsely claim that native macOS integration ran on another platform.

### Text Reporting

The default report gains deterministic native-signature sections after the existing artifact output:

- `Mach-O code signatures` for file targets;
- `Application bundle signatures` for `.app` roots.

Each entry prints path, presence, verification, metadata status, kind, identifier, Team ID, authorities, hardened runtime, and verification detail when present. Missing optional values render as `unknown` or `not available`; they are not silently promoted to positive trust facts.

All paths and untrusted metadata use the existing terminal-safe escaping. Diagnostics remain on stderr. Verdicts and summary counts are unchanged.

## Error Semantics

Fatal scan-wide errors remain unchanged: invalid top-level targets and required scan-wide initialization failures return `Err`.

Code-signature problems are nonfatal per-target outcomes:

- unsigned object: structured unsigned fact, no diagnostic required;
- invalid signature: structured failed verification fact, no evidence;
- codesign unavailable: unavailable statuses plus diagnostic;
- spawn/wait error: error statuses plus diagnostic;
- metadata display failure: partial result plus diagnostic;
- target changed to a symlink or wrong kind before invocation: error status plus diagnostic;
- unrecognized output: conservative unknown fields without invented trust claims.

No code-signature status changes a verdict in Phase 2.

## Testing Strategy

Implementation follows red-green-refactor cycles. Required tests include:

- command runner preserves separate stdout/stderr and nonzero exit status;
- command runner reports unavailable and other I/O failures distinctly through an injectable seam;
- parser extracts identifier, Team ID, ordered authorities, ad-hoc signature, certificate-backed signature, and runtime flag;
- parser handles `not set`, `(unavailable)`, unknown lines, CRLF, reordered lines, and split streams;
- explicit unsigned output differs from invalid verification;
- verification and metadata failures preserve the other query's successful facts;
- command arguments are exact and paths containing spaces or shell metacharacters remain one argument;
- Mach-O files produce signature targets while non-Mach-O files do not;
- direct and nested `.app` roots are sorted/de-duplicated while their contents remain discovered;
- symlinked `.app` roots remain skipped;
- one failed signature inspection does not abort later targets;
- non-macOS production behavior is unavailable without command execution;
- reporter renders Mach-O and bundle sections through terminal-safe escaping;
- existing 68 tests and the full regression script remain green.

Read-only macOS validation should also exercise:

- the built `target/debug/af`, which may be linker-signed/ad-hoc;
- one available system application bundle;
- an unsigned-Mach-O synthetic runner fixture in the required automated suite;
- a disposable harmless unsigned Mach-O host fixture only when one can be prepared without modifying any user or system artifact.

Host results are recorded as observations, not hard-coded trust expectations, because OS builds and signatures vary.

## Commit Gate

Before committing:

```text
cargo fmt --check
cargo check --locked --offline
cargo test --locked --offline
cargo build --locked --offline
YRX_REGENERATE_MODULES_RS=false cargo clippy --all-targets --all-features --locked --offline -- -D warnings
./scripts/check-all.sh
git diff --check
git status --short
```

The coherent module commit is:

```text
feat(macos): inspect code signatures
```

It is pushed to `origin/feature/cli-skeleton` only after the complete gate and independent review pass.

## Deferred Work

The following remain later V0.1 modules:

- entitlement extraction;
- Gatekeeper/system-policy assessment;
- explicitly supportable notarization evidence;
- quarantine metadata;
- trust aggregation and conservative signature-derived evidence;
- JSON reporting and CLI flags.

Homebrew and all other V0.2 work remain explicitly deferred.
