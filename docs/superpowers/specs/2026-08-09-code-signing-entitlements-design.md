# Code-Signing Entitlement Inspection Design

## Purpose

This specification defines the third AegisForge V0.1 implementation module: read-only extraction, normalization, and reporting of code-signing entitlements for Mach-O files and application bundles already selected by the native signature layer.

Entitlements are declared capabilities and configuration. Values such as JIT access, disabled library validation, or `get-task-allow` are useful security context, but are not automatically malware indicators. This module records facts only. It does not create evidence, alter verdicts, or score entitlement combinations.

An adversarial review also exposed a fact-injection flaw in Phase 2's human-readable codesign metadata parser. This module must replace that parser with Security.framework's public structured signing-information dictionary before adding entitlement facts. Shipping new structured facts alongside known-injectable metadata would not be acceptable.

## Scope

This module will:

- replace parsed `/usr/bin/codesign -d --verbose=4` metadata with public Security.framework values;
- retain bounded `/usr/bin/codesign` only for verification and structured DER entitlement extraction;
- recognize legacy XML or binary property-list entitlement slots through Security.framework's typed dictionary rather than parse codesign text;
- distinguish parsed DER, signed/no-entitlements, unsigned, rejected, unavailable, runner failure, malformed output, and non-authoritative compatibility context;
- normalize admitted values into one bounded recursive model;
- report every retained entitlement deterministically with security-oriented escaping;
- select one Mach-O slice deterministically, bind both structured sources to its exact CPU type/subtype, and, whenever that selector remains safely bound, label every available but uninspected slice;
- retain root identity checks and require a safely resolved, retained bundle main executable before any selected-slice fact query;
- keep failures nonfatal and scoped to the affected signature target.

It will not add entitlement-derived evidence, modify signatures, execute inspected code, assess Gatekeeper or notarization, inspect quarantine, add JSON output or CLI flags, perform Homebrew/V0.2 work, or implement the later aggregate macOS trust model.

## Validated Native Interfaces

### Entitlement extraction

The macOS 26.5.2 `codesign(1)` manual documents `--entitlements path`, says `-` writes entitlement data to stdout, and permits `--der` or `--xml` to select a representation. The selected command is:

```text
/usr/bin/codesign -d --entitlements - --der --architecture <cpu-type>,<cpu-subtype> -- <absolute-path>
```

Read-only host checks confirmed:

- a signed executable without entitlements exits successfully with exactly zero stdout bytes;
- an explicitly empty dictionary emits DER bytes `70 05 02 01 01 b0 00`;
- current DER-backed applications emit a constructed application tag 16 document;
- a normal legacy XML-backed application is normalized to the same DER schema by codesign;
- an unsigned object exits nonzero with a target-prefixed diagnostic;
- `--entitlements :-` emits a deprecation warning and is not used;
- a numeric CPU type plus comma-separated subtype is accepted by `--architecture`, avoiding architecture-name ambiguity;
- `--` is accepted before the target and prevents option injection.

### Structured signing information

The public Security.framework sequence for the selected slice is:

```text
SecStaticCodeCreateWithPathAndAttributes({
    kSecCodeAttributeArchitecture: <CFNumber cpu type>,
    kSecCodeAttributeSubarchitecture: <CFNumber cpu subtype>
})
SecStaticCodeCheckValidity(kSecCSBasicValidateOnly | kSecCSNoNetworkAccess)
SecCodeCopySigningInformation(kSecCSSigningInformation)
```

`SecStaticCodeCreateWithPathAndAttributes` receives zero flags. For an application bundle only, one preliminary zero-flag `SecStaticCodeCreateWithPath`/basic-validity/copy operation resolves the documented main executable before its Mach-O selector can be read. After preliminary basic-validity success or exactly `errSecCSUnsigned`, its `SecCodeCopySigningInformation` call uses `kSecCSDefaultFlags` (`0`), which host validation confirmed returns `kSecCodeInfoMainExecutable` without requesting the broader certificate/signing-information payload. The returned path is an untrusted locator until the filesystem checks below pass. Every other preliminary validity result suppresses that copy. No status, presence, metadata, or entitlement fact from the default-architecture preliminary result is retained.

The selected-slice basic validity check validates signature structure before facts are copied, while deliberately leaving inner executable pages, inner signed-header validity, all architectures, and bundle resources to the independently reported codesign verification query. After selected basic-validity success, `SecCodeCopySigningInformation` receives exactly `kSecCSSigningInformation`. For an application bundle, the copied full dictionary's main path is validated before any other returned field is observed. If the selected basic check instead returns exactly `errSecCSUnsigned`, AegisForge performs one selected `kSecCSDefaultFlags` (`0`) copy, reads only `kSecCodeInfoMainExecutable`, and requires it to equal the preliminary captured path and identity before accepting the unsigned observation. No other field from that locator dictionary is read or retained.

For a bundle, any selected validity result other than success or exact unsigned, or any selected full/locator copy, type, path, or equality failure before main binding, invalidates and discards the selector and available-architecture list. The selected metadata status becomes `Error`, DER is suppressed as unbound, and only the later all-architecture verification can establish presence under the no-safe-selector rule. A Mach-O file target does not need this locator gate because its validated query path is already the retained main executable; its selected query status remains independently reportable and DER may continue after non-identity selected-query failures. `kSecCSNoNetworkAccess` explicitly disables online certificate, revocation, and notarization work on this uncancellable in-process path. The no-network bit is passed only to each `SecStaticCodeCheckValidity`; it is never passed to a copy call.

The adapter reads only documented public keys:

- `kSecCodeInfoIdentifier`;
- `kSecCodeInfoTeamIdentifier`;
- `kSecCodeInfoCertificates`;
- `kSecCodeInfoFlags`;
- `kSecCodeInfoMainExecutable`;
- `kSecCodeInfoEntitlements`;
- `kSecCodeInfoEntitlementsDict`.

Slice selection uses only the documented `kSecCodeAttributeArchitecture` and `kSecCodeAttributeSubarchitecture` keys with signed 32-bit CFNumbers copied directly from the retained, no-follow Mach-O handle. The selector is structurally and identity bound to the current bytes before use. Selected `kSecCSBasicValidateOnly` success does not cryptographically authenticate a thin Mach-O header or executable pages. Successful full all-architecture verification authenticates each presented inner thin header and its executable pages, but does not authenticate the outer fat header/table: outer count, offsets, sizes, alignment fields, and layout remain only bounded and structurally checked. Exact outer/inner CPU-selector equality binds the reported selector to the authenticated inner CPU fields when verification passes. Selected facts remain useful context when verification fails, but their report never upgrades that independent verification result.

Ad-hoc and hardened-runtime state come from the public `kSecCodeSignatureAdhoc` and `kSecCodeSignatureRuntime` flag bits. Certificate authorities come from structured certificate subject summaries, not lines of command output.

Local hostile-signature testing proved why this replacement is required. A signed identifier containing newline-delimited `TeamIdentifier=` and `Authority=` text creates apparently valid records in `codesign -d --verbose=4`; Security.framework returns the entire identifier as one CFString and does not manufacture those fields.

Security.framework's public entitlement keys are present for a validated legacy XML-backed application and absent for tested modern DER-only applications. The bounded DER query completes the modern coverage that the public dictionary alone lacks.

Both Security.framework signing-information display and codesign entitlement display select one architecture by default for a universal Mach-O, while codesign verification defaults to all architectures. A controlled fat binary with different valid x86_64 and arm64e entitlement dictionaries confirmed this behavior. Phase 3 therefore avoids both defaults for facts: it parses at most 32 selectors from the retained main-executable handle, verifies each outer fat entry against that slice's inner thin Mach-O header, sorts unique `(cpu_type, cpu_subtype)` pairs lexicographically as signed 32-bit integers, selects the first, and passes that exact selector to both APIs. When the selector remains safely bound and selected facts are retained, universal results are labeled `SELECTED_ARCHITECTURE`, store the full bounded selector list, and emit a diagnostic naming every uninspected slice. If a later bundle binding gate invalidates the selector, the list and selected facts are cleared under the `ALL_ARCHITECTURES`/`UNKNOWN` rules below. Neither outcome is described as whole-file entitlement coverage.

## Rejected Text Interfaces

### Default entitlement text

Codesign's default entitlement output is a tab-indented representation containing records such as `[Dict]`, `[Key]`, and `[String]`. It is structurally injectable.

A controlled disposable signature had one real key whose string value contained:

```text
safe
	[Key] injected.example
	[Value]
		[Bool] true
```

Default codesign output rendered those embedded lines exactly like a second top-level key. No indentation parser can recover the lost boundary. The DER output preserved the content as one UTF-8 string. AegisForge never turns abstract codesign text into entitlement facts, and a permanent regression test covers this fixture.

### Verbose metadata text

The Phase 2 metadata parser is likewise rejected. Both a newline-bearing filename and a signed newline-bearing identifier can forge `Identifier=`, `TeamIdentifier=`, `Authority=`, `Signature=`, or `CodeDirectory` records. Tightening record order would remain dependent on undocumented display formatting and would not make repeated authority records unambiguous.

### XML command fallback

AegisForge does not run `codesign --xml` as a fallback. Modern DER-only apps can return empty XML plus a warning, and two signed entitlement representations can disagree. Treating an arbitrary legacy slot as a successful substitute could report values macOS ignores. Legacy property-list context is instead obtained from the same structured, basically validated Security.framework result and is never promoted over conflicting DER.

## Selected Architecture

For each target, one orchestrator combines three independently reportable observations:

1. a structured Security.framework signing-information query;
2. bounded codesign verification;
3. bounded codesign DER entitlement extraction.

`src/macos/security_info.rs` owns the macOS FFI adapter and converts public CoreFoundation values into bounded Rust-owned observations. `src/macos/entitlements.rs` owns the entitlement model, DER decoder, recursive structured-value conversion, normalization, comparison, and budgets. `src/macos/codesign.rs` owns orchestration, exact native-output classification, target revalidation, status reconciliation, and diagnostics. `src/report/text.rs` owns terminal rendering.

The Security.framework adapter is behind a private trait so orchestration is fully testable without native calls. The non-macOS production inspector remains a stub.

## Dependency and FFI Choice

Add direct exact dependency `der = "=0.7.10"`. That version is already locked and cached through YARA-X's cryptographic dependencies. AegisForge uses borrowed RustCrypto `AnyRef`, `SliceReader`, `Utf8StringRef`, and `OctetStringRef` APIs; it does not rely on allocation features inherited accidentally through feature unification.

Under `cfg(target_os = "macos")`, add direct exact dependency `core-foundation-sys = "=0.8.7"`, also already locked and cached. A small handwritten extern block declares the public Security.framework functions, constants, and retained-reference ownership that its sys crate does not expose. The unsafe surface is confined to `security_info.rs`, every retained object has RAII release, every nullable pointer and CF type ID is checked, and collection/string lengths are bounded before allocation.

Do not add `plist`, `security-framework`, or `security-framework-sys`. The selected public API already supplies a framework-normalized legacy dictionary; avoiding a second property-list decoder removes AegisForge-owned auto-detection, entity, pre-event allocation, and shared-reference parser risks. Security.framework may already have resolved duplicate serialized keys before returning its CFDictionary, so legacy-only values remain explicitly non-authoritative. The selected dependencies add no new package record or license to the lockfile.

## Typed Entitlement Model

`CodeSignatureInspection` gains:

- `native_fact_scope: NativeFactScope`;
- `selected_architecture: Option<CodeSignatureArchitecture>`;
- `available_architectures: Vec<CodeSignatureArchitecture>`;
- `der_entitlements_status: NativeCheckStatus`;
- `entitlements_status: NativeCheckStatus`;
- `entitlement_source: Option<EntitlementSource>`;
- `entitlements: Vec<EntitlementEntry>`.

`der_entitlements_status` is the independently truthful result of the bounded DER command and decoder. `entitlements_status` is the final assessment after the DER result is compared with any structured legacy observation. Keeping both prevents compatibility or disagreement handling from hiding whether the primary query passed, was rejected, was unavailable, or failed locally.

`CodeSignatureArchitecture` stores the exact signed 32-bit CPU type and subtype plus a deterministic display label. Its codesign selector is the decimal string `<cpu_type>,<cpu_subtype>`. `NativeFactScope` is `ALL_ARCHITECTURES`, `SINGLE_ARCHITECTURE`, `SELECTED_ARCHITECTURE`, or `UNKNOWN`. Verification always remains target-wide/all-architectures. For `SINGLE_ARCHITECTURE` and `SELECTED_ARCHITECTURE`, presence, signature kind, structured metadata, and entitlements are explicitly scoped to `selected_architecture`; verification status is the separately labeled all-architecture result. `ALL_ARCHITECTURES` is used only when no safe retained selector remains—whether construction failed or a later bundle binding gate invalidated it—and successful all-architecture verification still establishes signed presence; it carries no selected architecture, metadata, kind, or entitlements. `UNKNOWN` likewise has no safe retained selector or structured facts and cannot report `Signed` or `Unsigned` presence.

Field invariants are exact: `UNKNOWN` and `ALL_ARCHITECTURES` have no selected or available architecture and no selected facts; `SINGLE_ARCHITECTURE` has exactly one available selector equal to the selected selector; `SELECTED_ARCHITECTURE` has at least two available selectors and contains the selected selector. A universal target can therefore report a selected slice as `Unsigned` without claiming the whole file is unsigned, or report the selected slice as `Signed` while the independent all-architecture verification fails.

Sources are:

```text
CODESIGN_DER_OUTPUT
LEGACY_PROPERTY_LIST_NON_AUTHORITATIVE
```

`CODESIGN_DER_OUTPUT` describes the successfully decoded format returned by the documented command. It does not claim that a physical DER slot was embedded in the signature: codesign can normalize a legacy XML-only slot into the same output representation.

The value domain is intentionally limited to types accepted by the validated CoreEntitlements representation:

```text
Boolean(bool)
SignedInteger(i64)
UnsignedInteger(u64)
String(String)
Data(Vec<u8>)
Array(Vec<EntitlementValue>)
Dictionary(Vec<EntitlementEntry>)
```

Current codesign signing tests reliably support booleans, signed integers, strings, arrays, and dictionaries. OCTET STRING/data is admitted for compatible implementations. Floating-point numbers, dates, UIDs, unknown CF types, and unknown DER tags are rejected instead of coerced. DER integers outside the combined `i64`/`u64` domain are rejected. Nonnegative values through `i64::MAX` normalize to `SignedInteger`; only larger canonical positive values become `UnsignedInteger`.

The root is depth 1 and must be a dictionary. Dictionary keys are sorted lexicographically at every level, arrays preserve order, and dictionary construction uses a `BTreeMap` so duplicate detection and common-prefix keys remain O(n log n). The owned model exposes no CoreFoundation or DER implementation types.

## CoreEntitlements DER Schema

The primary decoder accepts exactly the locally validated Apple shape:

```text
[APPLICATION 16] {
    INTEGER 1,
    [CONTEXT 16] {
        SEQUENCE { UTF8STRING key, value },
        ...
    }
}
```

Within a value position:

- `BOOLEAN` becomes `Boolean`;
- canonical `INTEGER` becomes a signed or unsigned integer under the normalization rule;
- `UTF8STRING` becomes `String`;
- `SEQUENCE` becomes an array;
- constructed `[CONTEXT 16]` becomes a dictionary;
- `OCTET STRING` becomes `Data`;
- every other tag is rejected.

The decoder requires schema version 1, exactly one key and one value per entry, complete consumption of every nested container, canonical lengths/integers/booleans, and no trailing bytes. Every scalar is decoded through its typed RustCrypto decoder and every manually entered reader is explicitly finished; accepting only a superficially valid TLV is insufficient.

## Legacy Property-List Observation

Security.framework returns the legacy embedded entitlement blob as `kSecCodeInfoEntitlements` CFData and, when it is a standard dictionary, the corresponding typed `kSecCodeInfoEntitlementsDict`.

The raw code-signing blob is used only for provenance and bounds. It must contain at least eight bytes, have big-endian magic `0xFADE7171`, and declare a big-endian length that includes the eight-byte header and exactly equals the CFData length. A payload beginning exactly with `bplist00` is binary. An XML payload must be valid UTF-8 and, after at most one UTF-8 BOM plus ASCII XML whitespace, begin with `<?xml` or `<plist`. Every other prefix or encoding is invalid. No raw payload is parsed by AegisForge. The typed public dictionary is recursively converted into the same model. Exactly one of the two legacy keys being present—raw without dictionary or dictionary without raw—is `Invalid`. A dictionary with invalid public value types, an unknown envelope, or inconsistent lengths is also `Invalid`.

Internally, the legacy observation is exactly one of:

```text
Absent
Valid { format, entries }
Invalid { reason }
Unobserved { reason }
```

`Invalid` always makes the final entitlement assessment `Error` and never supplies facts, regardless of the DER command status. It is not collapsed into `Absent` when the final matrix is applied.

`Absent` means the selected-architecture full signing-information query completed, was bound to the expected main executable, and both public legacy-entitlement keys were genuinely absent. `Unobserved` is permitted only when no selected-architecture full signing-information dictionary was obtained and bound because selector construction, selected-slice basic validation, copy, main binding, or the outer FFI operation failed. Preliminary and selected-unsigned path-only locator dictionaries, and any unbound full dictionary, are never inspected beyond the main-path key or substituted for this state. Once the selected full dictionary is main-bound, either public legacy key being observed makes every one-key-only pair, wrong CF type, oversized blob, framing/prefix error, unsupported value, cycle, or conversion-budget failure `Invalid`, never `Unobserved`. `Valid` is explicitly a Security.framework-normalized interpretation: serialized duplicate-key distinctions no longer exist in the returned CFDictionary. A valid DER result remains independently authoritative when legacy data is unobserved; diagnostics preserve why comparison was unavailable.

If DER and legacy dictionaries both exist, their fully normalized trees must be equal. Equality retains the DER result as `Passed` with source `CODESIGN_DER_OUTPUT`. A mismatch discards both trees and produces `Error`; AegisForge never guesses which conflicting slot macOS enforces.

If DER cannot be established because its independent status is `Failed`, `Unavailable`, or `Error`, but a complete legacy dictionary exists, AegisForge may retain that dictionary only as compatibility context. Its final status is `Error`, its source is `LEGACY_PROPERTY_LIST_NON_AUTHORITATIVE`, and a diagnostic records both the DER status and the fact that no authoritative DER observation was established. Compatibility values do not themselves establish signed presence and are cleared unless another independent query establishes an uncontradicted signed target. A successful DER observation of either a dictionary or absence, and an exact DER-query unsigned result, are authoritative observations rather than fallback failures; a disagreeing legacy slot is therefore discarded, not retained as compatibility context.

This handles XML and binary property-list slots when Security.framework recognizes them, without interpreting human-readable codesign output or trusting a fallback representation as authoritative.

## Resource Bounds

The following checked limits apply per target:

- 256 KiB maximum DER stdout or legacy raw entitlement blob;
- maximum depth 32, with the root counted as depth 1;
- maximum 4,096 logical nodes, counting every value and every dictionary entry;
- maximum 256 KiB cumulative materialized key/scalar bytes, charged for every logical occurrence before cloning or insertion;
- maximum 64 certificates and 64 KiB aggregate identifier/team/authority UTF-8 bytes;
- maximum 16 KiB for a filesystem-byte main-executable path returned through CoreFoundation;
- maximum 4 KiB retained detail from any native or framework failure, with explicit truncation.

The materialized budget counts shared CoreFoundation references on every traversal occurrence. Conversion also maintains an active-container identity set and rejects cycles. Checked arithmetic is mandatory. A large shared string referenced thousands of times therefore fails before an amplified Rust-owned tree is built. Container counts are checked before allocating Rust vectors, and dictionary insertion remains O(n log n).

Security.framework necessarily materializes its own signing-information dictionary before returning it, and the public API exposes neither a pre-parse size limit nor cancellation. The bounds above govern AegisForge's copies and traversal after the native call returns; they do not claim to bound Security.framework's internal allocations. That trusted native-parser boundary and its latency are explicit residual risks.

The entitlement reporter streams values rather than constructing one recursive output string. Security-text escaping expands one admitted byte by at most eight bytes, and fixed syntax is bounded by the node limit. Together, the materialized and node budgets keep one entitlement report below a conservative 3 MiB bound. A counting-writer test verifies that bound.

## Target and Native-Output Integrity

Before native inspection, AegisForge resolves one absolute, normalized query path and verifies it refers to the already selected target kind. The original and resolved root identities are retained. Paths containing CR or LF bytes are rejected for native inspection before any query; ordinary static analysis still proceeds.

The exact operation order is:

1. validate the original and resolved root identities;
2. for a bundle, run the preliminary path-only main-executable resolution under the success/unsigned continuation rule above and immediately revalidate both roots;
3. open the main executable with no-follow semantics, validate/capture its identity, parse the bounded architecture table, and choose the deterministic selector;
4. run the explicitly selected structured Security.framework query, including selected-main equality validation for either a full facts copy or the bundle unsigned path-only copy; discard an unbound bundle selector, then revalidate both roots and the main executable;
5. run bounded codesign verification with an explicit all-architectures flag, then revalidate both roots and the main executable;
6. if the selector remains safely bound, run bounded DER extraction with that exact architecture, then revalidate both roots and the main executable;
7. reconcile only after all required target revalidations pass.

Any failed filesystem identity, type, architecture-table, or confinement validation suppresses every later architecture-dependent stage and discards earlier structured facts. The same no-safe-selector outcome applies when a bundle main executable cannot be resolved or when the selected bundle query cannot bind back to the captured main: selected/available architectures and structured facts are cleared; metadata, DER-query, and final entitlement statuses are `Error`; selected legacy state is `Unobserved`; and the independent all-architecture verification still runs against the validated root. Successful verification then yields `Signed` presence with `ALL_ARCHITECTURES` scope; every other verification outcome leaves presence and scope `Unknown`. Preliminary default-architecture status, presence, metadata, and legacy values are never reconciled into the final inspection. For a direct Mach-O target, a Security signature/artifact rejection is a query outcome rather than an identity failure: independent verification still runs and DER runs because the structurally validated selector remains bound to the retained query file.

After Security.framework returns a documented `kSecCodeInfoMainExecutable`, AegisForge obtains its exact filesystem bytes with bounded `CFURLGetFileSystemRepresentation`; lossy CFString path conversion is forbidden. The path must contain no CR/LF bytes and must identify an absolute, non-symlink regular file. For a Mach-O target the already validated query path is the main executable and any returned main path must identify that same file. For an application bundle the preliminary returned main path is required, its canonical path must be contained under the canonical bundle root, and its identity is captured from a no-follow handle. Every main path returned by the later selected query must then resolve to that exact captured canonical path and identity; another valid Mach-O inside the same bundle is a target-validation failure, not an alternate fact source. The captured main identity is revalidated with both root identities after each later command. DER extraction runs only after this exact expected main-executable path has been established, so an `Executable=` stderr record is never trusted to discover or replace it.

The retained main-executable handle supplies all header bytes through bounded positional reads. A recognized thin 32-bit or 64-bit Mach-O header provides one selector and yields `SINGLE_ARCHITECTURE`. A 32-bit or 64-bit fat header may contain at most 32 entries; checked arithmetic validates its table size and every slice offset/size against the retained file length before selectors are admitted. For every fat entry, AegisForge then reads only that slice's fixed-size inner Mach-O header, requires recognized thin magic, decodes its fields according to that inner magic's byte order, and requires its raw signed CPU type and subtype to equal the decoded outer fat entry exactly. This prevents a forged outer selector from labeling facts extracted from a differently identified inner slice. Duplicate selectors, a zero slice size, overlap with the architecture table, overlap between slice ranges, an out-of-file or too-small slice, an unrecognized/truncated inner header, an outer/inner selector mismatch, an unrecognized/truncated top-level header, or no selector is an error. A valid multi-slice header yields `SELECTED_ARCHITECTURE` plus one bounded incomplete-coverage diagnostic. This scope label and selected selector qualify every reported identity/runtime/entitlement fact.

The two codesign invocations use atomic arguments and the same absolute query path:

```text
/usr/bin/codesign --verify --verbose=4 --all-architectures -- <absolute-path>
/usr/bin/codesign -d --entitlements - --der --architecture <cpu-type>,<cpu-subtype> -- <absolute-path>
```

The obsolete verbose metadata invocation is removed. Each command keeps the hardened runner's 30-second deadline and independent 1 MiB stdout/stderr caps; entitlement stdout is additionally limited to 256 KiB before decoding. Security.framework validation explicitly uses `kSecCSNoNetworkAccess` and has no cancellable deadline API. This remaining in-process latency limitation is explicit; moving the adapter into a supervised helper is deferred unless host testing demonstrates a practical stall.

Unsigned classification is raw-byte exact and is attempted only for a nonzero exit with empty stdout. Stderr must equal:

```text
<exact query-path bytes>: code object is not signed at all\n
```

No bare phrase, lossy UTF-8 comparison, trimming, stdout match, extra line, missing terminator, or CRLF variant is accepted. Other output is a rejection or error, never unsigned evidence.

Successful DER extraction for a Mach-O file accepts stderr only when it is empty or exactly the record below. For an application bundle the exact record is mandatory; empty stderr is not enough to re-bind the path-based codesign query to the captured main executable.

```text
Executable=<exact structured main-executable path bytes>\n
```

This is a full byte comparison, not line parsing. Any successful bundle DER stderr other than that exact record—including empty, mismatching, or additional output—is a main-binding failure: it invalidates the selector/list, clears selected facts, changes metadata, DER-query, and final entitlement statuses to `Error`, and applies the verification-only `ALL_ARCHITECTURES`/`UNKNOWN` rule rather than becoming an ordinary parser diagnostic. DER string contents are never inspected for diagnostics or signature presence.

An initial root-identity failure returns one conservative failed-target inspection without running a native query: `Unknown` presence, verification, metadata, DER-query, and final entitlement statuses all `Error`, no metadata or entitlements, and one target diagnostic. If either root or the captured main-executable identity changes after a native stage, remaining stages stop and the same conservative result replaces every partial observation. A stable-root main-resolution or architecture-classification failure follows the narrower behavior above: all-architecture verification still runs, but selected-slice facts remain unavailable.

These checks reduce, but do not eliminate, path-based time-of-check/time-of-use risk. Security.framework and codesign accept paths rather than retained descriptors. The main executable is captured only after the structured call returns, and bundle resources can still change independently. AegisForge reports bounded sequential observations and does not claim a single immutable bundle snapshot.

## Status Matrix

Verification and structured metadata keep their existing independent statuses. The Security adapter returns two separate sub-results: bounded identity/certificate/runtime metadata and the legacy entitlement state. An invalid legacy sub-result changes only the final entitlement assessment; it does not erase otherwise valid structured metadata. Conversely, a metadata conversion failure does not turn successfully classified legacy data into `Invalid`, although later reconciliation may still clear retained facts.

Structured metadata is `Passed` only after basic validity, successful full copy, and complete metadata type/bound validation. CF values are type-checked in non-overlapping order: CFBoolean before CFNumber; a CFNumber whose `CFNumberIsFloatType` is true is rejected before any `kCFNumberSInt64Type` conversion. Selected `errSecCSUnsigned` is `NotApplicable` and establishes explicit unsigned presence only after any required bundle locator equality check passes. A Mach-O file's successful basic validity positively establishes signed presence even if a later copy or conversion step fails. For a bundle, the positive observation is admitted only after the selected full dictionary has supplied and validated the exact captured main path/identity; a failure before that binding contributes no presence. A successfully copied, main-bound dictionary without `kSecCodeInfoIdentifier` violates the documented API invariant: metadata becomes `Error`, metadata facts are cleared, and the already bound positive basic-validity observation is preserved. It is not treated as unsigned or `NotApplicable`.

Those status and presence rules apply to the explicitly selected structured query only after the bundle main-binding gate passes. The bundle preliminary operation is a main-path resolution mechanism only: none of its status, presence, metadata, certificate, runtime, or legacy observations are exposed or reconciled. A preliminary or selected bundle binding failure is reported as the selector-resolution `Error` described above while verification still runs independently.

After the applicable target/main binding gate passes, only this audited artifact-rejection allowlist maps a Security OSStatus to `Failed`: `errSecCSSignatureFailed`, `errSecCSSignatureUnsupported`, `errSecCSBadDictionaryFormat`, `errSecCSReqInvalid`, `errSecCSReqUnsupported`, `errSecCSReqFailed`, `errSecCSBadObjectFormat`, `errSecCSSignatureInvalid`, `errSecCSInfoPlistFailed`, `errSecCSNoMainExecutable`, `errSecCSBadMainExecutable`, `errSecCSBadBundleFormat`, `errSecCSInvalidPlatform`, `errSecCSTooBig`, `errSecCSInvalidSymlink`, `errSecCSBadDiskImageFormat`, `errSecCSUnsupportedDigestAlgorithm`, `errSecCSInvalidAssociatedFileData`, `errSecCSInvalidTeamIdentifier`, `errSecCSBadTeamIdentifier`, `errSecCSSignatureUntrusted`, `errSecMultipleExecSegments`, `errSecCSInvalidEntitlements`, `errSecCSInvalidRuntimeVersion`, and `errSecCSRevokedNotarization`. An unbound selected bundle query remains orchestrator `Error` regardless of its raw OSStatus. Every other non-success status—including allocation, internal-component, invalid-reference, invalid-flag, missing-pointer, permission/readability, cancellation, and database failures—maps to `Error`. Local FFI/type/bound failures are also `Error`; the non-macOS adapter is `Unavailable`. No partial metadata facts survive a metadata error.

The DER-query status and final entitlement assessment are:

| DER command/result | DER status | Legacy state | Final entitlement status and facts |
|---|---|---|---|
| Main/architecture selection or selected-bundle binding unavailable; DER not run | `Error` | `Unobserved` | `Error`, no facts; independent verification remains truthful |
| Success, valid dictionary, benign stderr | `Passed` | `Absent`, `Unobserved`, or equal `Valid` | `Passed`, DER facts |
| Success, valid dictionary, benign stderr | `Passed` | different `Valid` or `Invalid` | `Error`, no facts |
| Success, exactly empty stdout, benign stderr | `NotApplicable` | `Absent` or `Unobserved` | `NotApplicable`, no facts |
| Success, exactly empty stdout, benign stderr | `NotApplicable` | `Valid` or `Invalid` | `Error`, no facts |
| Nonzero, exact unsigned bytes | `NotApplicable` | `Absent` or `Unobserved` | `NotApplicable`, explicit unsigned observation, no facts |
| Nonzero, exact unsigned bytes | `NotApplicable` | `Valid` or `Invalid` | `Error`, explicit unsigned observation, no facts |
| Nonzero, other bounded output | `Failed` | `Absent` or `Unobserved` | `Failed`, no facts |
| Runner unavailable | `Unavailable` | `Absent` or `Unobserved` | `Unavailable`, no facts |
| Runner I/O/timeout/output-cap failure | `Error` | `Absent` or `Unobserved` | `Error`, no facts |
| Malformed/over-limit/non-benign output | `Error` | `Absent` or `Unobserved` | `Error`, no facts |
| DER status `Failed`, `Unavailable`, or `Error` | unchanged | `Valid` | `Error`, legacy compatibility facts and source |
| Any DER result | independently truthful | `Invalid` | `Error`, no facts |

`Failed` is reserved for an executed native command that rejects the request with otherwise bounded output. `Unavailable` means the command could not be executed. Runner, parser, framing, FFI, and bound failures are `Error`. Exactly empty stdout establishes no entitlements only for a successful primary DER query with benign stderr and an `Absent` or `Unobserved` legacy state. The final status never rewrites `der_entitlements_status`; a diagnostic records the comparison whenever the two statuses differ.

## Presence Reconciliation

Presence reconciliation is scope-aware. Verification status always describes the explicit all-architecture query; selected Security.framework and DER observations describe only the selected slice.

1. With `SINGLE_ARCHITECTURE`, successful verification, successful selected basic validity, accepted valid DER, or accepted zero-byte/benign DER absence establishes positive signed presence. An exact verification, Security.framework, or DER unsigned result establishes explicit unsigned presence for that same slice.
2. With `SELECTED_ARCHITECTURE`, successful all-architecture verification still establishes positive presence for the selected slice. Selected Security.framework and accepted DER outcomes contribute positive or explicit-unsigned observations as above. An all-architecture exact-unsigned result means only that at least one slice is unsigned: it remains truthful verification status but never becomes an explicit-unsigned observation for the selected slice. A bounded diagnostic explains that it cannot be attributed.
3. With no safe selector, only successful all-architecture verification establishes `Signed` presence and changes scope to `ALL_ARCHITECTURES`. Failed, unavailable, erroneous, or exact-unsigned verification leaves presence and scope `Unknown`; AegisForge cannot infer that every architecture is unsigned.
4. Positive signed plus explicit unsigned within the same fact scope becomes `Unknown` and adds one disagreement diagnostic. Observations from different scopes are not treated as contradictions.
5. A same-scope contradiction or a selected slice finally classified `Unsigned` clears selected identity, certificate/runtime metadata, and all entitlements while preserving verification, metadata, and DER-query statuses plus the truthful final entitlement assessment.
6. Legacy compatibility values never establish signed presence and survive only when a same-scope query establishes uncontradicted `Signed` presence. DER/legacy disagreement clears entitlement facts even if other selected signature metadata remains usable.

An exit-zero DER command whose payload, stderr framing, size, or structure is rejected does not establish positive signed presence. Native exit success alone is not enough; the result must be one of the two accepted successful DER outcomes above.

Entitlement values never affect signature kind, hardened-runtime interpretation, evidence, verdict, or artifact summary counts.

## Platform Behavior

On macOS, the production inspector combines the structured adapter and bounded commands. On non-macOS targets, the stub returns `Unavailable` for verification, metadata, the DER query, and the final entitlement assessment, with empty facts and the existing single platform-unavailable diagnostic. The pure DER decoder, model normalization, orchestration, and reporting remain platform-independent and unit-tested.

## Text Reporting

Each signature entry labels presence/facts and verification with their different scopes:

```text
  <path> | presence: SIGNED (SINGLE_ARCHITECTURE) | verification (ALL_ARCHITECTURES): PASSED | metadata: PASSED | kind: AD_HOC
  Architecture: selected arm64 (16777228,0) | available: arm64 (16777228,0)
  Entitlements: PASSED | DER query: PASSED | source: CODESIGN_DER_OUTPUT
    - "com.apple.security.app-sandbox" = true
```

`UNKNOWN` and `ALL_ARCHITECTURES` render selected and available architecture as `not available`. A `SELECTED_ARCHITECTURE` entry always renders every available selector and the bounded uninspected-slice diagnostic. Thus no unqualified `Signed` or `Unsigned` label can be mistaken for a whole universal file.

When compatibility facts are retained, the line visibly reads `Entitlements: ERROR | DER query: <status> | source: LEGACY_PROPERTY_LIST_NON_AUTHORITATIVE`. Source is `not available` only when `entitlement_source` is `None`, not merely when the entry vector is empty. A successfully parsed empty DER dictionary remains `PASSED | DER query: PASSED | source: CODESIGN_DER_OUTPUT` and renders no entry lines; it is distinct from zero-byte absence.

Values use deterministic compact plist-like notation: booleans and base-10 numbers are unquoted; strings and dictionary keys are quoted; data is lowercase hexadecimal inside `data(...)`; arrays preserve order as `[value, value]`; nested dictionaries use sorted entries as `{"key": value, "key": value}`. Separators are exactly comma plus one ASCII space.

Entitlement keys and string values use an ASCII-only, one-pass escape: quote and backslash are escaped, printable ASCII is preserved, and every other Unicode scalar is emitted with uppercase hexadecimal as `\u{XXXX}` (at least four digits, expanding only when the scalar requires more). This neutralizes control characters, line separators, bidirectional controls, zero-width characters, combining marks, and natural right-to-left text. Structured identifier, team, and authority strings use the same security-text escape. Paths keep the existing lossless OS-string escape. Writer failures propagate as `io::Result` without panics.

## Required Tests

Implementation follows red-green-refactor cycles. Automated coverage includes:

- captured DER dictionaries with booleans, negative and boundary integers, strings, data, arrays, nested dictionaries, and the six initially interesting keys;
- empty dictionary versus exactly zero-byte no-entitlement output;
- schema tags/version, typed scalar canonicality, complete consumption, duplicate keys, non-dictionary roots, unsupported tags, integer overflow, and trailing bytes;
- deterministic nested sorting and array order;
- the hostile abstract string proving only the real key exists;
- Security.framework type conversion, null/type failures, retained-reference cleanup, exact zero create flags and numeric architecture/subarchitecture attributes, exact `kSecCSBasicValidateOnly | kSecCSNoNetworkAccess` validation flags, exact preliminary and selected-unsigned `kSecCSDefaultFlags` path-only copy flags, exact selected-success `kSecCSSigningInformation` facts-copy flags, CFBoolean-before-CFNumber handling, float-number rejection, flag mapping, certificate bounds, both one-key-only legacy combinations, raw envelope/length/format checks, XML/binary provenance, unsupported property-list values, and DER/legacy equality or mismatch;
- a shared-reference graph, a cycle, depth/node/materialized limits, checked arithmetic, and many common-prefix keys;
- exact program/arguments, spaces/metacharacters, absolute normalized path, numeric `--architecture` selector for DER, explicit `--all-architectures` and no `--architecture` on verification, and `--` for both commands;
- raw-byte unsigned matching: nonzero only, stderr only, exact target and LF only; signed stdout/DER strings and extra or injected lines never classify unsigned;
- signed filenames and signed identifiers containing forged metadata/unsigned records, proving no human-readable record becomes a fact;
- preliminary bundle call ordering, exact success/`errSecCSUnsigned` path-only copy continuation, short-circuiting of every other preliminary rejection, and continued verification after selected-query errors;
- exact DER stderr rules: bundle success requires `Executable=<captured-main>\n`; empty, mismatching, or additional bundle stderr clears selector/list/facts and falls back to verification-only `ALL_ARCHITECTURES`/`UNKNOWN`, while direct Mach-O success accepts empty stderr or the exact bound record; plus rejection of relative, symlink, non-regular, outside-bundle, wrong-Mach-O-identity, oversized, and CR/LF main paths and of any `Executable=` record when no validated expected main path exists;
- selected-query main-path equality with the captured preliminary path and identity after either success or exact unsigned, including rejection of an unsigned A-to-B rebind, a different valid in-bundle Mach-O, and the same path with a changed identity; every pre-binding failure clears selectors/facts, suppresses DER, and permits only verification-driven `ALL_ARCHITECTURES` or `UNKNOWN` scope;
- lossless bounded CFURL filesystem-byte conversion; thin/fat architecture parsing; the 32-entry cap; duplicate, truncated, overlapping-table, overlapping-slice, zero-size, overflow, and out-of-file slice rejection; bounded inner-header reads; non-Mach-O/truncated-inner and outer/inner CPU-selector mismatch rejection; deterministic signed-numeric selector sorting; and unknown-scope fact withholding while independent verification still runs;
- a two-slice universal fixture with different valid entitlements, proving verification is all-architecture while both fact sources receive the same explicit selector and the report is visibly `SELECTED_ARCHITECTURE` with every uninspected selector named;
- mixed signed/unsigned fat fixtures proving selected unsigned plus failed verification is selected-scope `Unsigned`, selected signed plus all-architecture exact-unsigned remains selected-scope `Signed`, and all-architecture unsigned with no selector remains `Unknown`;
- a matched outer/inner subtype mutation for which selected basic validity succeeds but all-architecture verification fails, plus a structurally valid outer-alignment mutation for which verification still passes, proving only authenticated inner CPU fields—not the outer fat table—can upgrade selector trust;
- exact `NativeFactScope` field invariants for unknown, all-architecture, thin, and universal results;
- root replacement after every stage and main-executable replacement after resolution, with later calls suppressed and all facts discarded;
- every row of the status matrix, including all four legacy states, retained non-authoritative context, dual-slot disagreement, and preservation of the separate DER-query status;
- independent structured metadata and legacy sub-results, Mach-O successful-basic-validity/later-copy failure, bundle pre-binding copy failure without a positive observation, and the post-binding missing-identifier invariant error;
- Security OSStatus classification for unsigned, every allowlisted artifact rejection, and representative allocation/internal/programming/permission errors;
- contradiction clearing that removes entries and `entitlement_source` without rewriting independent or final statuses;
- one failed target not stopping later targets and fake-inspector path/kind sanitization clearing seeded entitlement facts;
- exact ASCII-only reporting for controls, bidi, zero-width, combining, RTL, quote, and backslash content; the conservative output bound; writer failures;
- no entitlement-derived evidence, verdict, or summary change;
- non-macOS unavailable behavior;
- full locked/offline build, test, format, strict Clippy, regression-script, and diff gates.

Read-only macOS smoke validation covers the built `af`, one modern DER-backed app, one legacy XML-backed app, an unsigned harmless file, a disposable hostile-string entitlement, and a disposable hostile signing identifier. Temporary signed fixtures are isolated and removed. Host observations are reported rather than encoded as portable trust expectations.

## Security and Product Invariants

- The inspected artifact is never executed or modified.
- No shell, environment mutation, working-directory change, private Security.framework key, or internal signing-information flag is introduced.
- Human-readable codesign metadata and abstract entitlement text never become structured facts.
- Universal targets never imply whole-file metadata or entitlement coverage; whenever selected facts are retained, the deterministic selected slice and every available selector are explicit in both typed results and text output.
- Selected-slice metadata facts are copied only after selected basic signature validity succeeds. Default-flags path-only copies after preliminary success/unsigned and selected-bundle unsigned are locator checks only and never contribute metadata or entitlement facts; selected unsigned is admitted only after its locator matches the captured main identity.
- Native output and every Rust-owned collection, value, diagnostic, and rendered entitlement segment are bounded; Security.framework's documented in-process parsing remains an explicit trusted native boundary.
- Malformed or truncated data never becomes partial authoritative facts.
- Legacy compatibility values are visibly non-authoritative and never override or contradict DER.
- Entitlement absence, extraction failure, and unsigned state remain distinct.
- Entitlements are context only and create no evidence or verdict change.
- Application-bundle contents continue through ordinary recursive static analysis.
- One native-target failure does not stop later targets.
- External path and bundle-internal races remain outside the claimed snapshot boundary.
- Homebrew and release packaging remain V0.2.

## Commit and Push Policy

The approved design and implementation plan are committed and pushed separately before implementation. The completed module is committed as:

```text
feat(macos): inspect code-signing entitlements
```

It is pushed to `origin/feature/entitlement-inspection` only after focused tests, full gates, macOS smoke validation, and independent review pass. The completed native-command-hardening and CLI-skeleton branches remain unchanged.

## Deferred Work

Later V0.1 modules remain responsible for per-architecture signature/entitlement extraction for universal binaries, Gatekeeper/system-policy assessment, supportable notarization evidence, quarantine metadata, macOS trust aggregation, and conservative combination-based native-trust evidence. Moving Security.framework calls into a separately supervised helper is deferred unless bounded host testing demonstrates a practical stall. JSON reporting and related CLI flags remain later roadmap work. Homebrew remains V0.2.
