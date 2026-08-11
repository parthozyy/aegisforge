# Code-Signing Entitlement Inspection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace injectable human-readable code-signing metadata with structured Security.framework facts, extract one explicitly selected Mach-O slice's CoreEntitlements DER safely, and report bounded entitlement context without changing evidence or verdicts.

**Architecture:** A platform-independent entitlement module owns the bounded typed tree, normalization, DER decoder, and DER/legacy reconciliation. `codesign.rs` owns retained-handle architecture selection, target identity, exact raw native-output classification, scope-aware presence reconciliation, and orchestration through an injected high-level Security provider. A macOS-only `security_info.rs` confines Security.framework FFI, CoreFoundation ownership, structured conversion, and legacy-slot observation; the scanner continues to treat the resulting inspection as context, and the text reporter streams deterministic escaped output.

**Tech Stack:** Rust 2024, `der = "=0.7.10"` borrowed decoding APIs, macOS Security.framework and `core-foundation-sys = "=0.8.7"`, the existing bounded native-command runner, retained Unix file handles with positional reads, in-source unit fixtures, and locked/offline Cargo gates.

**Specification:** `docs/superpowers/specs/2026-08-09-code-signing-entitlements-design.md` at approved SHA-256 `95581d11a7c748f58c93eacf86d8618305cf7e4026d3f47ff8b2d7a7febb549f`.

---

## Execution and Commit Discipline

- Use `@superpowers:test-driven-development` for every production change: add a focused failing test, record the intended RED, implement only enough to turn it GREEN, then refactor while green.
- Use `@superpowers:requesting-code-review` after each implementation task and resolve every Critical or Important finding before committing.
- Run each task's focused tests, the full locked/offline suite, formatting, strict Clippy, and `git diff --check` before its commit.
- A private helper introduced before Task 6 wires its production caller may carry only an item-level `#[cfg_attr(not(test), allow(dead_code))]`; record it in that task and remove every such staging allowance in Task 6. Never apply a module-wide or unrelated lint suppression.
- Commit and push each coherent submodule separately to `origin/feature/entitlement-inspection`; do not batch unrelated work or squash the history.
- The final orchestration commit keeps the specification's required message `feat(macos): inspect code-signing entitlements`. Support commits precede it and remain independently buildable.
- Do not modify, merge, tag, or release `feature/cli-skeleton` or `feature/native-command-hardening`. Do not add Homebrew work.

## File Structure

- Create `src/macos/entitlements.rs`: public entitlement value/source types; checked resource budget; CoreEntitlements DER decoder; legacy observation types; DER/legacy final assessment.
- Create `src/macos/security_info.rs`: macOS-only Security.framework adapter, low-level test seam, CoreFoundation RAII, public-key extraction, main-path conversion, structured metadata, legacy conversion, and OSStatus classification.
- Modify `src/macos/mod.rs`: export the platform-independent entitlement module and register the macOS-only Security adapter privately.
- Modify `src/macos/codesign.rs`: extend the public inspection model; parse/select architectures from a retained handle; validate root/main identity; define the high-level Security provider seam; remove verbose metadata text parsing; invoke verification and DER commands; reconcile statuses, presence, scope, and facts.
- Modify `src/report/text.rs`: render scope/architecture/entitlement fields; add streaming ASCII-only security-text escaping and bounded recursive value output.
- Modify `src/scanner/scan.rs`: strengthen mismatched-inspector sanitization and prove entitlements remain context-only.
- Modify `Cargo.toml` and `Cargo.lock`: add only the two exact direct dependencies already present transitively in the lockfile.

The implementation must not change `src/macos/command.rs`, evidence or verdict models, summary counting, CLI arguments, discovery, JSON output, or release packaging.

---

### Task 1: Add the Bounded Entitlement and Fact-Scope Model

**Files:**

- Create: `src/macos/entitlements.rs`
- Modify: `src/macos/mod.rs`
- Modify: `src/macos/codesign.rs:1-112`
- Modify: `src/report/text.rs:433-447`
- Modify: `Cargo.toml:11-20`
- Modify: `Cargo.lock:21-30`
- Test: `src/macos/entitlements.rs`
- Test: `src/macos/codesign.rs`

- [ ] **Step 1: Add exact dependencies and refresh only the root lock entry**

Add:

```toml
[dependencies]
der = "=0.7.10"

[target.'cfg(target_os = "macos")'.dependencies]
core-foundation-sys = "=0.8.7"
```

Keep the existing dependencies and Unix `libc` section unchanged. Run once without `--locked` because making already-locked transitive crates direct changes the root package dependency list:

```text
YRX_REGENERATE_MODULES_RS=false cargo check --offline
git diff -- Cargo.toml Cargo.lock
```

Expected: Cargo resolves entirely offline; no new package record appears; only the root `aegisforge` dependency list gains `der` and target-specific `core-foundation-sys`.

- [ ] **Step 2: Write failing model/default/limit tests**

Register `pub mod entitlements;` in `src/macos/mod.rs`. In `entitlements.rs`, add tests first for stable source labels, structural equality, sorted dictionary construction, array-order preservation, checked budget counters, and every exact boundary. In `codesign.rs`, add tests that `unknown()` clears every new field and that all four fact scopes obey their field invariants.

Replace the reporter's direct `CodeSignatureInspection { ... }` test fixture with `CodeSignatureInspection::unknown(...)` followed by explicit assignments for only the facts that fixture needs. This keeps Task 1 and later model extensions compiling without changing report behavior.

The intended public types are:

```rust
pub const MAX_ENTITLEMENT_BYTES: usize = 256 * 1024;
pub const MAX_ENTITLEMENT_DEPTH: usize = 32;
pub const MAX_ENTITLEMENT_NODES: usize = 4_096;
pub const MAX_ENTITLEMENT_MATERIALIZED_BYTES: usize = 256 * 1024;
pub const MAX_ENTITLEMENT_REPORT_BYTES: usize = 3 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementEntry {
    pub key: String,
    pub value: EntitlementValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntitlementValue {
    Boolean(bool),
    SignedInteger(i64),
    UnsignedInteger(u64),
    String(String),
    Data(Vec<u8>),
    Array(Vec<EntitlementValue>),
    Dictionary(Vec<EntitlementEntry>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntitlementSource {
    CodesignDerOutput,
    LegacyPropertyListNonAuthoritative,
}
```

Extend the signature model with:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeFactScope {
    AllArchitectures,
    SingleArchitecture,
    SelectedArchitecture,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CodeSignatureArchitecture {
    pub cpu_type: i32,
    pub cpu_subtype: i32,
    pub display_label: String,
}
```

`CodeSignatureArchitecture::codesign_selector()` must return `format!("{},{}", cpu_type, cpu_subtype)`. Known labels may use Goblin only for display after masking capability bits; raw signed values remain stored, sorted, compared, and passed to codesign unchanged. Unknown labels include the numeric pair deterministically.

Add these fields to `CodeSignatureInspection`:

```rust
pub native_fact_scope: NativeFactScope,
pub selected_architecture: Option<CodeSignatureArchitecture>,
pub available_architectures: Vec<CodeSignatureArchitecture>,
pub der_entitlements_status: NativeCheckStatus,
pub entitlements_status: NativeCheckStatus,
pub entitlement_source: Option<EntitlementSource>,
pub entitlements: Vec<EntitlementEntry>,
```

`unknown()` uses `Unknown`, no selector/list/facts/source, and `Error` for verification, metadata, DER, and final entitlement status. Stable labels are exactly the specification's uppercase names.

- [ ] **Step 3: Run focused tests to verify RED**

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::entitlements::tests -- --nocapture
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::codesign::tests::unknown_inspection_uses_conservative_defaults -- --exact --nocapture
```

Expected: compilation fails for the missing model, label methods, inspection fields, and budget type. Zero matching tests is not an acceptable RED.

- [ ] **Step 4: Implement the model and reusable checked budget**

Add a crate-visible budget shared by DER and CoreFoundation conversion:

```rust
pub(crate) struct EntitlementBudget {
    nodes: usize,
    materialized_bytes: usize,
}

impl EntitlementBudget {
    pub(crate) fn new() -> Self;
    pub(crate) fn enter_value(&mut self, depth: usize) -> Result<(), String>;
    pub(crate) fn enter_dictionary_entry(&mut self) -> Result<(), String>;
    pub(crate) fn charge_materialized(&mut self, bytes: usize) -> Result<(), String>;
}
```

Use `checked_add` for every counter. Count the root dictionary as a value at depth 1; every value as one node; every dictionary entry as an additional node; key/string/data bytes before cloning; booleans as one byte; integers as eight bytes. Build dictionaries through `BTreeMap::entry`, reject duplicates, and convert with `into_iter()` for deterministic order.

Until the DER and Security conversion tasks consume the private budget in production, place an item-level `#[cfg_attr(not(test), allow(dead_code))]` only on the staged budget type/implementation. Task 6 must remove it.

Add a private invariant checker used by constructors/reconciliation tests:

- `Unknown` and `AllArchitectures`: no selected/available architectures and no selected facts.
- `SingleArchitecture`: exactly one available selector equal to selected.
- `SelectedArchitecture`: at least two available selectors containing selected.

- [ ] **Step 5: Run GREEN and regression gates**

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::entitlements::tests
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::codesign::tests
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
cargo fmt --all -- --check
YRX_REGENERATE_MODULES_RS=false cargo clippy --all-targets --all-features --locked --offline -- -D warnings
git diff --check
```

Expected: all focused and full tests pass; no warning or formatting/diff error.

- [ ] **Step 6: Review, commit, and push the model module**

After independent spec/code-quality review reports no Critical or Important issue:

```text
git add Cargo.toml Cargo.lock src/macos/mod.rs src/macos/entitlements.rs src/macos/codesign.rs src/report/text.rs
git commit -m "feat(macos): model entitlement inspection"
git push origin feature/entitlement-inspection
```

---

### Task 2: Decode CoreEntitlements DER with Strict Bounds

**Files:**

- Modify: `src/macos/entitlements.rs`
- Test: `src/macos/entitlements.rs`

- [ ] **Step 1: Add an independent test-only DER fixture builder**

Create test helpers that emit shortest-form TLV lengths without using RustCrypto's encoder:

```rust
fn der_length(length: usize) -> Vec<u8>;
fn tlv(tag: u8, content: &[u8]) -> Vec<u8>;
fn utf8(value: &str) -> Vec<u8>;
fn entry(key: &str, value: Vec<u8>) -> Vec<u8>;
fn dictionary(entries: Vec<Vec<u8>>) -> Vec<u8>; // tag 0xB0
fn document(entries: Vec<Vec<u8>>) -> Vec<u8>;   // tag 0x70, INTEGER 1
```

Add fixtures for the six interesting keys, empty dictionary (`70 05 02 01 01 B0 00`), booleans, negative/i64/u64 boundaries, UTF-8 string, octet data, array, nested dictionary, hostile abstract `[Key]` injection text, and deliberately unsorted nested dictionaries.

- [ ] **Step 2: Add failing strictness and budget tests**

Cover:

- exact application/context/sequence tags and schema version 1;
- primitive versus constructed tag mistakes;
- noncanonical length, BOOLEAN, and INTEGER encodings;
- missing/extra entry members and incomplete nested consumption;
- duplicate keys and unsupported tags;
- integer values below `i64::MIN` or above `u64::MAX`;
- top-level trailing bytes and non-dictionary roots;
- empty input and `MAX_ENTITLEMENT_BYTES + 1`;
- depth 32 pass/depth 33 fail;
- exactly 4,096 nodes pass/one more fail;
- exactly 256 KiB cumulative materialized bytes pass/one more byte fail;
- hundreds of common-prefix keys without quadratic duplicate checks;
- nested dictionaries sorted at every level and arrays retaining order.

- [ ] **Step 3: Run the DER tests to verify RED**

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::entitlements::tests::der_ -- --nocapture
```

Expected: the new tests compile against the model but fail because `decode_der_entitlements` is missing. Zero matching tests is not acceptable.

- [ ] **Step 4: Implement the borrowed strict decoder**

Use only no-feature borrowed APIs:

```rust
use der::{
    asn1::{AnyRef, OctetStringRef, Utf8StringRef},
    Decode, Reader, SliceReader, Tag, TagNumber, Tagged,
};

pub(crate) fn decode_der_entitlements(
    bytes: &[u8],
) -> Result<Vec<EntitlementEntry>, String>;
```

Algorithm:

1. Reject empty or over-256-KiB input.
2. Parse the complete document with `AnyRef::from_der(bytes)` and require `TagNumber::N16.application(true)`.
3. Enter a fresh `SliceReader`, decode typed version `u8 == 1`, decode exactly one constructed `TagNumber::N16.context_specific(true)` dictionary, and call `finish(())`.
4. For each dictionary entry, charge the entry node, require `Tag::Sequence`, decode exactly one `Utf8StringRef` key plus one value, finish the entry reader, and insert through `BTreeMap::entry`.
5. Decode `BOOLEAN` as `bool`, `UTF8STRING` as `Utf8StringRef`, and `OCTET STRING` as `OctetStringRef`; charge before copying.
6. For INTEGER, inspect the first content octet. Negative encodings decode only as `i64`; nonnegative encodings try `i64` then `u64`. Normalize `0..=i64::MAX` to `SignedInteger` and only larger positives to `UnsignedInteger`.
7. Decode `SEQUENCE` recursively as an ordered array and constructed context tag 16 as a sorted dictionary; finish every entered reader.
8. Reject every unknown tag and any partially consumed reader.

Never accept `AnyRef::value()` directly as a scalar; typed decoders provide canonical BOOLEAN, INTEGER, UTF-8, and OCTET validation.

Until Task 6 calls the decoder from the production DER assessment, place an item-level `#[cfg_attr(not(test), allow(dead_code))]` only on `decode_der_entitlements`. Task 6 must remove it.

- [ ] **Step 5: Run GREEN and regression gates**

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::entitlements::tests -- --nocapture
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
cargo fmt --all -- --check
YRX_REGENERATE_MODULES_RS=false cargo clippy --all-targets --all-features --locked --offline -- -D warnings
git diff --check
```

- [ ] **Step 6: Review, commit, and push the DER module**

```text
git add src/macos/entitlements.rs
git commit -m "feat(macos): decode CoreEntitlements DER"
git push origin feature/entitlement-inspection
```

---

### Task 3: Select and Bind a Mach-O Architecture from One Retained Handle

**Files:**

- Modify: `src/macos/codesign.rs`
- Test: `src/macos/codesign.rs`

- [ ] **Step 1: Add byte-backed positional-read and Mach-O fixture helpers**

Add a private production seam and test implementation:

```rust
trait PositionalRead {
    fn file_len(&self) -> std::io::Result<u64>;
    fn read_exact_at(&self, offset: u64, destination: &mut [u8]) -> std::io::Result<()>;
}
```

The Unix `File` implementation uses `std::os::unix::fs::FileExt::read_exact_at`. Test builders emit thin32/thin64 in both byte orders and fat32/fat64 tables with independently chosen inner byte order. A logging reader records every requested range.

- [ ] **Step 2: Add failing architecture tests**

Cover all exact magic forms:

| Bytes | Form | Order |
|---|---|---|
| `FE ED FA CE` | thin32 | big |
| `CE FA ED FE` | thin32 | little |
| `FE ED FA CF` | thin64 | big |
| `CF FA ED FE` | thin64 | little |
| `CA FE BA BE` | fat32 | big |
| `BE BA FE CA` | fat32 | little |
| `CA FE BA BF` | fat64 | big |
| `BF BA FE CA` | fat64 | little |

Test 0, 1, 32, and 33 fat entries; one-entry fat as `SingleArchitecture`; duplicates; signed-numeric selector sorting; capability-bit preservation; zero/too-small/out-of-file slices; checked offset/size/table overflow; table and slice overlap; valid adjacency; bad alignment exponent or divisibility; nonzero fat64 reserved; truncated/non-Mach-O inner header; and raw outer/inner CPU or subtype mismatch. Prove the logging reader accesses only the outer header/table and fixed 28/32-byte inner headers.

Add a Unix replacement test: open a complete Mach-O with `O_NOFOLLOW | O_NONBLOCK`, replace its path, and prove parsing still observes the original retained handle.

- [ ] **Step 3: Run focused architecture tests to verify RED**

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::codesign::architecture_tests -- --nocapture
```

Expected: compile failure for the parser/selection seam and then assertion failures for unsupported formats during incremental implementation.

- [ ] **Step 4: Implement bounded thin/fat parsing**

Add:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
struct MachOArchitectureSelection {
    selected: CodeSignatureArchitecture,
    available: Vec<CodeSignatureArchitecture>,
}

fn parse_macho_architectures<R: PositionalRead>(
    reader: &R,
) -> Result<MachOArchitectureSelection, String>;
```

Rules:

- thin headers are fixed 28 or 32 bytes; decode raw signed CPU fields at offsets 4 and 8 in the header's own byte order;
- fat32 table size is `8 + 20*n`, fat64 is `8 + 32*n`, with `1..=32` entries checked before reading into a fixed maximum stack buffer;
- require nonzero slices wholly inside the retained file and after the table; reject overlapping sorted ranges;
- validate `1_u64.checked_shl(align)` and `offset % alignment == 0`; reject nonzero fat64 `reserved`;
- require every declared slice to contain its entire fixed inner thin header; derive inner byte order from inner magic; compare raw signed outer/inner CPU pairs exactly;
- reject duplicate pairs with `BTreeSet`; sort public architectures by raw `(i32, i32)` and select index zero;
- one selector, including one-entry fat, is `SingleArchitecture`; two or more is `SelectedArchitecture`.

Goblin may supply a friendly display label only after masking subtype capability bits for lookup. Never use Goblin's fat parser or masked subtype for equality, ordering, or codesign arguments.

Until Task 6 consumes the private positional parser in production, use item-level `#[cfg_attr(not(test), allow(dead_code))]` only on the staged parser/read seam. Task 6 must remove it.

- [ ] **Step 5: Run GREEN and regression gates**

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::codesign::architecture_tests -- --nocapture
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
cargo fmt --all -- --check
YRX_REGENERATE_MODULES_RS=false cargo clippy --all-targets --all-features --locked --offline -- -D warnings
git diff --check
```

- [ ] **Step 6: Review, commit, and push architecture binding**

```text
git add src/macos/codesign.rs
git commit -m "feat(macos): bind code-signature architectures"
git push origin feature/entitlement-inspection
```

---

### Task 4: Read Structured Security.framework Signing Information

**Files:**

- Create: `src/macos/security_info.rs`
- Modify: `src/macos/mod.rs`
- Modify: `src/macos/codesign.rs`
- Modify: `src/macos/entitlements.rs`
- Test: `src/macos/security_info.rs`
- Test: `src/macos/entitlements.rs`

- [ ] **Step 1: Define the high-level provider and observation seam**

Keep command/orchestration fakes independent from raw CF pointers:

```rust
pub(crate) trait SecurityInfoProvider {
    fn resolve_bundle_main(&self, bundle: &Path) -> PreliminarySecurityObservation;
    fn inspect_selected(
        &self,
        request: &SelectedSecurityRequest<'_>,
        bind_main: &mut dyn FnMut(&Path) -> Result<(), String>,
    ) -> SelectedSecurityObservation;
}
```

`CodesignInspector<R, S>` is `pub(crate)` with `R: NativeCommandRunner` and `S: SecurityInfoProvider`, avoiding a public private-bound lint. Separate selected observation components so tests can represent:

- direct Mach-O basic success followed by copy failure: signed observation survives;
- bundle failure before selected main binding: no positive observation survives;
- bundle main binding followed by later metadata conversion failure: positive observation survives;
- metadata conversion and legacy conversion succeeding/failing independently.

The callback forces the real adapter to extract and bind a bundle's selected `MainExecutable` before reading any other copied field.

- [ ] **Step 2: Write failing provider/flags/status/ownership tests**

Add a macOS-only low-level `SecurityApi` seam for create/check/copy/certificate-summary calls and RAII drop counters. Test exact sequences and flags:

- preliminary create flags `0`, check flags `0x2000_0006`, then copy flags `0` only after success or `errSecCSUnsigned`;
- selected create-with-attributes flags `0`, signed SInt32 architecture/subarchitecture attributes, check flags `0x2000_0006`;
- selected success copies with `kSecCSSigningInformation == 2`;
- selected unsigned bundle copies main-only with flags `0`; selected unsigned direct Mach-O performs no copy;
- no-network flags never reach a copy call;
- every create/copy out-pointer starts null and null-on-success is an error;
- each retained reference is released exactly once on success and every error exit; borrowed dictionary/array values and exported constants are never released.

Test OSStatus mapping: `errSecCSUnsigned == -67062`; the exact 25-code artifact allowlist below maps to `Failed`; representative allocation/internal/invalid-flag/permission/readability/cancellation/database statuses map to `Error`:

```text
-67061 -67059 -67058 -67052 -67051 -67050 -67049 -67045
-67030 -67029 -67028 -67010 -67005 -67004 -67003 -67001
-67000 -66999 -66998 -66997 -66996 -66995 -66994 -66993
-66992
```

- [ ] **Step 3: Write failing structured conversion and legacy tests**

Using actual test CF objects behind the low-level seam, cover exact type IDs; Boolean-before-Number; floating-number rejection; failed integer conversion; required `kSecCodeInfoFlags`; ad-hoc/runtime bits; required identifier and optional team; certificate count 64 and aggregate metadata 64 KiB; null/type errors; bounded lossless CFURL bytes; CR/LF/relative/oversized main paths; shared references charged on every occurrence; active-container cycles; depth/node/materialized limits; and common-prefix dictionary keys. A successfully copied and main-bound full dictionary with a missing, null, wrong-type, empty, or over-budget identifier is metadata `Error`, clears metadata facts, and preserves the already bound positive basic-validity observation.

Legacy coverage must distinguish:

```rust
pub(crate) enum LegacyEntitlementObservation {
    Absent,
    Valid { format: LegacyFormat, entries: Vec<EntitlementEntry> },
    Invalid { reason: String },
    Unobserved { reason: String },
}
```

Test both keys absent, raw-only, dictionary-only, wrong types, 256-KiB raw bound, exact `FA DE 71 71` header and big-endian total length, `bplist00`, UTF-8 BOM plus allowed XML whitespace then `<?xml`/`<plist`, unknown prefix/encoding, unsupported CF values, and conversion failures. Once a bound full dictionary exposes either legacy key, every failure is `Invalid`, never `Unobserved`.

- [ ] **Step 4: Run focused tests to verify RED**

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::security_info::tests -- --nocapture
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::entitlements::tests::structured_ -- --nocapture
```

Expected: compile failure for the provider/FFI/conversion seams. The non-macOS build must still compile because framework symbols remain exactly macOS-gated.

- [ ] **Step 5: Implement the confined macOS FFI adapter**

Declare only these public Security.framework functions in one `unsafe extern "C"` block carrying the exact macOS framework link attribute `#[link(name = "Security", kind = "framework")]`:

```text
SecStaticCodeCreateWithPath
SecStaticCodeCreateWithPathAndAttributes
SecStaticCodeCheckValidity
SecCodeCopySigningInformation
SecStaticCodeGetTypeID
SecCertificateGetTypeID
SecCertificateCopySubjectSummary
```

Declare only the approved public globals: architecture/subarchitecture and identifier/team/certificates/flags/main-executable/entitlements/entitlements-dictionary keys. Use exact constants:

```rust
const K_SEC_CS_DEFAULT_FLAGS: u32 = 0;
const K_SEC_CS_BASIC_VALIDATE_ONLY: u32 = 6;
const K_SEC_CS_NO_NETWORK_ACCESS: u32 = 1 << 29;
const CHECK_FLAGS: u32 = 0x2000_0006;
const K_SEC_CS_SIGNING_INFORMATION: u32 = 2;
const K_SEC_CODE_SIGNATURE_ADHOC: u32 = 0x0002;
const K_SEC_CODE_SIGNATURE_RUNTIME: u32 = 0x10000;
const ERR_SEC_CS_UNSIGNED: i32 = -67062;
```

Use `core-foundation-sys` type IDs and conversions. Retain/release created input CFURLs, CFNumbers, attribute dictionaries, returned static-code objects, copied signing dictionaries, and copied certificate summaries. Keep borrowed values alive through the retained parent dictionary; never release them or exported globals. Put an explicit, local `// SAFETY:` justification at each unsafe operation as required by Rust 2024.

For `MainExecutable`, use `CFURLGetFileSystemRepresentation(resolveAgainstBase = true)` into a fixed 16-KiB-plus-NUL buffer, require termination and exact bytes, then reject empty/relative/CR/LF paths before returning `PathBuf`. Do not convert through a lossy CFString.

Require full-copy flags to exist and fit `u32`; otherwise metadata is `Error`. Check CFBoolean before CFNumber and `CFNumberIsFloatType` before SInt64 conversion. Bound CFString conversion before allocation, require complete UTF-16 consumption, and charge aggregate bytes before cloning. Traverse CF arrays/dictionaries with the reusable `EntitlementBudget`, active-container identity set, and `BTreeMap` duplicate-safe normalization.

Until Task 6 constructs and invokes the real provider, use item-level `#[cfg_attr(not(test), allow(dead_code))]` only on staged private provider/adapter entry points. Do not suppress warnings across the module; Task 6 must remove all staging allowances.

- [ ] **Step 6: Run GREEN and platform regression gates**

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::security_info::tests -- --nocapture
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::entitlements::tests
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
cargo fmt --all -- --check
YRX_REGENERATE_MODULES_RS=false cargo clippy --all-targets --all-features --locked --offline -- -D warnings
git diff --check
```

- [ ] **Step 7: Review, commit, and push structured metadata**

```text
git add src/macos/mod.rs src/macos/security_info.rs src/macos/codesign.rs src/macos/entitlements.rs
git commit -m "feat(macos): read structured signing information"
git push origin feature/entitlement-inspection
```

---

### Task 5: Reconcile DER, Legacy, Presence, and Fact Scope

**Files:**

- Modify: `src/macos/entitlements.rs`
- Modify: `src/macos/codesign.rs`
- Test: `src/macos/entitlements.rs`
- Test: `src/macos/codesign.rs`

- [ ] **Step 1: Write the complete entitlement-matrix tests**

Define pure internal observations for DER parsed dictionary, successful zero-byte absence, exact unsigned, command rejection, unavailable, runner/parser/framing error, and all four legacy states. Add one table-driven case for every specification matrix row.

Assert independently:

- `der_entitlements_status` never changes during comparison;
- equal DER/legacy trees keep DER source/status;
- different or invalid legacy clears facts and yields final `Error`;
- failed/unavailable/error DER plus valid legacy retains only non-authoritative compatibility context with final `Error`;
- valid empty DER dictionary is `Passed` with source present and zero entries;
- zero-byte DER absence is `NotApplicable` with no source;
- contradiction clearing removes entries/source without rewriting independent or final statuses.

- [ ] **Step 2: Write scope-aware presence and metadata-clearing tests**

Cover all rules for `SingleArchitecture`, `SelectedArchitecture`, no-safe-selector `AllArchitectures`, and `Unknown`, including:

- thin positive/unsigned observations from verification, selected Security, and DER;
- selected-slice signed plus all-architecture exact-unsigned remains selected `Signed` with diagnostic;
- selected-slice unsigned plus failed verification is selected `Unsigned`;
- all-architecture unsigned with no selector remains `Unknown`;
- positive plus explicit unsigned in the same scope becomes `Unknown` and clears metadata/entitlements;
- observations in different scopes are not contradictions;
- compatibility facts survive only with an uncontradicted same-scope positive observation;
- verification status always retains its all-architecture meaning.

For every valid `SelectedArchitecture` result, add one bounded, deterministically ordered diagnostic naming the selected selector and every available-but-uninspected selector. Assert it appears exactly once, survives an independent verification failure, and is removed when a later bundle binding failure invalidates the selector/list.

- [ ] **Step 3: Run focused reconciliation tests to verify RED**

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::entitlements::tests::reconcile_ -- --nocapture
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::codesign::reconciliation_tests -- --nocapture
```

Expected: failures for the missing assessment/reconciliation functions and incorrect Phase 2 scope-blind behavior.

- [ ] **Step 4: Implement pure reconciliation before orchestration**

Add:

```rust
pub(crate) fn reconcile_entitlements(
    der: DerEntitlementObservation,
    legacy: LegacyEntitlementObservation,
) -> ReconciledEntitlements;

fn reconcile_inspection(
    target: &Path,
    target_kind: CodeSignatureTargetKind,
    architecture: ArchitectureState,
    verification: VerificationAssessment,
    security: SelectedSecurityAssessment,
    entitlements: ReconciledEntitlements,
) -> CodeSignatureInspection;
```

Keep metadata and legacy as independent subresults. Make all fact-clearing explicit in one helper so identifier, team, authorities, kind/runtime, entries, source, selected selector, and available list cannot be partially retained on a forbidden path. Sort/truncate diagnostics deterministically and cap every detail at 4 KiB.

Until Task 6 invokes the pure reconciliation entry point from production orchestration, use one item-level `#[cfg_attr(not(test), allow(dead_code))]` on that staged entry point and remove it in Task 6.

- [ ] **Step 5: Run GREEN and regression gates**

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::entitlements::tests
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::codesign::reconciliation_tests
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
cargo fmt --all -- --check
YRX_REGENERATE_MODULES_RS=false cargo clippy --all-targets --all-features --locked --offline -- -D warnings
git diff --check
```

- [ ] **Step 6: Review, commit, and push reconciliation**

```text
git add src/macos/entitlements.rs src/macos/codesign.rs
git commit -m "feat(macos): reconcile structured signature facts"
git push origin feature/entitlement-inspection
```

---

### Task 6: Orchestrate Bound Structured and Native Queries

**Files:**

- Modify: `src/macos/codesign.rs`
- Test: `src/macos/codesign.rs`

- [ ] **Step 1: Replace text-parser fixtures with structured fakes and stage logs**

Keep `RecordingRunner`, add `RecordingSecurityInfoProvider`, and share `Rc<RefCell<Vec<NativeStage>>>` so tests assert exact stage order. Replace four-byte/file-text fixtures with complete thin/fat Mach-O headers and bundle main executables. Add raw `Vec<u8>` command-output fixtures.

Delete tests whose only purpose is accepting `Identifier=`, `TeamIdentifier=`, `Authority=`, `Signature=`, or `CodeDirectory` lines. Replace them with hostile filename and hostile signed-identifier tests proving no human-readable record becomes a fact.

- [ ] **Step 2: Add failing root/main/ordering tests**

Cover the exact seven-stage order and every short circuit:

1. original/resolved root validation;
2. bundle preliminary main resolution after basic success or exact unsigned only;
3. no-follow main open, identity capture, architecture parse and deterministic selection;
4. selected Security query and selected-main equality before facts;
5. all-architecture verification;
6. DER only while selector remains bound;
7. reconciliation after final revalidation.

Add mutations after preliminary, selected Security, verification, and DER for original root, resolved root, main path, and main identity. Initial identity failure returns one conservative all-`Error` inspection and runs no native stage. Stable-root selector failures still run verification but retain no selected facts. Bundle pre-binding failures clear selector/list/facts, suppress DER, set metadata/DER/final entitlement `Error`, and permit only verification-driven `AllArchitectures` or `Unknown`. Direct Mach-O selected query errors retain the structurally bound selector and may continue to DER.

Main-path tests include relative, symlink, non-regular, outside canonical bundle, wrong Mach-O identity, same path/replaced identity, another valid in-bundle Mach-O, over-16-KiB, CR/LF, and lossless non-UTF-8 Unix bytes.

- [ ] **Step 3: Add failing exact command/output tests**

Require these exact program/argv vectors with atomic `OsString` arguments:

```text
/usr/bin/codesign --verify --verbose=4 --all-architectures -- <absolute-path>
/usr/bin/codesign -d --entitlements - --der --architecture <signed-cpu>,<signed-subtype> -- <absolute-path>
```

Verification has no `--architecture`; both commands contain `--`; no verbose metadata command remains.

Unsigned is accepted only on nonzero exit, exactly empty stdout, and exact stderr bytes `<query-path>: code object is not signed at all\n`. Reject a bare phrase, stdout phrase, lossy target, missing LF, CRLF, extra line, different target, or success exit. Include a signed DER string and signed path containing newline-delimited unsigned/metadata text; neither changes presence or facts.

Before decoding DER, reject stdout over 256 KiB. On success, direct Mach-O stderr is empty or exact `Executable=<main>\n`; bundle stderr must be exactly that record. Empty/mismatch/extra bundle stderr invalidates selector/list/facts and falls back to verification-only scope. Exactly zero stdout is absence; an empty dictionary decodes as present `Passed` facts with zero entries.

Add automated orchestration regressions using the byte-level fat fixture builder plus queued Security/native observations:

- a two-slice universal file with different valid DER dictionaries, proving the deterministic selected selector is passed identically to Security and DER, the selected dictionary alone is retained, verification remains all-architecture, scope is `SelectedArchitecture`, and every uninspected selector is diagnosed;
- selected unsigned plus failed all-architecture verification, selected signed plus all-architecture exact-unsigned, and all-architecture exact-unsigned after selector loss, proving the three mixed-slice presence outcomes;
- a fixture whose outer and inner subtype are mutated together, with queued selected Basic success and verification failure, proving structural selector binding does not upgrade verification;
- a fixture whose outer alignment field alone is changed to another structurally valid value, with queued successful verification, proving the outer fat table is never treated as authenticated metadata.

These are ordinary automated tests in the focused/full Cargo suite, not smoke-only checks. Task 8 repeats the same security boundaries against disposable real macOS signatures.

- [ ] **Step 4: Run orchestration tests to verify RED**

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::codesign::orchestration_tests -- --nocapture
```

Expected: Phase 2 command order/arguments and lossy text classifications fail the new assertions.

- [ ] **Step 5: Implement root/main binding and exact orchestration**

Use structures equivalent to:

```rust
struct ValidatedRoot {
    query_path: PathBuf,
    original_identity: FileIdentity,
    resolved_identity: FileIdentity,
}

struct RetainedMain {
    canonical_path: PathBuf,
    identity: FileIdentity,
    file: File,
}
```

Before canonicalization, reject a symlink root and CR/LF bytes. Produce one absolute normalized query path and retain both identities. Open main files with `O_NOFOLLOW | O_NONBLOCK`, require handle metadata is regular, capture identity, and use only that handle for architecture reads. For bundles, require canonical containment and exact later path/identity equality. Revalidate roots/main after every native stage before using partial observations.

Assess native output from raw bytes only. Build unsigned and `Executable=` records by concatenating exact filesystem bytes with fixed ASCII suffix/prefix; do not use `display()`, UTF-8 loss, line splitting, trimming, or combined stdout/stderr. Keep the hardened runner unchanged.

Construct the real macOS inspector with `SystemCommandRunner` plus the Security provider. Keep the non-macOS stub and set verification, metadata, DER, and final entitlement statuses to `Unavailable` with no architecture/facts/source and one existing platform diagnostic.

Remove every temporary item-level staging `dead_code` allowance added by Tasks 1–5; all of those helpers now have production callers. Before the GREEN gate, run `rg -n 'cfg_attr\(not\(test\), allow\(dead_code\)\)' src/macos` and require no match attributable to this plan.

- [ ] **Step 6: Remove the injectable Phase 2 parser**

Delete `ParsedMetadata`, `TextObservation`, `RuntimeObservation`, `assess_metadata`, `parse_metadata`, `parse_metadata_line`, `parse_code_directory_flags`, `output_contains_unsigned`, `output_lines`, and the `/usr/bin/codesign -d --verbose=4` invocation. Confirm no human-readable codesign record is converted into structured data anywhere.

- [ ] **Step 7: Run GREEN and regression gates**

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline macos::codesign::tests -- --nocapture
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
cargo fmt --all -- --check
YRX_REGENERATE_MODULES_RS=false cargo clippy --all-targets --all-features --locked --offline -- -D warnings
./scripts/check-all.sh
git diff --check
```

- [ ] **Step 8: Review, commit, and push the completed inspector**

After independent spec and code-quality review:

```text
git add src/macos/codesign.rs
git commit -m "feat(macos): inspect code-signing entitlements"
git push origin feature/entitlement-inspection
```

---

### Task 7: Sanitize and Stream Entitlement Reporting

**Files:**

- Modify: `src/scanner/scan.rs:260-280,603-760`
- Modify: `src/report/text.rs:128-255,391-977`
- Test: `src/scanner/scan.rs`
- Test: `src/report/text.rs`

- [ ] **Step 1: Extend scanner sanitization and context-only tests**

Seed a mismatched fake inspection with selected/available architectures, passed DER/final statuses, DER source, nested entitlement facts, identity/team/authorities/runtime, and diagnostics. Assert `inspect_signature_target` replaces it with `unknown()` plus only the trusted mismatch diagnostic, so none of those fields survive.

Extend the signature-isolation test with suspicious-looking entitlement keys and values. Assert artifact evidence, verdict, detector statuses, and every summary count are byte-for-byte unchanged. Preserve later-target continuation and deterministic signature sorting.

- [ ] **Step 2: Add failing exact report and escaping tests**

Require the header shape:

```text
  <path> | presence: SIGNED (SINGLE_ARCHITECTURE) | verification (ALL_ARCHITECTURES): PASSED | metadata: PASSED | kind: AD_HOC
  Architecture: selected arm64 (16777228,0) | available: arm64 (16777228,0)
  Entitlements: PASSED | DER query: PASSED | source: CODESIGN_DER_OUTPUT
    - "com.apple.security.app-sandbox" = true
```

Test `Unknown`/`AllArchitectures` as `not available`; every available selector for universal results; the exact bounded diagnostic naming every uninspected selector; empty DER dictionary retaining its source/header but no entry lines; zero-byte absence with no source; and compatibility context visibly labeled `LEGACY_PROPERTY_LIST_NON_AUTHORITATIVE` while final status is `ERROR`.

Add exact recursive notation tests for bool, signed/unsigned decimal, `data(00ff)`, arrays, and sorted nested dictionaries. Keys/strings must escape quote and backslash; keep printable ASCII; render every other scalar as uppercase `\u{XXXX}` with at least four digits. Cover NUL, DEL, newline, bidi controls, zero-width characters, combining marks, natural RTL, quotes, and literal backslash in a single pass. Structured identifier/team/authority uses the same ASCII-only escape, while paths retain existing lossless OS-string escaping.

Add writer-failure tests at header, key, nested scalar, and flush boundaries plus a counting writer proving the maximum admitted tree stays below 3 MiB without constructing one recursive intermediate `String`.

- [ ] **Step 3: Run focused tests to verify RED**

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline scanner::scan::tests::mismatched_inspector_identity_is_replaced_without_copying_untrusted_facts -- --exact --nocapture
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline report::text::tests -- --nocapture
```

Expected: scanner assertions fail until new fields are cleared; reporter assertions fail until scope/architecture/entitlements and ASCII-only escaping are implemented.

- [ ] **Step 4: Implement streaming report helpers**

Add:

```rust
fn write_security_text<W: Write>(value: &str, writer: &mut W) -> io::Result<()>;
fn write_quoted_security_text<W: Write>(value: &str, writer: &mut W) -> io::Result<()>;
fn write_entitlement_value<W: Write>(value: &EntitlementValue, writer: &mut W) -> io::Result<()>;
```

Write values directly to `W`; do not build a recursive output string. Emit exactly comma plus one space between values. Use uppercase hexadecimal Unicode escapes and lowercase data hex. Preserve the distinction between `entitlement_source: Some(..)` with an empty vector and `None`.

- [ ] **Step 5: Run GREEN and regression gates**

```text
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline scanner::scan::tests -- --nocapture
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline report::text::tests -- --nocapture
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
cargo fmt --all -- --check
YRX_REGENERATE_MODULES_RS=false cargo clippy --all-targets --all-features --locked --offline -- -D warnings
./scripts/check-all.sh
git diff --check
```

- [ ] **Step 6: Review, commit, and push reporting integration**

```text
git add src/scanner/scan.rs src/report/text.rs
git commit -m "feat(report): render code-signing entitlements"
git push origin feature/entitlement-inspection
```

---

### Task 8: Run Final Security Gates and macOS Smoke Validation

**Files:**

- Modify only files required by verified review findings.
- Do not add permanent host-specific fixtures or trust expectations.

- [ ] **Step 1: Run all clean verification gates**

```text
YRX_REGENERATE_MODULES_RS=false cargo fmt --all -- --check
YRX_REGENERATE_MODULES_RS=false cargo check --all-targets --locked --offline
YRX_REGENERATE_MODULES_RS=false cargo test --locked --offline
YRX_REGENERATE_MODULES_RS=false cargo clippy --all-targets --all-features --locked --offline -- -D warnings
YRX_REGENERATE_MODULES_RS=false cargo build --locked --offline
./scripts/check-all.sh
git diff --check
git status --short
```

Expected: every command exits 0, all tests pass, Clippy reports no warning, and the worktree contains only intentional review fixes (or is clean).

- [ ] **Step 2: Perform isolated read-only macOS smoke checks**

Build `af`, then inspect:

- the built ad-hoc `target/debug/af` with no entitlements;
- one installed modern DER-backed application;
- one installed legacy XML-backed application;
- one harmless unsigned temporary file;
- one disposable ad-hoc signature whose entitlement string contains abstract `[Key]` injection text;
- one disposable ad-hoc signature whose identifier contains newline-delimited forged metadata records.
- one disposable two-slice universal fixture whose slices have different valid entitlement dictionaries, plus a mixed signed/unsigned variant, proving selected-slice facts and all-architecture verification stay visibly separate;
- one disposable signed universal fixture with a matched outer/inner subtype mutation, proving selected basic validity can succeed while all-architecture verification fails;
- one disposable signed universal fixture with only a structurally valid outer alignment mutation, proving verification may still pass and the outer fat table is never described as signature-authenticated.

Use a unique temporary directory, atomic argument vectors, and read-only `./target/debug/af scan <path>` invocations. Confirm the hostile values remain single escaped strings, no forged team/authority/unsigned fact appears, statuses/scopes match the design, and all temporary fixtures are removed afterward.

- [ ] **Step 3: Obtain final independent review**

Dispatch separate spec-compliance and adversarial code-quality reviewers over the entire branch diff from `be2275f`. Require explicit review of FFI ownership, raw-byte matching, bundle binding, retained-handle architecture parsing, scope-aware reconciliation, bounds, and report injection. Resolve every Critical/Important issue using RED-GREEN cycles, then rerun Step 1 and the affected smoke checks.

- [ ] **Step 4: Commit and push only verified review fixes**

If review required changes, make a narrowly scoped fix commit with a descriptive message and push it. If no changes are needed, do not create an empty commit.

```text
git push origin feature/entitlement-inspection
git rev-parse HEAD
git rev-parse @{upstream}
```

Expected: local `HEAD` equals the upstream branch. Stop before opening a PR, merging, tagging, or releasing unless the user explicitly requests the next action.
