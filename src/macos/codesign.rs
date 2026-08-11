use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use crate::macos::command::SystemCommandRunner;
use crate::macos::command::{NativeCommandError, NativeCommandOutput, NativeCommandRunner};
use crate::macos::entitlements::{EntitlementEntry, EntitlementSource};
use crate::scanner::result::{DiagnosticKind, ScanDiagnostic};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CodeSignatureTargetKind {
    MachOFile,
    ApplicationBundle,
}

impl CodeSignatureTargetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MachOFile => "MACH_O_FILE",
            Self::ApplicationBundle => "APPLICATION_BUNDLE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignaturePresence {
    Signed,
    Unsigned,
    Unknown,
}

impl SignaturePresence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signed => "SIGNED",
            Self::Unsigned => "UNSIGNED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeCheckStatus {
    Passed,
    Failed,
    NotApplicable,
    Unavailable,
    Error,
}

impl NativeCheckStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "PASSED",
            Self::Failed => "FAILED",
            Self::NotApplicable => "NOT_APPLICABLE",
            Self::Unavailable => "UNAVAILABLE",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    AdHoc,
    CertificateBacked,
    Unknown,
}

impl SignatureKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdHoc => "AD_HOC",
            Self::CertificateBacked => "CERTIFICATE_BACKED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeFactScope {
    #[cfg_attr(not(test), allow(dead_code))]
    AllArchitectures,
    #[cfg_attr(not(test), allow(dead_code))]
    SingleArchitecture,
    #[cfg_attr(not(test), allow(dead_code))]
    SelectedArchitecture,
    Unknown,
}

#[cfg_attr(not(test), allow(dead_code))]
impl NativeFactScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllArchitectures => "ALL_ARCHITECTURES",
            Self::SingleArchitecture => "SINGLE_ARCHITECTURE",
            Self::SelectedArchitecture => "SELECTED_ARCHITECTURE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CodeSignatureArchitecture {
    pub cpu_type: i32,
    pub cpu_subtype: i32,
    #[cfg_attr(not(test), allow(dead_code))]
    pub display_label: String,
}

impl PartialEq for CodeSignatureArchitecture {
    fn eq(&self, other: &Self) -> bool {
        (self.cpu_type, self.cpu_subtype) == (other.cpu_type, other.cpu_subtype)
    }
}

impl Eq for CodeSignatureArchitecture {}

impl PartialOrd for CodeSignatureArchitecture {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CodeSignatureArchitecture {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.cpu_type, self.cpu_subtype).cmp(&(other.cpu_type, other.cpu_subtype))
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl CodeSignatureArchitecture {
    pub fn new(cpu_type: i32, cpu_subtype: i32) -> Self {
        use goblin::mach::constants::cputype::{CPU_SUBTYPE_MASK, get_arch_name_from_types};

        let lookup_subtype = (cpu_subtype as u32) & !CPU_SUBTYPE_MASK;
        let display_label = get_arch_name_from_types(cpu_type as u32, lookup_subtype)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("cpu_type={cpu_type},cpu_subtype={cpu_subtype}"));

        Self {
            cpu_type,
            cpu_subtype,
            display_label,
        }
    }

    pub fn codesign_selector(&self) -> String {
        format!("{},{}", self.cpu_type, self.cpu_subtype)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignatureInspection {
    pub target: PathBuf,
    pub target_kind: CodeSignatureTargetKind,
    pub native_fact_scope: NativeFactScope,
    pub selected_architecture: Option<CodeSignatureArchitecture>,
    pub available_architectures: Vec<CodeSignatureArchitecture>,
    pub presence: SignaturePresence,
    pub verification_status: NativeCheckStatus,
    pub metadata_status: NativeCheckStatus,
    pub der_entitlements_status: NativeCheckStatus,
    pub entitlements_status: NativeCheckStatus,
    pub entitlement_source: Option<EntitlementSource>,
    pub entitlements: Vec<EntitlementEntry>,
    pub identifier: Option<String>,
    pub team_identifier: Option<String>,
    pub authorities: Vec<String>,
    pub signature_kind: SignatureKind,
    pub hardened_runtime: Option<bool>,
    pub verification_detail: Option<String>,
    pub diagnostics: Vec<ScanDiagnostic>,
}

impl CodeSignatureInspection {
    pub fn unknown(target: PathBuf, target_kind: CodeSignatureTargetKind) -> Self {
        Self {
            target,
            target_kind,
            native_fact_scope: NativeFactScope::Unknown,
            selected_architecture: None,
            available_architectures: Vec::new(),
            presence: SignaturePresence::Unknown,
            verification_status: NativeCheckStatus::Error,
            metadata_status: NativeCheckStatus::Error,
            der_entitlements_status: NativeCheckStatus::Error,
            entitlements_status: NativeCheckStatus::Error,
            entitlement_source: None,
            entitlements: Vec::new(),
            identifier: None,
            team_identifier: None,
            authorities: Vec::new(),
            signature_kind: SignatureKind::Unknown,
            hardened_runtime: None,
            verification_detail: None,
            diagnostics: Vec::new(),
        }
    }
}

pub trait CodeSignatureInspector {
    fn inspect(
        &self,
        target: &Path,
        target_kind: CodeSignatureTargetKind,
    ) -> CodeSignatureInspection;
}

pub struct CodesignInspector<R: NativeCommandRunner> {
    runner: R,
}

impl<R: NativeCommandRunner> CodesignInspector<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R: NativeCommandRunner> CodeSignatureInspector for CodesignInspector<R> {
    fn inspect(
        &self,
        target: &Path,
        target_kind: CodeSignatureTargetKind,
    ) -> CodeSignatureInspection {
        let target_identity = match validate_target(target, target_kind) {
            Ok(identity) => identity,
            Err(message) => {
                return failed_target_inspection(
                    target,
                    target_kind,
                    format!("code-signature target validation failed: {message}"),
                );
            }
        };

        let verify_arguments = [
            OsString::from("--verify"),
            OsString::from("--verbose=4"),
            target.as_os_str().to_os_string(),
        ];
        let display_arguments = [
            OsString::from("-d"),
            OsString::from("--verbose=4"),
            target.as_os_str().to_os_string(),
        ];
        let program = Path::new("/usr/bin/codesign");

        let verification_output = self.runner.run(program, &verify_arguments);
        if let Err(message) = revalidate_target(target, target_kind, &target_identity) {
            return failed_target_inspection(target, target_kind, message);
        }

        let metadata_output = self.runner.run(program, &display_arguments);
        if let Err(message) = revalidate_target(target, target_kind, &target_identity) {
            return failed_target_inspection(target, target_kind, message);
        }

        let verification = assess_verification(verification_output, target);
        let metadata = assess_metadata(metadata_output, target);

        reconcile(target, target_kind, verification, metadata)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct TargetIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    file_type: u32,
    #[cfg(unix)]
    length: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(not(unix))]
    is_file: bool,
    #[cfg(not(unix))]
    is_directory: bool,
    #[cfg(not(unix))]
    length: u64,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
    #[cfg(not(unix))]
    created: Option<std::time::SystemTime>,
    #[cfg(not(unix))]
    read_only: bool,
}

impl TargetIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                file_type: metadata.mode() & 0o170000,
                length: metadata.len(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            }
        }

        #[cfg(not(unix))]
        {
            Self {
                is_file: metadata.is_file(),
                is_directory: metadata.is_dir(),
                length: metadata.len(),
                modified: metadata.modified().ok(),
                created: metadata.created().ok(),
                read_only: metadata.permissions().readonly(),
            }
        }
    }
}

#[derive(Default)]
struct ParsedMetadata {
    identifier: TextObservation,
    team_identifier: TextObservation,
    authorities: Vec<String>,
    ad_hoc: bool,
    certificate_backed: bool,
    runtime: RuntimeObservation,
}

#[derive(Default)]
enum TextObservation {
    #[default]
    Unseen,
    Consistent(String),
    Conflicting,
}

impl TextObservation {
    fn observe_nonempty(&mut self, value: &str) {
        let value = value.trim();
        if value.is_empty() {
            return;
        }

        match self {
            Self::Unseen => *self = Self::Consistent(value.to_string()),
            Self::Consistent(existing) if existing == value => {}
            Self::Consistent(_) => *self = Self::Conflicting,
            Self::Conflicting => {}
        }
    }

    fn value(self) -> Option<String> {
        match self {
            Self::Consistent(value) => Some(value),
            Self::Unseen | Self::Conflicting => None,
        }
    }

    fn is_conflicting(&self) -> bool {
        matches!(self, Self::Conflicting)
    }
}

#[derive(Clone, Copy, Default)]
enum RuntimeObservation {
    #[default]
    Unseen,
    Consistent(bool),
    Conflicting,
}

impl RuntimeObservation {
    fn observe(&mut self, value: bool) {
        *self = match *self {
            Self::Unseen => Self::Consistent(value),
            Self::Consistent(existing) if existing == value => Self::Consistent(existing),
            Self::Consistent(_) | Self::Conflicting => Self::Conflicting,
        };
    }

    fn value(self) -> Option<bool> {
        match self {
            Self::Consistent(value) => Some(value),
            Self::Unseen | Self::Conflicting => None,
        }
    }

    fn is_conflicting(self) -> bool {
        matches!(self, Self::Conflicting)
    }
}

struct QueryAssessment {
    status: NativeCheckStatus,
    positive_signed: bool,
    explicit_unsigned: bool,
    detail: Option<String>,
    diagnostics: Vec<ScanDiagnostic>,
    metadata: ParsedMetadata,
}

fn validate_target(
    target: &Path,
    target_kind: CodeSignatureTargetKind,
) -> Result<TargetIdentity, String> {
    let metadata = std::fs::symlink_metadata(target)
        .map_err(|error| format!("cannot inspect '{}': {error}", target.display()))?;

    if metadata.file_type().is_symlink() {
        return Err(format!("'{}' is a symbolic link", target.display()));
    }

    match target_kind {
        CodeSignatureTargetKind::MachOFile if !metadata.is_file() => {
            return Err(format!("'{}' is not a regular file", target.display()));
        }
        CodeSignatureTargetKind::ApplicationBundle
            if !metadata.is_dir() || !has_app_extension(target) =>
        {
            return Err(format!(
                "'{}' is not a real .app directory",
                target.display()
            ));
        }
        _ => {}
    }

    Ok(TargetIdentity::from_metadata(&metadata))
}

fn revalidate_target(
    target: &Path,
    target_kind: CodeSignatureTargetKind,
    expected: &TargetIdentity,
) -> Result<(), String> {
    let current = validate_target(target, target_kind)
        .map_err(|message| format!("code-signature target changed during inspection: {message}"))?;

    if &current == expected {
        Ok(())
    } else {
        Err(format!(
            "code-signature target changed during inspection: identity no longer matches for '{}'",
            target.display()
        ))
    }
}

fn failed_target_inspection(
    target: &Path,
    target_kind: CodeSignatureTargetKind,
    message: String,
) -> CodeSignatureInspection {
    let mut inspection = CodeSignatureInspection::unknown(target.to_path_buf(), target_kind);
    inspection
        .diagnostics
        .push(code_signature_diagnostic(target, message));
    inspection
}

fn has_app_extension(target: &Path) -> bool {
    target
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("app"))
}

fn assess_verification(
    result: Result<NativeCommandOutput, NativeCommandError>,
    target: &Path,
) -> QueryAssessment {
    match result {
        Ok(output) => {
            let explicit_unsigned = output_contains_unsigned(&output, target);
            if output.success {
                QueryAssessment {
                    status: NativeCheckStatus::Passed,
                    positive_signed: true,
                    explicit_unsigned,
                    detail: None,
                    diagnostics: Vec::new(),
                    metadata: ParsedMetadata::default(),
                }
            } else if explicit_unsigned {
                QueryAssessment {
                    status: NativeCheckStatus::NotApplicable,
                    positive_signed: false,
                    explicit_unsigned: true,
                    detail: None,
                    diagnostics: Vec::new(),
                    metadata: ParsedMetadata::default(),
                }
            } else {
                QueryAssessment {
                    status: NativeCheckStatus::Failed,
                    positive_signed: false,
                    explicit_unsigned: false,
                    detail: output_detail(&output),
                    diagnostics: Vec::new(),
                    metadata: ParsedMetadata::default(),
                }
            }
        }
        Err(error) => runner_failure(error, target, "verification"),
    }
}

fn assess_metadata(
    result: Result<NativeCommandOutput, NativeCommandError>,
    target: &Path,
) -> QueryAssessment {
    match result {
        Ok(output) => {
            let explicit_unsigned = output_contains_unsigned(&output, target);
            let parsed = parse_metadata(&output);
            if output.success {
                QueryAssessment {
                    status: NativeCheckStatus::Passed,
                    positive_signed: true,
                    explicit_unsigned,
                    detail: None,
                    diagnostics: Vec::new(),
                    metadata: parsed,
                }
            } else if explicit_unsigned {
                QueryAssessment {
                    status: NativeCheckStatus::NotApplicable,
                    positive_signed: false,
                    explicit_unsigned: true,
                    detail: None,
                    diagnostics: Vec::new(),
                    metadata: parsed,
                }
            } else {
                let detail = output_detail(&output);
                let message = match detail.as_deref() {
                    Some(detail) => format!("codesign metadata query failed: {detail}"),
                    None => "codesign metadata query failed".to_string(),
                };
                QueryAssessment {
                    status: NativeCheckStatus::Failed,
                    positive_signed: false,
                    explicit_unsigned: false,
                    detail,
                    diagnostics: vec![code_signature_diagnostic(target, message)],
                    metadata: parsed,
                }
            }
        }
        Err(error) => runner_failure(error, target, "metadata"),
    }
}

fn runner_failure(error: NativeCommandError, target: &Path, query: &str) -> QueryAssessment {
    let (status, message) = match error {
        NativeCommandError::Unavailable(message) => (
            NativeCheckStatus::Unavailable,
            format!("codesign {query} query unavailable: {message}"),
        ),
        NativeCommandError::Io(message) => (
            NativeCheckStatus::Error,
            format!("codesign {query} query error: {message}"),
        ),
    };

    QueryAssessment {
        status,
        positive_signed: false,
        explicit_unsigned: false,
        detail: None,
        diagnostics: vec![code_signature_diagnostic(target, message)],
        metadata: ParsedMetadata::default(),
    }
}

fn reconcile(
    target: &Path,
    target_kind: CodeSignatureTargetKind,
    verification: QueryAssessment,
    metadata: QueryAssessment,
) -> CodeSignatureInspection {
    let positive_signed = verification.positive_signed || metadata.positive_signed;
    let explicit_unsigned = verification.explicit_unsigned || metadata.explicit_unsigned;
    let contradictory = positive_signed && explicit_unsigned;
    let presence = if contradictory {
        SignaturePresence::Unknown
    } else if positive_signed {
        SignaturePresence::Signed
    } else if explicit_unsigned {
        SignaturePresence::Unsigned
    } else {
        SignaturePresence::Unknown
    };

    let mut diagnostics = verification.diagnostics;
    diagnostics.extend(metadata.diagnostics);
    if contradictory {
        diagnostics.push(code_signature_diagnostic(
            target,
            "codesign verification and metadata queries disagree about signature presence"
                .to_string(),
        ));
    }

    let mut parsed = metadata.metadata;
    let clear_metadata = contradictory || presence == SignaturePresence::Unsigned;
    if clear_metadata {
        parsed = ParsedMetadata::default();
    }

    let signature_kind = if presence == SignaturePresence::Signed {
        match (parsed.ad_hoc, parsed.certificate_backed) {
            (true, false) => SignatureKind::AdHoc,
            (false, true) => SignatureKind::CertificateBacked,
            (true, true) => {
                diagnostics.push(code_signature_diagnostic(
                    target,
                    "codesign metadata contains conflicting ad-hoc and certificate-backed markers"
                        .to_string(),
                ));
                SignatureKind::Unknown
            }
            (false, false) => SignatureKind::Unknown,
        }
    } else {
        SignatureKind::Unknown
    };

    if parsed.runtime.is_conflicting() {
        diagnostics.push(code_signature_diagnostic(
            target,
            "codesign metadata contains ambiguous hardened-runtime observations".to_string(),
        ));
    }
    if parsed.identifier.is_conflicting() {
        diagnostics.push(code_signature_diagnostic(
            target,
            "codesign metadata contains ambiguous Identifier observations".to_string(),
        ));
    }
    if parsed.team_identifier.is_conflicting() {
        diagnostics.push(code_signature_diagnostic(
            target,
            "codesign metadata contains ambiguous TeamIdentifier observations".to_string(),
        ));
    }
    let identifier = parsed.identifier.value();
    let team_identifier = parsed.team_identifier.value();
    let hardened_runtime = parsed.runtime.value();

    diagnostics.sort_by(|left, right| left.message.cmp(&right.message));

    CodeSignatureInspection {
        target: target.to_path_buf(),
        target_kind,
        native_fact_scope: NativeFactScope::Unknown,
        selected_architecture: None,
        available_architectures: Vec::new(),
        presence,
        verification_status: verification.status,
        metadata_status: metadata.status,
        der_entitlements_status: NativeCheckStatus::Error,
        entitlements_status: NativeCheckStatus::Error,
        entitlement_source: None,
        entitlements: Vec::new(),
        identifier,
        team_identifier,
        authorities: parsed.authorities,
        signature_kind,
        hardened_runtime,
        verification_detail: verification.detail,
        diagnostics,
    }
}

fn parse_metadata(output: &NativeCommandOutput) -> ParsedMetadata {
    let mut parsed = ParsedMetadata::default();
    for line in output_lines(output) {
        parse_metadata_line(line.trim(), &mut parsed);
    }
    parsed
}

fn parse_metadata_line(line: &str, parsed: &mut ParsedMetadata) {
    if let Some(value) = line.strip_prefix("Identifier=") {
        parsed.identifier.observe_nonempty(value);
    } else if let Some(value) = line.strip_prefix("TeamIdentifier=") {
        let value = value.trim();
        if value != "not set" {
            parsed.team_identifier.observe_nonempty(value);
        }
    } else if let Some(value) = line.strip_prefix("Authority=") {
        let value = value.trim();
        if !value.is_empty()
            && value != "(unavailable)"
            && !parsed
                .authorities
                .iter()
                .any(|authority| authority == value)
        {
            parsed.authorities.push(value.to_string());
            parsed.certificate_backed = true;
        }
    } else if let Some(value) = line.strip_prefix("Signature=") {
        if value.trim() == "adhoc" {
            parsed.ad_hoc = true;
        }
    } else if line.starts_with("Signature size=") {
        parsed.certificate_backed = true;
    } else if let Some(record) = line.strip_prefix("CodeDirectory ") {
        parse_code_directory_flags(record, parsed);
    }
}

fn parse_code_directory_flags(record: &str, parsed: &mut ParsedMetadata) {
    let Some(flags) = record
        .split_ascii_whitespace()
        .find_map(|field| field.strip_prefix("flags="))
    else {
        return;
    };

    let Some(opening) = flags.find('(') else {
        return;
    };
    let Some(through_tokens) = flags.strip_suffix(')') else {
        return;
    };
    let mut runtime = false;

    for token in through_tokens[opening + 1..].split(',').map(str::trim) {
        match token {
            "adhoc" => parsed.ad_hoc = true,
            "runtime" => runtime = true,
            _ => {}
        }
    }
    parsed.runtime.observe(runtime);
}

fn output_contains_unsigned(output: &NativeCommandOutput, target: &Path) -> bool {
    output_lines(output)
        .iter()
        .any(|line| is_unsigned_diagnostic_line(line.trim(), target))
}

fn is_unsigned_diagnostic_line(line: &str, target: &Path) -> bool {
    const UNSIGNED_DIAGNOSTIC: &str = "code object is not signed at all";

    line == UNSIGNED_DIAGNOSTIC || line == format!("{}: {UNSIGNED_DIAGNOSTIC}", target.display())
}

fn output_detail(output: &NativeCommandOutput) -> Option<String> {
    output_lines(output)
        .iter()
        .map(|line| line.trim())
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

fn output_lines(output: &NativeCommandOutput) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .chain(
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .map(str::to_owned),
        )
        .collect()
}

fn code_signature_diagnostic(target: &Path, message: String) -> ScanDiagnostic {
    ScanDiagnostic::new(
        DiagnosticKind::CodeSignature,
        Some(target.to_path_buf()),
        message,
    )
}

#[cfg(target_os = "macos")]
pub type PlatformCodeSignatureInspector = CodesignInspector<SystemCommandRunner>;

#[cfg(target_os = "macos")]
pub fn platform_code_signature_inspector() -> PlatformCodeSignatureInspector {
    CodesignInspector::new(SystemCommandRunner)
}

#[cfg(not(target_os = "macos"))]
pub struct PlatformCodeSignatureInspector;

#[cfg(not(target_os = "macos"))]
impl CodeSignatureInspector for PlatformCodeSignatureInspector {
    fn inspect(
        &self,
        target: &Path,
        target_kind: CodeSignatureTargetKind,
    ) -> CodeSignatureInspection {
        let mut inspection = CodeSignatureInspection::unknown(target.to_path_buf(), target_kind);
        inspection.verification_status = NativeCheckStatus::Unavailable;
        inspection.metadata_status = NativeCheckStatus::Unavailable;
        inspection.diagnostics.push(code_signature_diagnostic(
            target,
            "native macOS code-signature inspection is unavailable on this platform".to_string(),
        ));
        inspection
    }
}

#[cfg(not(target_os = "macos"))]
pub fn platform_code_signature_inspector() -> PlatformCodeSignatureInspector {
    PlatformCodeSignatureInspector
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeSet, VecDeque};
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::macos::command::{NativeCommandError, NativeCommandOutput, NativeCommandRunner};
    use crate::scanner::result::DiagnosticKind;

    static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aegisforge-codesign-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test directory should be created");
            Self { path }
        }

        fn file(&self, name: &str) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, b"fixture").expect("test file should be created");
            path
        }

        fn bundle(&self, name: &str) -> PathBuf {
            let path = self.path.join(name);
            fs::create_dir(&path).expect("test bundle should be created");
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    type RunResult = Result<NativeCommandOutput, NativeCommandError>;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedCall {
        program: PathBuf,
        arguments: Vec<OsString>,
    }

    struct RecordingRunner {
        results: RefCell<VecDeque<RunResult>>,
        calls: RefCell<Vec<RecordedCall>>,
    }

    impl RecordingRunner {
        fn new(results: impl IntoIterator<Item = RunResult>) -> Self {
            Self {
                results: RefCell::new(results.into_iter().collect()),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl NativeCommandRunner for RecordingRunner {
        fn run(&self, program: &Path, arguments: &[OsString]) -> RunResult {
            self.calls.borrow_mut().push(RecordedCall {
                program: program.to_path_buf(),
                arguments: arguments.to_vec(),
            });
            self.results
                .borrow_mut()
                .pop_front()
                .expect("fake runner should have a queued result")
        }
    }

    struct ReplacingRunner {
        target: PathBuf,
        backup: PathBuf,
        replace_after_call: usize,
        calls: Cell<usize>,
        results: RefCell<VecDeque<RunResult>>,
    }

    impl ReplacingRunner {
        fn new(
            target: PathBuf,
            replace_after_call: usize,
            results: impl IntoIterator<Item = RunResult>,
        ) -> Self {
            let backup = target.with_extension("original-before-codesign-test");
            Self {
                target,
                backup,
                replace_after_call,
                calls: Cell::new(0),
                results: RefCell::new(results.into_iter().collect()),
            }
        }
    }

    impl NativeCommandRunner for ReplacingRunner {
        fn run(&self, _program: &Path, _arguments: &[OsString]) -> RunResult {
            let call = self.calls.get() + 1;
            self.calls.set(call);
            if call == self.replace_after_call {
                fs::rename(&self.target, &self.backup)
                    .expect("validated test target should be moved aside");
                fs::write(&self.target, b"replacement target with different contents")
                    .expect("replacement test target should be created");
            }
            self.results
                .borrow_mut()
                .pop_front()
                .expect("replacing runner should have a queued result")
        }
    }

    fn command_output(success: bool, stdout: &str, stderr: &str) -> RunResult {
        Ok(NativeCommandOutput {
            success,
            exit_code: Some(if success { 0 } else { 1 }),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    fn inspect_file(runner: RecordingRunner) -> (CodeSignatureInspection, RecordingRunner) {
        let directory = TestDirectory::new();
        let target = directory.file("sample");
        let inspector = CodesignInspector::new(runner);
        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);
        (inspection, inspector.runner)
    }

    fn messages(inspection: &CodeSignatureInspection) -> Vec<&str> {
        inspection
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.as_str())
            .collect()
    }

    #[test]
    fn signature_presence_has_stable_labels() {
        assert_eq!(SignaturePresence::Signed.as_str(), "SIGNED");
        assert_eq!(SignaturePresence::Unsigned.as_str(), "UNSIGNED");
        assert_eq!(SignaturePresence::Unknown.as_str(), "UNKNOWN");
    }

    #[test]
    fn native_check_status_has_stable_labels() {
        assert_eq!(NativeCheckStatus::Passed.as_str(), "PASSED");
        assert_eq!(NativeCheckStatus::Failed.as_str(), "FAILED");
        assert_eq!(NativeCheckStatus::NotApplicable.as_str(), "NOT_APPLICABLE");
        assert_eq!(NativeCheckStatus::Unavailable.as_str(), "UNAVAILABLE");
        assert_eq!(NativeCheckStatus::Error.as_str(), "ERROR");
    }

    #[test]
    fn code_signature_target_kind_has_stable_labels() {
        assert_eq!(CodeSignatureTargetKind::MachOFile.as_str(), "MACH_O_FILE");
        assert_eq!(
            CodeSignatureTargetKind::ApplicationBundle.as_str(),
            "APPLICATION_BUNDLE"
        );
    }

    #[test]
    fn signature_kind_has_stable_labels() {
        assert_eq!(SignatureKind::AdHoc.as_str(), "AD_HOC");
        assert_eq!(
            SignatureKind::CertificateBacked.as_str(),
            "CERTIFICATE_BACKED"
        );
        assert_eq!(SignatureKind::Unknown.as_str(), "UNKNOWN");
    }

    #[test]
    fn native_fact_scope_has_stable_labels() {
        assert_eq!(
            NativeFactScope::AllArchitectures.as_str(),
            "ALL_ARCHITECTURES"
        );
        assert_eq!(
            NativeFactScope::SingleArchitecture.as_str(),
            "SINGLE_ARCHITECTURE"
        );
        assert_eq!(
            NativeFactScope::SelectedArchitecture.as_str(),
            "SELECTED_ARCHITECTURE"
        );
        assert_eq!(NativeFactScope::Unknown.as_str(), "UNKNOWN");
    }

    #[test]
    fn architecture_has_exact_selector_and_known_label() {
        let architecture = CodeSignatureArchitecture::new(16_777_228, 2);

        assert_eq!(architecture.cpu_type, 16_777_228);
        assert_eq!(architecture.cpu_subtype, 2);
        assert_eq!(architecture.display_label, "arm64e");
        assert_eq!(architecture.codesign_selector(), "16777228,2");
    }

    #[test]
    fn architecture_masks_capability_bits_only_for_label_lookup() {
        let subtype_with_capability = (0x8000_0000_u32 | 2) as i32;
        let architecture = CodeSignatureArchitecture::new(16_777_228, subtype_with_capability);

        assert_eq!(architecture.display_label, "arm64e");
        assert_eq!(architecture.cpu_subtype, subtype_with_capability);
        assert_eq!(
            architecture.codesign_selector(),
            format!("16777228,{subtype_with_capability}")
        );
    }

    #[test]
    fn architecture_fallback_label_is_deterministic_and_numeric() {
        let first = CodeSignatureArchitecture::new(123, -456);
        let second = CodeSignatureArchitecture::new(123, -456);

        assert_eq!(first, second);
        assert_eq!(first.display_label, "cpu_type=123,cpu_subtype=-456");
        assert_eq!(first.codesign_selector(), "123,-456");
    }

    #[test]
    fn architecture_order_uses_the_raw_signed_tuple() {
        let lower_subtype = CodeSignatureArchitecture::new(7, -1);
        let higher_subtype = CodeSignatureArchitecture::new(7, 0);
        let higher_type = CodeSignatureArchitecture::new(8, i32::MIN);

        assert!(lower_subtype < higher_subtype);
        assert!(higher_subtype < higher_type);
    }

    #[test]
    fn architecture_identity_ignores_display_label() {
        let first = CodeSignatureArchitecture {
            cpu_type: 16_777_228,
            cpu_subtype: 2,
            display_label: "arm64e".to_string(),
        };
        let relabeled = CodeSignatureArchitecture {
            display_label: "deliberately different".to_string(),
            ..first.clone()
        };

        assert_eq!(first, relabeled);
        assert_eq!(first.cmp(&relabeled), std::cmp::Ordering::Equal);
        assert_eq!(BTreeSet::from([first, relabeled]).len(), 1);
    }

    #[test]
    fn target_kinds_remain_distinct_in_constructed_inspections() {
        let file = CodeSignatureInspection::unknown(
            PathBuf::from("sample"),
            CodeSignatureTargetKind::MachOFile,
        );
        let bundle = CodeSignatureInspection::unknown(
            PathBuf::from("Sample.app"),
            CodeSignatureTargetKind::ApplicationBundle,
        );

        assert_eq!(file.target_kind, CodeSignatureTargetKind::MachOFile);
        assert_eq!(
            bundle.target_kind,
            CodeSignatureTargetKind::ApplicationBundle
        );
        assert_ne!(file.target_kind, bundle.target_kind);
    }

    #[test]
    fn unknown_inspection_uses_conservative_defaults() {
        let target = PathBuf::from("sample");

        let inspection =
            CodeSignatureInspection::unknown(target.clone(), CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspection.target, target);
        assert_eq!(inspection.target_kind, CodeSignatureTargetKind::MachOFile);
        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Error);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Error);
        assert_eq!(inspection.native_fact_scope, NativeFactScope::Unknown);
        assert_eq!(inspection.selected_architecture, None);
        assert!(inspection.available_architectures.is_empty());
        assert_eq!(inspection.der_entitlements_status, NativeCheckStatus::Error);
        assert_eq!(inspection.entitlements_status, NativeCheckStatus::Error);
        assert_eq!(inspection.entitlement_source, None);
        assert!(inspection.entitlements.is_empty());
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.verification_detail, None);
        assert!(inspection.diagnostics.is_empty());
    }

    fn native_fact_scope_fields_are_valid(inspection: &CodeSignatureInspection) -> bool {
        let has_no_selected_facts = inspection.identifier.is_none()
            && inspection.team_identifier.is_none()
            && inspection.authorities.is_empty()
            && inspection.signature_kind == SignatureKind::Unknown
            && inspection.hardened_runtime.is_none()
            && inspection.entitlement_source.is_none()
            && inspection.entitlements.is_empty();

        match inspection.native_fact_scope {
            NativeFactScope::Unknown | NativeFactScope::AllArchitectures => {
                inspection.selected_architecture.is_none()
                    && inspection.available_architectures.is_empty()
                    && has_no_selected_facts
            }
            NativeFactScope::SingleArchitecture => inspection
                .selected_architecture
                .as_ref()
                .is_some_and(|selected| {
                    inspection.available_architectures.as_slice() == std::slice::from_ref(selected)
                }),
            NativeFactScope::SelectedArchitecture => {
                inspection.available_architectures.len() >= 2
                    && inspection
                        .selected_architecture
                        .as_ref()
                        .is_some_and(|selected| {
                            inspection.available_architectures.contains(selected)
                        })
            }
        }
    }

    #[test]
    fn native_fact_scope_examples_obey_field_invariants() {
        let target = PathBuf::from("sample");
        let first = CodeSignatureArchitecture::new(7, 3);
        let second = CodeSignatureArchitecture::new(16_777_228, 0);

        let unknown =
            CodeSignatureInspection::unknown(target.clone(), CodeSignatureTargetKind::MachOFile);

        let mut all =
            CodeSignatureInspection::unknown(target.clone(), CodeSignatureTargetKind::MachOFile);
        all.native_fact_scope = NativeFactScope::AllArchitectures;
        all.presence = SignaturePresence::Signed;
        all.verification_status = NativeCheckStatus::Passed;

        let mut single =
            CodeSignatureInspection::unknown(target.clone(), CodeSignatureTargetKind::MachOFile);
        single.native_fact_scope = NativeFactScope::SingleArchitecture;
        single.selected_architecture = Some(first.clone());
        single.available_architectures = vec![first.clone()];

        let mut selected =
            CodeSignatureInspection::unknown(target, CodeSignatureTargetKind::MachOFile);
        selected.native_fact_scope = NativeFactScope::SelectedArchitecture;
        selected.selected_architecture = Some(first.clone());
        selected.available_architectures = vec![first, second];

        assert!(native_fact_scope_fields_are_valid(&unknown));
        assert!(native_fact_scope_fields_are_valid(&all));
        assert!(native_fact_scope_fields_are_valid(&single));
        assert!(native_fact_scope_fields_are_valid(&selected));
    }

    #[test]
    fn code_signature_inspector_is_object_safe() {
        fn accepts_inspector(_inspector: &dyn CodeSignatureInspector) {}

        let runner = RecordingRunner::new([]);
        accepts_inspector(&CodesignInspector::new(runner));
    }

    #[test]
    fn successful_adhoc_signature_is_reconciled_as_signed() {
        let runner = RecordingRunner::new([
            command_output(true, "", "sample: valid on disk\n"),
            command_output(
                true,
                "",
                "Identifier=com.example.tool\nCodeDirectory v=20400 flags=0x20002(adhoc,linker-signed) hashes=1\nSignature=adhoc\nTeamIdentifier=not set\n",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Passed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Passed);
        assert_eq!(inspection.signature_kind, SignatureKind::AdHoc);
        assert_eq!(inspection.identifier.as_deref(), Some("com.example.tool"));
        assert_eq!(inspection.team_identifier, None);
        assert_eq!(inspection.hardened_runtime, Some(false));
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn certificate_metadata_handles_crlf_reordering_and_stable_deduplication() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\r\n"),
            command_output(
                true,
                "Authority=Leaf Certificate\r\nTeamIdentifier=TEAM12345\r\nAuthority=(unavailable)\r\nSignature size=9000\r\nAuthority=Root Certificate\r\nAuthority=Leaf Certificate\r\nCodeDirectory v=20500 flags=0x10000(runtime) hashes=2\r\nIdentifier=com.example.signed\r\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.signature_kind, SignatureKind::CertificateBacked);
        assert_eq!(inspection.identifier.as_deref(), Some("com.example.signed"));
        assert_eq!(inspection.team_identifier.as_deref(), Some("TEAM12345"));
        assert_eq!(
            inspection.authorities,
            vec!["Leaf Certificate", "Root Certificate"]
        );
        assert_eq!(inspection.hardened_runtime, Some(true));
    }

    #[test]
    fn explicit_unsigned_from_both_queries_is_not_applicable() {
        let standalone = "code object is not signed at all\n";
        let runner = RecordingRunner::new([
            command_output(false, "", standalone),
            command_output(false, standalone, ""),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Unsigned);
        assert_eq!(
            inspection.verification_status,
            NativeCheckStatus::NotApplicable
        );
        assert_eq!(inspection.metadata_status, NativeCheckStatus::NotApplicable);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.hardened_runtime, None);
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn unsigned_diagnostic_for_different_target_is_not_accepted() {
        let directory = TestDirectory::new();
        let target = directory.file("sample");
        let diagnostic = format!(
            "{}: code object is not signed at all\n",
            directory.path.join("different-sample").display()
        );
        let runner = RecordingRunner::new([
            command_output(false, "", &diagnostic),
            command_output(false, &diagnostic, ""),
        ]);
        let inspector = CodesignInspector::new(runner);

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Failed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Failed);
    }

    #[test]
    fn exact_unsigned_diagnostic_accepts_target_path_containing_equals() {
        let directory = TestDirectory::new();
        let target = directory.file("unsigned=sample");
        let diagnostic = format!("{}: code object is not signed at all\n", target.display());
        let runner = RecordingRunner::new([
            command_output(false, "", &diagnostic),
            command_output(false, &diagnostic, ""),
        ]);
        let inspector = CodesignInspector::new(runner);

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspection.presence, SignaturePresence::Unsigned);
        assert_eq!(
            inspection.verification_status,
            NativeCheckStatus::NotApplicable
        );
        assert_eq!(inspection.metadata_status, NativeCheckStatus::NotApplicable);
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn unsigned_phrase_inside_signed_key_value_metadata_is_not_a_diagnostic() {
        let directory = TestDirectory::new();
        let target = directory.file("signed code object is not signed at all");
        let authority = "Signer: code object is not signed at all";
        let display_output = format!(
            "Executable={}\nIdentifier=com.example.signed\nAuthority={authority}\nSignature size=9000\n",
            target.display()
        );
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(true, "", &display_output),
        ]);
        let inspector = CodesignInspector::new(runner);

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Passed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Passed);
        assert_eq!(inspection.signature_kind, SignatureKind::CertificateBacked);
        assert_eq!(inspection.identifier.as_deref(), Some("com.example.signed"));
        assert_eq!(inspection.authorities, vec![authority]);
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn invalid_verification_retains_successful_signed_metadata_and_detail() {
        let runner = RecordingRunner::new([
            command_output(
                false,
                "",
                "sample: invalid signature (code or signature modified)\n",
            ),
            command_output(
                true,
                "Identifier=com.example.invalid\nAuthority=Signer\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Failed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Passed);
        assert_eq!(
            inspection.identifier.as_deref(),
            Some("com.example.invalid")
        );
        assert_eq!(inspection.authorities, vec!["Signer"]);
        assert!(
            inspection
                .verification_detail
                .as_deref()
                .is_some_and(|detail| detail.contains("invalid signature"))
        );
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn failed_display_preserves_positive_verification_without_inventing_metadata() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                false,
                "unrecognized output\nIdentifier=com.example.partial\n",
                "display failed\n",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Passed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Failed);
        assert_eq!(
            inspection.identifier.as_deref(),
            Some("com.example.partial")
        );
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert_eq!(
            inspection.diagnostics[0].kind,
            DiagnosticKind::CodeSignature
        );
        assert!(messages(&inspection)[0].contains("metadata"));
    }

    #[test]
    fn positive_signed_and_explicit_unsigned_are_reported_as_contradictory() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                false,
                "Identifier=must.be.cleared\nAuthority=Must Clear\nCodeDirectory flags=0x10000(runtime)\n",
                "code object is not signed at all\n",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Passed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::NotApplicable);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert!(messages(&inspection)[0].contains("disagree"));
    }

    #[test]
    fn conflicting_adhoc_and_certificate_markers_leave_signature_kind_unknown() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(true, "Signature=adhoc\nAuthority=Signer\n", ""),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.authorities, vec!["Signer"]);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert!(messages(&inspection)[0].contains("conflicting"));
    }

    #[test]
    fn independent_runner_failures_have_truthful_statuses_and_sorted_diagnostics() {
        let runner = RecordingRunner::new([
            Err(NativeCommandError::Unavailable(
                "codesign missing".to_string(),
            )),
            Err(NativeCommandError::Io(
                "display could not start".to_string(),
            )),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(
            inspection.verification_status,
            NativeCheckStatus::Unavailable
        );
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Error);
        assert_eq!(inspection.diagnostics.len(), 2);
        assert!(
            inspection
                .diagnostics
                .windows(2)
                .all(|pair| pair[0].message <= pair[1].message)
        );
        assert!(
            messages(&inspection)
                .iter()
                .any(|message| message.contains("codesign missing"))
        );
        assert!(
            messages(&inspection)
                .iter()
                .any(|message| message.contains("display could not start"))
        );
    }

    #[test]
    fn metadata_output_limit_preserves_successful_verification_without_inventing_metadata() {
        let directory = TestDirectory::new();
        let target = directory.file("output-limited");
        let limit_reason = "native command stderr exceeded 1048576-byte limit";
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            Err(NativeCommandError::Io(limit_reason.to_string())),
        ]);
        let inspector = CodesignInspector::new(runner);

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Passed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Error);
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.verification_detail, None);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert_eq!(
            inspection.diagnostics[0].kind,
            DiagnosticKind::CodeSignature
        );
        assert!(inspection.diagnostics[0].message.contains(limit_reason));
        assert_eq!(
            inspector.runner.calls.borrow().as_slice(),
            [
                RecordedCall {
                    program: PathBuf::from("/usr/bin/codesign"),
                    arguments: vec![
                        OsString::from("--verify"),
                        OsString::from("--verbose=4"),
                        target.clone().into_os_string(),
                    ],
                },
                RecordedCall {
                    program: PathBuf::from("/usr/bin/codesign"),
                    arguments: vec![
                        OsString::from("-d"),
                        OsString::from("--verbose=4"),
                        target.into_os_string(),
                    ],
                },
            ]
        );
    }

    #[test]
    fn invokes_codesign_with_exact_arguments_and_keeps_hostile_bundle_path_atomic() {
        let directory = TestDirectory::new();
        let target = directory.bundle("name with spaces;$(touch nope).app");
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(true, "Identifier=com.example.bundle\n", ""),
        ]);
        let inspector = CodesignInspector::new(runner);

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::ApplicationBundle);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(
            inspector.runner.calls.borrow().as_slice(),
            [
                RecordedCall {
                    program: PathBuf::from("/usr/bin/codesign"),
                    arguments: vec![
                        OsString::from("--verify"),
                        OsString::from("--verbose=4"),
                        target.clone().into_os_string(),
                    ],
                },
                RecordedCall {
                    program: PathBuf::from("/usr/bin/codesign"),
                    arguments: vec![
                        OsString::from("-d"),
                        OsString::from("--verbose=4"),
                        target.into_os_string(),
                    ],
                },
            ]
        );
        assert!(!directory.path.join("nope").exists());
    }

    #[test]
    fn useful_metadata_is_combined_from_stdout_and_stderr() {
        let runner = RecordingRunner::new([
            command_output(true, "unknown verify line\n", "valid\n"),
            command_output(
                true,
                "unknown first\nTeamIdentifier=TEAM-SPLIT\nAuthority=Leaf\n",
                "Identifier=com.example.split\nCodeDirectory v=1 flags=0x2(adhoc) extra\nAuthority=Root\nunknown last\n",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.identifier.as_deref(), Some("com.example.split"));
        assert_eq!(inspection.team_identifier.as_deref(), Some("TEAM-SPLIT"));
        assert_eq!(inspection.authorities, vec!["Leaf", "Root"]);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.hardened_runtime, Some(false));
    }

    #[test]
    fn code_directory_prefix_without_record_boundary_is_ignored() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(true, "CodeDirectoryBogus v=1 flags=0x10000(runtime)\n", ""),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
    }

    #[test]
    fn flags_substring_inside_another_field_name_is_ignored() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(true, "CodeDirectory v=1 notflags=0x10000(runtime)\n", ""),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
    }

    #[test]
    fn flags_field_without_parenthesized_tokens_is_ignored() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(true, "CodeDirectory v=1 flags=0x0\n", ""),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
    }

    #[test]
    fn flags_field_with_unclosed_token_list_is_ignored() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(true, "CodeDirectory v=1 flags=0x10000(runtime\n", ""),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
    }

    #[test]
    fn conflicting_runtime_observations_are_ambiguous_without_losing_signed_metadata() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                true,
                "Identifier=com.example.runtime-conflict\nCodeDirectory v=1 flags=0x0(none)\nCodeDirectory v=1 flags=0x10000(runtime)\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Passed);
        assert_eq!(
            inspection.identifier.as_deref(),
            Some("com.example.runtime-conflict")
        );
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert_eq!(
            inspection.diagnostics[0].kind,
            DiagnosticKind::CodeSignature
        );
        assert!(messages(&inspection)[0].contains("ambiguous"));
    }

    #[test]
    fn duplicate_true_runtime_observations_remain_true_without_diagnostic() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                true,
                "CodeDirectory v=1 flags=0x10000(runtime)\nCodeDirectory v=1 flags=0x10000(runtime)\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.hardened_runtime, Some(true));
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn duplicate_false_runtime_observations_remain_false_without_diagnostic() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                true,
                "CodeDirectory v=1 flags=0x0(none)\nCodeDirectory v=1 flags=0x2(linker-signed)\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.hardened_runtime, Some(false));
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn conflicting_identifier_observations_clear_identifier_and_preserve_other_metadata() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                true,
                "Identifier=com.example.first\nTeamIdentifier=TEAM-STABLE\nIdentifier=com.example.second\nAuthority=Stable Signer\nCodeDirectory v=1 flags=0x10000(runtime)\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier.as_deref(), Some("TEAM-STABLE"));
        assert_eq!(inspection.authorities, vec!["Stable Signer"]);
        assert_eq!(inspection.hardened_runtime, Some(true));
        assert_eq!(inspection.diagnostics.len(), 1);
        assert_eq!(
            inspection.diagnostics[0].kind,
            DiagnosticKind::CodeSignature
        );
        assert!(messages(&inspection)[0].contains("Identifier"));
        assert!(messages(&inspection)[0].contains("ambiguous"));
    }

    #[test]
    fn conflicting_team_identifier_observations_clear_team_and_preserve_other_metadata() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                true,
                "Identifier=com.example.stable\nTeamIdentifier=TEAM-FIRST\nTeamIdentifier=TEAM-SECOND\nAuthority=Stable Signer\nCodeDirectory v=1 flags=0x0(none)\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.identifier.as_deref(), Some("com.example.stable"));
        assert_eq!(inspection.team_identifier, None);
        assert_eq!(inspection.authorities, vec!["Stable Signer"]);
        assert_eq!(inspection.hardened_runtime, Some(false));
        assert_eq!(inspection.diagnostics.len(), 1);
        assert!(messages(&inspection)[0].contains("TeamIdentifier"));
        assert!(messages(&inspection)[0].contains("ambiguous"));
    }

    #[test]
    fn exact_duplicate_identity_observations_remain_present_without_diagnostic() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                true,
                "Identifier=com.example.duplicate\nTeamIdentifier=TEAM-SAME\nIdentifier=com.example.duplicate\nTeamIdentifier=TEAM-SAME\nAuthority=Signer\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(
            inspection.identifier.as_deref(),
            Some("com.example.duplicate")
        );
        assert_eq!(inspection.team_identifier.as_deref(), Some("TEAM-SAME"));
        assert_eq!(inspection.authorities, vec!["Signer"]);
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn wrong_target_kind_is_rejected_before_commands_run() {
        let directory = TestDirectory::new();
        let target = directory.file("not-a-bundle.app");
        let inspector = CodesignInspector::new(RecordingRunner::new([]));

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::ApplicationBundle);

        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Error);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Error);
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert_eq!(
            inspection.diagnostics[0].kind,
            DiagnosticKind::CodeSignature
        );
        assert!(inspector.runner.calls.borrow().is_empty());
    }

    #[test]
    fn target_replacement_after_verify_stops_display_and_discards_query_facts() {
        let directory = TestDirectory::new();
        let target = directory.file("replace-between-queries");
        let runner = ReplacingRunner::new(
            target.clone(),
            1,
            [
                command_output(true, "", "valid\n"),
                command_output(
                    true,
                    "Identifier=com.example.replacement\nAuthority=Replacement Signer\nCodeDirectory v=1 flags=0x10000(runtime)\n",
                    "",
                ),
            ],
        );
        let inspector = CodesignInspector::new(runner);

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspector.runner.calls.get(), 1);
        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Error);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Error);
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.verification_detail, None);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert_eq!(
            inspection.diagnostics[0].kind,
            DiagnosticKind::CodeSignature
        );
        assert!(messages(&inspection)[0].contains("changed"));
    }

    #[test]
    fn target_replacement_after_display_discards_all_query_facts() {
        let directory = TestDirectory::new();
        let target = directory.file("replace-after-display");
        let runner = ReplacingRunner::new(
            target.clone(),
            2,
            [
                command_output(true, "", "valid\n"),
                command_output(
                    true,
                    "Identifier=com.example.original\nAuthority=Original Signer\nCodeDirectory v=1 flags=0x10000(runtime)\n",
                    "",
                ),
            ],
        );
        let inspector = CodesignInspector::new(runner);

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspector.runner.calls.get(), 2);
        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Error);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Error);
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.verification_detail, None);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert!(messages(&inspection)[0].contains("changed"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_target_is_rejected_before_commands_run() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let real_target = directory.file("real");
        let target = directory.path.join("link");
        symlink(real_target, &target).expect("test symlink should be created");
        let inspector = CodesignInspector::new(RecordingRunner::new([]));

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Error);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Error);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert!(inspector.runner.calls.borrow().is_empty());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_platform_inspector_reports_unavailable_without_native_execution() {
        let directory = TestDirectory::new();
        let target = directory.file("sample");
        let inspector = platform_code_signature_inspector();

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(
            inspection.verification_status,
            NativeCheckStatus::Unavailable
        );
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Unavailable);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert_eq!(
            inspection.diagnostics[0].kind,
            DiagnosticKind::CodeSignature
        );
        assert!(messages(&inspection)[0].contains("macOS"));
    }
}
