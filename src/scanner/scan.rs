use std::path::Path;

use crate::detection::analyzer::{MachODependencyContext, analyze_artifact_result};
use crate::detection::verdict::determine_verdict;
use crate::detection::yara::YaraEngine;
use crate::macos::codesign::{
    CodeSignatureInspection, CodeSignatureInspector, CodeSignatureTargetKind,
    platform_code_signature_inspector,
};

use super::discovery::{DiscoveryResult, discover_files_with_diagnostics};
use super::file_type::ArtifactType;
use super::macho::inspect_macho;
use super::macho_dependencies::inspect_macho_dependencies;
use super::metadata::collect_artifact;
use super::path::{PathType, inspect_path};
use super::result::{
    ArtifactResult, Detector, DetectorOutcome, DetectorStatus, DiagnosticKind, ScanDiagnostic,
    ScanResult, ScanSummary,
};

pub fn scan_path(path: &Path) -> Result<ScanResult, String> {
    let target_type = inspect_path(path)?;
    let yara_engine = YaraEngine::from_directory(Path::new("rules/yara"))?;
    let discovery = discover_files_with_diagnostics(path)?;
    let inspector = platform_code_signature_inspector();

    Ok(assemble_scan_result(
        path,
        target_type,
        discovery,
        &yara_engine,
        &inspector,
    ))
}

#[cfg(test)]
fn scan_path_with_yara(
    path: &Path,
    yara_engine: &YaraEngine,
    inspector: &dyn CodeSignatureInspector,
) -> Result<ScanResult, String> {
    let target_type = inspect_path(path)?;
    let discovery = discover_files_with_diagnostics(path)?;

    Ok(assemble_scan_result(
        path,
        target_type,
        discovery,
        yara_engine,
        inspector,
    ))
}

struct StaticScanOutput {
    artifacts: Vec<ArtifactResult>,
    diagnostics: Vec<ScanDiagnostic>,
    failed: usize,
    macho_signature_targets: Vec<std::path::PathBuf>,
    bundle_signature_targets: Vec<std::path::PathBuf>,
}

fn assemble_scan_result(
    target: &Path,
    target_type: PathType,
    discovery: DiscoveryResult,
    yara_engine: &YaraEngine,
    inspector: &dyn CodeSignatureInspector,
) -> ScanResult {
    let static_output = assemble_static_scan(discovery, yara_engine);
    let code_signatures = inspect_signature_targets(&static_output, inspector);
    let StaticScanOutput {
        artifacts,
        mut diagnostics,
        failed,
        macho_signature_targets: _,
        bundle_signature_targets: _,
    } = static_output;

    let summary = ScanSummary::from_artifacts(failed, &artifacts);
    diagnostics.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| diagnostic_kind_rank(left.kind).cmp(&diagnostic_kind_rank(right.kind)))
            .then_with(|| left.message.cmp(&right.message))
    });

    ScanResult {
        target: target.to_path_buf(),
        target_type,
        artifacts,
        code_signatures,
        diagnostics,
        summary,
    }
}

fn assemble_static_scan(discovery: DiscoveryResult, yara_engine: &YaraEngine) -> StaticScanOutput {
    let DiscoveryResult {
        mut files,
        app_bundles,
        mut diagnostics,
    } = discovery;
    let mut artifacts = Vec::new();
    let mut failed = 0;
    let mut macho_signature_targets = Vec::new();
    files.sort();

    for file in files {
        let collected = match collect_artifact(&file) {
            Ok(collected) => collected,
            Err(error) => {
                failed += 1;
                diagnostics.push(ScanDiagnostic::new(
                    DiagnosticKind::Metadata,
                    Some(file),
                    error,
                ));
                continue;
            }
        };
        let artifact = collected.artifact;

        let mut detector_statuses = Vec::new();
        let mut artifact_diagnostics = Vec::new();
        let mut macho = None;
        let mut macho_dependencies = None;

        if artifact.file_type == ArtifactType::MachO {
            macho_signature_targets.push(artifact.path.clone());

            match inspect_macho(&collected.contents) {
                Ok(info) => {
                    macho = Some(info);
                    detector_statuses.push(DetectorStatus::new(
                        Detector::MachOHeader,
                        DetectorOutcome::Completed,
                    ));
                }
                Err(error) => {
                    artifact_diagnostics.push(ScanDiagnostic::new(
                        DiagnosticKind::MachOHeader,
                        Some(artifact.path.clone()),
                        error,
                    ));
                    detector_statuses.push(DetectorStatus::new(
                        Detector::MachOHeader,
                        DetectorOutcome::Failed,
                    ));
                }
            }

            match inspect_macho_dependencies(&collected.contents, &artifact.path) {
                Ok(dependencies) => {
                    macho_dependencies = Some(dependencies);
                    detector_statuses.push(DetectorStatus::new(
                        Detector::MachODependencies,
                        DetectorOutcome::Completed,
                    ));
                }
                Err(error) => {
                    artifact_diagnostics.push(ScanDiagnostic::new(
                        DiagnosticKind::MachODependencies,
                        Some(artifact.path.clone()),
                        error,
                    ));
                    detector_statuses.push(DetectorStatus::new(
                        Detector::MachODependencies,
                        DetectorOutcome::Failed,
                    ));
                }
            }
        } else {
            detector_statuses.push(DetectorStatus::new(
                Detector::MachOHeader,
                DetectorOutcome::NotApplicable,
            ));
            detector_statuses.push(DetectorStatus::new(
                Detector::MachODependencies,
                DetectorOutcome::NotApplicable,
            ));
        }

        let dependency_context = if artifact.file_type != ArtifactType::MachO {
            MachODependencyContext::NotApplicable
        } else {
            match macho_dependencies.as_ref() {
                Some(dependencies) => MachODependencyContext::Available(dependencies),
                None => MachODependencyContext::Failed,
            }
        };
        let analysis = analyze_artifact_result(
            &artifact,
            &collected.contents,
            yara_engine,
            dependency_context,
        );
        detector_statuses.extend(analysis.detector_statuses);
        artifact_diagnostics.extend(analysis.diagnostics);
        let verdict = determine_verdict(&analysis.evidence);

        artifacts.push(ArtifactResult {
            artifact,
            macho,
            macho_dependencies,
            evidence: analysis.evidence,
            verdict,
            detector_statuses,
            diagnostics: artifact_diagnostics,
        });
    }

    macho_signature_targets.sort();
    macho_signature_targets.dedup();
    let mut bundle_signature_targets = app_bundles;
    bundle_signature_targets.sort();
    bundle_signature_targets.dedup();

    StaticScanOutput {
        artifacts,
        diagnostics,
        failed,
        macho_signature_targets,
        bundle_signature_targets,
    }
}

fn inspect_signature_targets(
    static_output: &StaticScanOutput,
    inspector: &dyn CodeSignatureInspector,
) -> Vec<CodeSignatureInspection> {
    let mut inspections = Vec::with_capacity(
        static_output.macho_signature_targets.len() + static_output.bundle_signature_targets.len(),
    );

    for target in &static_output.macho_signature_targets {
        inspections.push(inspect_signature_target(
            inspector,
            target,
            CodeSignatureTargetKind::MachOFile,
        ));
    }

    for target in &static_output.bundle_signature_targets {
        inspections.push(inspect_signature_target(
            inspector,
            target,
            CodeSignatureTargetKind::ApplicationBundle,
        ));
    }

    inspections.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then_with(|| left.target_kind.cmp(&right.target_kind))
    });
    inspections
}

fn inspect_signature_target(
    inspector: &dyn CodeSignatureInspector,
    target: &Path,
    target_kind: CodeSignatureTargetKind,
) -> CodeSignatureInspection {
    let inspection = inspector.inspect(target, target_kind);
    if inspection.target == target && inspection.target_kind == target_kind {
        return inspection;
    }

    let mut replacement = CodeSignatureInspection::unknown(target.to_path_buf(), target_kind);
    replacement.diagnostics.push(ScanDiagnostic::new(
        DiagnosticKind::CodeSignature,
        Some(target.to_path_buf()),
        format!(
            "code-signature inspector returned a mismatched target identity for {} request",
            target_kind.as_str()
        ),
    ));
    replacement
}

fn diagnostic_kind_rank(kind: DiagnosticKind) -> u8 {
    match kind {
        DiagnosticKind::Discovery => 0,
        DiagnosticKind::Metadata => 1,
        DiagnosticKind::MachOHeader => 2,
        DiagnosticKind::MachODependencies => 3,
        DiagnosticKind::CodeSignature => 4,
        DiagnosticKind::Yara => 5,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    #[cfg(unix)]
    use std::ffi::CString;
    use std::fs;
    use std::io::ErrorKind;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    #[cfg(unix)]
    use std::sync::mpsc::{self, RecvTimeoutError};
    #[cfg(unix)]
    use std::thread;
    #[cfg(unix)]
    use std::time::Duration;

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    use crate::detection::verdict::Verdict;
    use crate::macos::codesign::{
        CodeSignatureInspection, CodeSignatureInspector, CodeSignatureTargetKind,
        NativeCheckStatus, SignatureKind, SignaturePresence,
    };
    use crate::scanner::discovery::DiscoveryResult;
    use crate::scanner::result::{Detector, DetectorOutcome, DetectorStatus, DiagnosticKind};

    use super::*;

    const NO_MATCH_RULE: &str = r#"
        rule harmless_scan_test_rule {
            condition:
                false
        }
    "#;

    const REPLACEMENT_MATCH_RULE: &str = r#"
        rule replacement_content_must_not_be_scanned {
            strings:
                $marker = "AEGISFORGE_ORDER_MARKER"
            condition:
                $marker
        }
    "#;

    static NEXT_TEMP_DIR_ID: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            loop {
                let id = NEXT_TEMP_DIR_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("aegisforge-scan-tests-{}-{id}", std::process::id()));

                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("temporary test directory should be creatable: {error}"),
                }
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write_file(&self, relative_path: impl AsRef<Path>, contents: &[u8]) -> PathBuf {
            let path = self.path.join(relative_path);

            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("temporary test file parent should be creatable");
            }

            fs::write(&path, contents).expect("temporary test file should be writable");
            path
        }

        fn missing_child(&self, name: &str) -> PathBuf {
            let path = self.path.join(name);
            assert!(!path.exists(), "missing test path should not exist");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn no_match_engine() -> YaraEngine {
        YaraEngine::from_source(NO_MATCH_RULE).expect("harmless YARA rule should compile")
    }

    struct FakeCodeSignatureInspector {
        calls: RefCell<Vec<(PathBuf, CodeSignatureTargetKind)>>,
        inspections: RefCell<VecDeque<CodeSignatureInspection>>,
    }

    impl FakeCodeSignatureInspector {
        fn new(inspections: impl IntoIterator<Item = CodeSignatureInspection>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                inspections: RefCell::new(inspections.into_iter().collect()),
            }
        }

        fn calls(&self) -> Vec<(PathBuf, CodeSignatureTargetKind)> {
            self.calls.borrow().clone()
        }
    }

    impl CodeSignatureInspector for FakeCodeSignatureInspector {
        fn inspect(
            &self,
            target: &Path,
            target_kind: CodeSignatureTargetKind,
        ) -> CodeSignatureInspection {
            self.calls
                .borrow_mut()
                .push((target.to_path_buf(), target_kind));
            self.inspections
                .borrow_mut()
                .pop_front()
                .expect("fake inspector should have a queued inspection")
        }
    }

    fn unknown_inspection(
        target: impl Into<PathBuf>,
        target_kind: CodeSignatureTargetKind,
    ) -> CodeSignatureInspection {
        CodeSignatureInspection::unknown(target.into(), target_kind)
    }

    #[test]
    fn content_classified_macho_is_inspected_once() {
        let fixture = TempDir::new();
        let macho = fixture.write_file("tool", &[0xCF, 0xFA, 0xED, 0xFE]);
        let engine = no_match_engine();
        let inspector = FakeCodeSignatureInspector::new([unknown_inspection(
            macho.clone(),
            CodeSignatureTargetKind::MachOFile,
        )]);

        let result = scan_path_with_yara(&macho, &engine, &inspector)
            .expect("Mach-O scan should complete despite parser errors");

        assert_eq!(
            inspector.calls(),
            [(macho.clone(), CodeSignatureTargetKind::MachOFile)]
        );
        assert_eq!(result.code_signatures.len(), 1);
        assert_eq!(result.code_signatures[0].target, macho);
    }

    #[test]
    fn non_macho_is_never_inspected_for_code_signing() {
        let fixture = TempDir::new();
        let ordinary = fixture.write_file("ordinary.txt", b"ordinary content");
        let engine = no_match_engine();
        let inspector = FakeCodeSignatureInspector::new([]);

        let result = scan_path_with_yara(&ordinary, &engine, &inspector)
            .expect("ordinary file scan should complete");

        assert!(inspector.calls().is_empty());
        assert!(result.code_signatures.is_empty());
    }

    #[test]
    fn every_bundle_is_inspected_once_while_bundle_contents_are_analyzed() {
        let fixture = TempDir::new();
        let first_bundle = fixture.path().join("First.app");
        let second_bundle = fixture.path().join("nested/Second.APP");
        fs::create_dir_all(&first_bundle).expect("first bundle should be creatable");
        fs::create_dir_all(&second_bundle).expect("second bundle should be creatable");
        let first_file = fixture.write_file("First.app/Contents/resource.txt", b"first");
        let second_file = fixture.write_file("nested/Second.APP/Contents/resource.txt", b"second");
        let engine = no_match_engine();
        let inspector = FakeCodeSignatureInspector::new([
            unknown_inspection(
                first_bundle.clone(),
                CodeSignatureTargetKind::ApplicationBundle,
            ),
            unknown_inspection(
                second_bundle.clone(),
                CodeSignatureTargetKind::ApplicationBundle,
            ),
        ]);

        let result = scan_path_with_yara(fixture.path(), &engine, &inspector)
            .expect("bundle tree scan should complete");

        assert_eq!(
            inspector.calls(),
            [
                (
                    first_bundle.clone(),
                    CodeSignatureTargetKind::ApplicationBundle,
                ),
                (
                    second_bundle.clone(),
                    CodeSignatureTargetKind::ApplicationBundle,
                ),
            ]
        );
        assert_eq!(
            result
                .artifacts
                .iter()
                .map(|artifact| artifact.artifact.path.clone())
                .collect::<Vec<_>>(),
            [first_file, second_file]
        );
    }

    #[test]
    fn signature_invocations_are_grouped_and_sorted_but_results_are_globally_sorted() {
        let fixture = TempDir::new();
        let a_macho = fixture.write_file("a-tool", &[0xCF, 0xFA, 0xED, 0xFE]);
        let z_macho = fixture.write_file("z-tool", &[0xCF, 0xFA, 0xED, 0xFE]);
        let b_bundle = fixture.path().join("b.app");
        let y_bundle = fixture.path().join("y.app");
        fs::create_dir_all(&b_bundle).expect("bundle should be creatable");
        fs::create_dir_all(&y_bundle).expect("bundle should be creatable");
        let discovery = DiscoveryResult {
            files: vec![z_macho.clone(), a_macho.clone(), z_macho.clone()],
            app_bundles: vec![y_bundle.clone(), b_bundle.clone(), y_bundle.clone()],
            diagnostics: Vec::new(),
        };
        let engine = no_match_engine();
        let inspector = FakeCodeSignatureInspector::new([
            unknown_inspection(a_macho.clone(), CodeSignatureTargetKind::MachOFile),
            unknown_inspection(z_macho.clone(), CodeSignatureTargetKind::MachOFile),
            unknown_inspection(b_bundle.clone(), CodeSignatureTargetKind::ApplicationBundle),
            unknown_inspection(y_bundle.clone(), CodeSignatureTargetKind::ApplicationBundle),
        ]);

        let result = assemble_scan_result(
            fixture.path(),
            PathType::Directory,
            discovery,
            &engine,
            &inspector,
        );

        assert_eq!(
            inspector.calls(),
            [
                (a_macho.clone(), CodeSignatureTargetKind::MachOFile),
                (z_macho.clone(), CodeSignatureTargetKind::MachOFile),
                (b_bundle.clone(), CodeSignatureTargetKind::ApplicationBundle,),
                (y_bundle.clone(), CodeSignatureTargetKind::ApplicationBundle,),
            ]
        );
        assert_eq!(
            result
                .code_signatures
                .iter()
                .map(|inspection| (inspection.target.clone(), inspection.target_kind))
                .collect::<Vec<_>>(),
            [
                (a_macho, CodeSignatureTargetKind::MachOFile),
                (b_bundle, CodeSignatureTargetKind::ApplicationBundle),
                (y_bundle, CodeSignatureTargetKind::ApplicationBundle),
                (z_macho, CodeSignatureTargetKind::MachOFile),
            ]
        );
    }

    #[test]
    fn signature_results_use_target_kind_as_the_path_tiebreaker() {
        let shared_target = PathBuf::from("same-target");
        let static_output = StaticScanOutput {
            artifacts: Vec::new(),
            diagnostics: Vec::new(),
            failed: 0,
            macho_signature_targets: vec![shared_target.clone()],
            bundle_signature_targets: vec![shared_target.clone()],
        };
        let inspector = FakeCodeSignatureInspector::new([
            unknown_inspection(shared_target.clone(), CodeSignatureTargetKind::MachOFile),
            unknown_inspection(
                shared_target.clone(),
                CodeSignatureTargetKind::ApplicationBundle,
            ),
        ]);

        let inspections = inspect_signature_targets(&static_output, &inspector);

        assert_eq!(
            inspections
                .iter()
                .map(|inspection| (inspection.target.clone(), inspection.target_kind))
                .collect::<Vec<_>>(),
            [
                (shared_target.clone(), CodeSignatureTargetKind::MachOFile),
                (shared_target, CodeSignatureTargetKind::ApplicationBundle),
            ]
        );
    }

    #[test]
    fn mismatched_inspector_identity_is_replaced_without_copying_untrusted_facts() {
        let requested_macho = PathBuf::from("a-requested-macho");
        let requested_bundle = PathBuf::from("b-requested.app");
        let later_bundle = PathBuf::from("z-later.app");
        let static_output = StaticScanOutput {
            artifacts: Vec::new(),
            diagnostics: Vec::new(),
            failed: 0,
            macho_signature_targets: vec![requested_macho.clone()],
            bundle_signature_targets: vec![requested_bundle.clone(), later_bundle.clone()],
        };
        let untrusted_diagnostic = ScanDiagnostic::new(
            DiagnosticKind::CodeSignature,
            Some(PathBuf::from("untrusted-path")),
            "untrusted diagnostic".to_string(),
        );
        let mut mismatched_path = unknown_inspection(
            PathBuf::from("different-target"),
            CodeSignatureTargetKind::MachOFile,
        );
        mismatched_path.presence = SignaturePresence::Signed;
        mismatched_path.verification_status = NativeCheckStatus::Passed;
        mismatched_path.metadata_status = NativeCheckStatus::Passed;
        mismatched_path.identifier = Some("untrusted.identifier".to_string());
        mismatched_path.team_identifier = Some("UNTRUSTEDTEAM".to_string());
        mismatched_path.authorities = vec!["Untrusted Authority".to_string()];
        mismatched_path.signature_kind = SignatureKind::CertificateBacked;
        mismatched_path.hardened_runtime = Some(true);
        mismatched_path.verification_detail = Some("untrusted detail".to_string());
        mismatched_path
            .diagnostics
            .push(untrusted_diagnostic.clone());
        let mut mismatched_kind =
            unknown_inspection(requested_bundle.clone(), CodeSignatureTargetKind::MachOFile);
        mismatched_kind.identifier = Some("also.untrusted".to_string());
        mismatched_kind.diagnostics.push(untrusted_diagnostic);
        let valid_later = unknown_inspection(
            later_bundle.clone(),
            CodeSignatureTargetKind::ApplicationBundle,
        );
        let inspector = FakeCodeSignatureInspector::new([
            mismatched_path,
            mismatched_kind,
            valid_later.clone(),
        ]);

        let inspections = inspect_signature_targets(&static_output, &inspector);

        assert_eq!(inspector.calls().len(), 3, "later targets must still run");
        assert_eq!(inspections.len(), 3);
        for (inspection, requested_target, requested_kind) in [
            (
                &inspections[0],
                &requested_macho,
                CodeSignatureTargetKind::MachOFile,
            ),
            (
                &inspections[1],
                &requested_bundle,
                CodeSignatureTargetKind::ApplicationBundle,
            ),
        ] {
            let mut expected =
                CodeSignatureInspection::unknown(requested_target.clone(), requested_kind);
            expected.diagnostics.push(ScanDiagnostic::new(
                DiagnosticKind::CodeSignature,
                Some(requested_target.clone()),
                format!(
                    "code-signature inspector returned a mismatched target identity for {} request",
                    requested_kind.as_str()
                ),
            ));
            assert_eq!(inspection, &expected);
        }
        assert_eq!(inspections[2], valid_later);
    }

    #[test]
    fn failed_signature_is_retained_and_later_targets_continue() {
        let fixture = TempDir::new();
        let first = fixture.write_file("a-tool", &[0xCF, 0xFA, 0xED, 0xFE]);
        let later = fixture.write_file("z-tool", &[0xCF, 0xFA, 0xED, 0xFE]);
        let failure_diagnostic = ScanDiagnostic::new(
            DiagnosticKind::CodeSignature,
            Some(first.clone()),
            "native inspection unavailable".to_string(),
        );
        let mut failed = unknown_inspection(first.clone(), CodeSignatureTargetKind::MachOFile);
        failed.verification_status = NativeCheckStatus::Unavailable;
        failed.metadata_status = NativeCheckStatus::Failed;
        failed.diagnostics.push(failure_diagnostic.clone());
        let inspector = FakeCodeSignatureInspector::new([
            failed,
            unknown_inspection(later.clone(), CodeSignatureTargetKind::MachOFile),
        ]);
        let discovery = DiscoveryResult {
            files: vec![later.clone(), first.clone()],
            app_bundles: Vec::new(),
            diagnostics: Vec::new(),
        };

        let result = assemble_scan_result(
            fixture.path(),
            PathType::Directory,
            discovery,
            &no_match_engine(),
            &inspector,
        );

        assert_eq!(inspector.calls().len(), 2);
        assert_eq!(result.code_signatures.len(), 2);
        assert_eq!(result.code_signatures[0].target, first);
        assert_eq!(
            result.code_signatures[0].verification_status,
            NativeCheckStatus::Unavailable
        );
        assert_eq!(
            result.code_signatures[0].metadata_status,
            NativeCheckStatus::Failed
        );
        assert_eq!(result.code_signatures[0].diagnostics, [failure_diagnostic]);
        assert_eq!(result.code_signatures[1].target, later);
    }

    #[test]
    fn signature_results_do_not_change_artifact_analysis_or_summary() {
        let fixture = TempDir::new();
        let macho = fixture.write_file("tool", &[0xCF, 0xFA, 0xED, 0xFE]);
        let bundle = fixture.path().join("Tool.app");
        fs::create_dir(&bundle).expect("bundle should be creatable");
        let discovery = DiscoveryResult {
            files: vec![macho.clone()],
            app_bundles: vec![bundle.clone()],
            diagnostics: Vec::new(),
        };
        let inspector = FakeCodeSignatureInspector::new([
            unknown_inspection(macho, CodeSignatureTargetKind::MachOFile),
            unknown_inspection(bundle, CodeSignatureTargetKind::ApplicationBundle),
        ]);

        let result = assemble_scan_result(
            fixture.path(),
            PathType::Directory,
            discovery,
            &no_match_engine(),
            &inspector,
        );

        assert_eq!(result.summary.discovered, 1);
        assert_eq!(result.summary.analyzed, 1);
        assert_eq!(result.summary.failed, 0);
        assert_eq!(result.summary.unknown, 1);
        assert_eq!(result.summary.suspicious, 0);
        assert_eq!(result.summary.malicious, 0);
        assert_eq!(result.artifacts[0].verdict, Verdict::Unknown);
        assert!(result.artifacts[0].evidence.is_empty());
        assert_eq!(result.code_signatures.len(), 2);
    }

    #[test]
    fn static_phase_completes_artifacts_and_targets_without_native_access() {
        let fixture = TempDir::new();
        let macho = fixture.write_file("tool", &[0xCF, 0xFA, 0xED, 0xFE]);
        let ordinary = fixture.write_file("ordinary", b"ordinary");
        let bundle = fixture.path().join("Tool.app");
        fs::create_dir(&bundle).expect("bundle should be creatable");
        let discovery = DiscoveryResult {
            files: vec![ordinary.clone(), macho.clone()],
            app_bundles: vec![bundle.clone()],
            diagnostics: Vec::new(),
        };
        let inspector = FakeCodeSignatureInspector::new([]);

        let static_output = assemble_static_scan(discovery, &no_match_engine());

        assert!(inspector.calls().is_empty());
        assert_eq!(static_output.artifacts.len(), 2);
        assert_eq!(static_output.macho_signature_targets, [macho]);
        assert_eq!(static_output.bundle_signature_targets, [bundle]);
        assert_eq!(static_output.failed, 0);
        assert_eq!(
            static_output
                .artifacts
                .iter()
                .map(|artifact| artifact.artifact.path.clone())
                .collect::<Vec<_>>(),
            [ordinary, fixture.path().join("tool")]
        );
    }

    #[test]
    fn native_phase_accepts_completed_static_output_and_inspects_all_pending_targets() {
        let fixture = TempDir::new();
        let macho = fixture.write_file("tool", &[0xCF, 0xFA, 0xED, 0xFE]);
        let bundle = fixture.path().join("Tool.app");
        fs::create_dir(&bundle).expect("bundle should be creatable");
        let static_output = assemble_static_scan(
            DiscoveryResult {
                files: vec![macho.clone()],
                app_bundles: vec![bundle.clone()],
                diagnostics: Vec::new(),
            },
            &no_match_engine(),
        );
        let inspector = FakeCodeSignatureInspector::new([
            unknown_inspection(macho.clone(), CodeSignatureTargetKind::MachOFile),
            unknown_inspection(bundle.clone(), CodeSignatureTargetKind::ApplicationBundle),
        ]);

        let inspections = inspect_signature_targets(&static_output, &inspector);

        assert_eq!(inspections.len(), 2);
        assert_eq!(
            inspector.calls(),
            [
                (macho, CodeSignatureTargetKind::MachOFile),
                (bundle, CodeSignatureTargetKind::ApplicationBundle),
            ]
        );
    }

    #[test]
    fn non_macho_scan_marks_macho_detectors_not_applicable() {
        let fixture = TempDir::new();
        let path = fixture.write_file("ordinary.txt", b"ordinary readable content");
        let engine = no_match_engine();
        let inspector = FakeCodeSignatureInspector::new([]);

        let result = scan_path_with_yara(&path, &engine, &inspector).expect("scan should succeed");

        assert_eq!(result.target, path);
        assert_eq!(result.target_type, PathType::File);
        assert_eq!(result.summary.discovered, 1);
        assert_eq!(result.summary.analyzed, 1);
        assert_eq!(result.summary.failed, 0);
        assert_eq!(result.artifacts[0].verdict, Verdict::Unknown);
        assert_eq!(
            result.artifacts[0].detector_statuses,
            vec![
                DetectorStatus::new(Detector::MachOHeader, DetectorOutcome::NotApplicable),
                DetectorStatus::new(Detector::MachODependencies, DetectorOutcome::NotApplicable,),
                DetectorStatus::new(Detector::FileTypeMismatch, DetectorOutcome::Completed),
                DetectorStatus::new(Detector::RiskyRpath, DetectorOutcome::NotApplicable),
                DetectorStatus::new(Detector::Yara, DetectorOutcome::Completed),
            ]
        );
    }

    #[test]
    fn scan_results_are_deterministic() {
        let fixture = TempDir::new();
        fixture.write_file("z.txt", b"z");
        fixture.write_file("nested/b.txt", b"b");
        fixture.write_file("a.txt", b"a");
        let engine = no_match_engine();
        let inspector = FakeCodeSignatureInspector::new([]);

        let result = scan_path_with_yara(fixture.path(), &engine, &inspector)
            .expect("directory scan should succeed");
        let relative_paths: Vec<_> = result
            .artifacts
            .iter()
            .map(|artifact| {
                artifact
                    .artifact
                    .path
                    .strip_prefix(fixture.path())
                    .expect("artifact should belong to fixture")
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();

        assert_eq!(relative_paths, ["a.txt", "nested/b.txt", "z.txt"]);
        assert_eq!(result.summary.discovered, 3);
        assert_eq!(result.summary.analyzed, 3);
    }

    #[test]
    fn metadata_failure_does_not_abort_later_artifact() {
        let fixture = TempDir::new();
        let missing = fixture.missing_child("missing.txt");
        let readable = fixture.write_file("readable.txt", b"readable");
        let discovery = DiscoveryResult {
            files: vec![missing.clone(), readable.clone()],
            app_bundles: Vec::new(),
            diagnostics: Vec::new(),
        };
        let engine = no_match_engine();
        let inspector = FakeCodeSignatureInspector::new([]);

        let result = assemble_scan_result(
            fixture.path(),
            PathType::Directory,
            discovery,
            &engine,
            &inspector,
        );

        assert_eq!(result.summary.discovered, 2);
        assert_eq!(result.summary.analyzed, 1);
        assert_eq!(result.summary.failed, 1);
        assert_eq!(result.artifacts.len(), 1);
        assert_eq!(result.artifacts[0].artifact.path, readable);
        assert_eq!(result.diagnostics.len(), 1);
        assert_eq!(result.diagnostics[0].kind, DiagnosticKind::Metadata);
        assert_eq!(result.diagnostics[0].path.as_ref(), Some(&missing));
        assert!(
            result.diagnostics[0]
                .message
                .contains("Failed to read metadata")
        );
        assert!(
            result.diagnostics[0]
                .message
                .contains(&missing.display().to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn discovered_path_replaced_by_symlink_is_not_analyzed() {
        let fixture = TempDir::new();
        let discovered_path = fixture.write_file("candidate", b"original harmless bytes");
        let outside_path = fixture.write_file("outside", b"AEGISFORGE_ORDER_MARKER");
        fs::remove_file(&discovered_path).expect("candidate should be removable");
        symlink(&outside_path, &discovered_path).expect("replacement symlink should be creatable");
        let discovery = DiscoveryResult {
            files: vec![discovered_path.clone()],
            app_bundles: Vec::new(),
            diagnostics: Vec::new(),
        };
        let engine = YaraEngine::from_source(REPLACEMENT_MATCH_RULE)
            .expect("replacement-detecting YARA rule should compile");
        let inspector = FakeCodeSignatureInspector::new([]);

        let result = assemble_scan_result(
            fixture.path(),
            PathType::Directory,
            discovery,
            &engine,
            &inspector,
        );

        assert_eq!(result.summary.discovered, 1);
        assert_eq!(result.summary.analyzed, 0);
        assert_eq!(result.summary.failed, 1);
        assert!(result.artifacts.is_empty());
        assert_eq!(result.diagnostics.len(), 1);
        assert_eq!(result.diagnostics[0].kind, DiagnosticKind::Metadata);
        assert_eq!(result.diagnostics[0].path.as_ref(), Some(&discovered_path));
    }

    #[cfg(unix)]
    #[test]
    fn discovered_path_replaced_by_fifo_fails_promptly() {
        let fixture = TempDir::new();
        let fifo_path = fixture.write_file("candidate", b"placeholder");
        fs::remove_file(&fifo_path).expect("placeholder should be removable");
        let fifo_c_path = CString::new(fifo_path.as_os_str().as_bytes())
            .expect("temporary path should not contain NUL bytes");

        // SAFETY: `fifo_c_path` is a valid, NUL-terminated path and the mode is valid.
        let status = unsafe { libc::mkfifo(fifo_c_path.as_ptr(), 0o600) };
        assert_eq!(status, 0, "FIFO fixture should be creatable");

        let target = fixture.path().to_path_buf();
        let worker_fifo_path = fifo_path.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let discovery = DiscoveryResult {
                files: vec![worker_fifo_path],
                app_bundles: Vec::new(),
                diagnostics: Vec::new(),
            };
            let engine = no_match_engine();
            let inspector = FakeCodeSignatureInspector::new([]);
            let result =
                assemble_scan_result(&target, PathType::Directory, discovery, &engine, &inspector);
            let _ = sender.send(result);
        });

        let result = match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                let unblocker = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&fifo_path)
                    .expect("FIFO should be openable read/write to unblock the worker");
                let _ = receiver.recv_timeout(Duration::from_secs(1));
                worker.join().expect("scan worker should join");
                drop(unblocker);
                panic!("artifact scan blocked while opening a FIFO");
            }
            Err(RecvTimeoutError::Disconnected) => {
                worker.join().expect("scan worker should join");
                panic!("scan worker disconnected without a result");
            }
        };

        worker.join().expect("scan worker should join");
        assert_eq!(result.summary.discovered, 1);
        assert_eq!(result.summary.analyzed, 0);
        assert_eq!(result.summary.failed, 1);
        assert!(result.artifacts.is_empty());
        assert_eq!(result.diagnostics.len(), 1);
        assert_eq!(result.diagnostics[0].kind, DiagnosticKind::Metadata);
        assert_eq!(result.diagnostics[0].path.as_ref(), Some(&fifo_path));
        assert!(result.diagnostics[0].message.contains("not a regular file"));
    }

    #[test]
    fn discovered_non_regular_path_is_not_analyzed() {
        let fixture = TempDir::new();
        let directory_path = fixture.path().join("unexpected-directory");
        fs::create_dir(&directory_path).expect("fixture directory should be creatable");
        let discovery = DiscoveryResult {
            files: vec![directory_path.clone()],
            app_bundles: Vec::new(),
            diagnostics: Vec::new(),
        };
        let engine = no_match_engine();
        let inspector = FakeCodeSignatureInspector::new([]);

        let result = assemble_scan_result(
            fixture.path(),
            PathType::Directory,
            discovery,
            &engine,
            &inspector,
        );

        assert_eq!(result.summary.discovered, 1);
        assert_eq!(result.summary.analyzed, 0);
        assert_eq!(result.summary.failed, 1);
        assert!(result.artifacts.is_empty());
        assert_eq!(result.diagnostics.len(), 1);
        assert_eq!(result.diagnostics[0].kind, DiagnosticKind::Metadata);
        assert_eq!(result.diagnostics[0].path.as_ref(), Some(&directory_path));
        assert!(result.diagnostics[0].message.contains("not a regular file"));
    }

    #[test]
    fn scan_diagnostics_are_sorted() {
        let fixture = TempDir::new();
        let a_path = fixture.path().join("a.txt");
        let z_path = fixture.path().join("z.txt");
        let discovery = DiscoveryResult {
            files: Vec::new(),
            app_bundles: Vec::new(),
            diagnostics: vec![
                ScanDiagnostic::new(
                    DiagnosticKind::Discovery,
                    Some(z_path.clone()),
                    "z path".to_string(),
                ),
                ScanDiagnostic::new(
                    DiagnosticKind::Yara,
                    Some(a_path.clone()),
                    "yara diagnostic".to_string(),
                ),
                ScanDiagnostic::new(
                    DiagnosticKind::CodeSignature,
                    Some(a_path.clone()),
                    "signature diagnostic".to_string(),
                ),
                ScanDiagnostic::new(
                    DiagnosticKind::Discovery,
                    Some(a_path.clone()),
                    "beta".to_string(),
                ),
                ScanDiagnostic::new(
                    DiagnosticKind::Discovery,
                    Some(a_path.clone()),
                    "alpha".to_string(),
                ),
            ],
        };
        let engine = no_match_engine();
        let inspector = FakeCodeSignatureInspector::new([]);

        let result = assemble_scan_result(
            fixture.path(),
            PathType::Directory,
            discovery,
            &engine,
            &inspector,
        );

        assert_eq!(
            result.diagnostics,
            vec![
                ScanDiagnostic::new(
                    DiagnosticKind::Discovery,
                    Some(a_path.clone()),
                    "alpha".to_string(),
                ),
                ScanDiagnostic::new(
                    DiagnosticKind::Discovery,
                    Some(a_path.clone()),
                    "beta".to_string(),
                ),
                ScanDiagnostic::new(
                    DiagnosticKind::CodeSignature,
                    Some(a_path.clone()),
                    "signature diagnostic".to_string(),
                ),
                ScanDiagnostic::new(
                    DiagnosticKind::Yara,
                    Some(a_path),
                    "yara diagnostic".to_string(),
                ),
                ScanDiagnostic::new(
                    DiagnosticKind::Discovery,
                    Some(z_path),
                    "z path".to_string(),
                ),
            ]
        );
    }

    #[test]
    fn malformed_macho_records_independent_failures() {
        let fixture = TempDir::new();
        let path = fixture.write_file("malformed", &[0xCF, 0xFA, 0xED, 0xFE]);
        let engine = no_match_engine();
        let inspector = FakeCodeSignatureInspector::new([unknown_inspection(
            path.clone(),
            CodeSignatureTargetKind::MachOFile,
        )]);

        let result = scan_path_with_yara(&path, &engine, &inspector).expect("scan should complete");
        let artifact = &result.artifacts[0];

        assert_eq!(artifact.verdict, Verdict::Unknown);
        assert_eq!(
            artifact.detector_statuses,
            vec![
                DetectorStatus::new(Detector::MachOHeader, DetectorOutcome::Failed),
                DetectorStatus::new(Detector::MachODependencies, DetectorOutcome::Failed),
                DetectorStatus::new(Detector::FileTypeMismatch, DetectorOutcome::Completed),
                DetectorStatus::new(Detector::RiskyRpath, DetectorOutcome::Skipped),
                DetectorStatus::new(Detector::Yara, DetectorOutcome::Completed),
            ]
        );
        assert_eq!(artifact.diagnostics.len(), 2);
        assert_eq!(artifact.diagnostics[0].kind, DiagnosticKind::MachOHeader);
        assert_eq!(
            artifact.diagnostics[1].kind,
            DiagnosticKind::MachODependencies
        );
        assert!(
            artifact
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.path.as_ref() == Some(&path))
        );
    }
}
