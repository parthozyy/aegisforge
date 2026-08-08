use crate::scanner::artifact::Artifact;
use crate::scanner::macho_dependencies::MachODependencies;
use crate::scanner::result::{
    Detector, DetectorOutcome, DetectorStatus, DiagnosticKind, ScanDiagnostic,
};

use super::evidence::{Evidence, EvidenceKind, Severity};
use super::file_mismatch::detect_file_type_mismatch;
use super::rpath_risk::detect_rpath_risk;
use super::yara::YaraEngine;

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

pub fn analyze_artifact_result(
    artifact: &Artifact,
    contents: &[u8],
    yara_engine: &YaraEngine,
    macho_dependencies: MachODependencyContext<'_>,
) -> AnalysisResult {
    analyze_artifact_with_yara(artifact, macho_dependencies, || {
        yara_engine.scan_bytes(contents)
    })
}

fn analyze_artifact_with_yara(
    artifact: &Artifact,
    macho_dependencies: MachODependencyContext<'_>,
    scan_yara: impl FnOnce() -> Result<Vec<String>, String>,
) -> AnalysisResult {
    let mut evidence = detect_file_type_mismatch(artifact);
    let mut detector_statuses = vec![DetectorStatus::new(
        Detector::FileTypeMismatch,
        DetectorOutcome::Completed,
    )];
    let mut diagnostics = Vec::new();

    match macho_dependencies {
        MachODependencyContext::Available(dependencies) => {
            evidence.extend(detect_rpath_risk(dependencies));
            detector_statuses.push(DetectorStatus::new(
                Detector::RiskyRpath,
                DetectorOutcome::Completed,
            ));
        }
        MachODependencyContext::NotApplicable => {
            detector_statuses.push(DetectorStatus::new(
                Detector::RiskyRpath,
                DetectorOutcome::NotApplicable,
            ));
        }
        MachODependencyContext::Failed => {
            detector_statuses.push(DetectorStatus::new(
                Detector::RiskyRpath,
                DetectorOutcome::Skipped,
            ));
        }
    }

    match scan_yara() {
        Ok(mut yara_matches) => {
            yara_matches.sort();

            for rule_name in yara_matches {
                evidence.push(Evidence::new(
                    EvidenceKind::YaraRuleMatch,
                    Severity::High,
                    format!("YARA rule matched: {rule_name}"),
                ));
            }
            detector_statuses.push(DetectorStatus::new(
                Detector::Yara,
                DetectorOutcome::Completed,
            ));
        }
        Err(error) => {
            diagnostics.push(ScanDiagnostic::new(
                DiagnosticKind::Yara,
                Some(artifact.path.clone()),
                error,
            ));
            detector_statuses.push(DetectorStatus::new(Detector::Yara, DetectorOutcome::Failed));
        }
    }

    AnalysisResult {
        evidence,
        detector_statuses,
        diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::ErrorKind;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::scanner::file_type::ArtifactType;
    use crate::scanner::result::{Detector, DetectorOutcome, DetectorStatus, DiagnosticKind};

    use super::*;

    const TEST_RULE: &str = r#"
        rule harmless_analyzer_test_rule {
            condition:
                false
        }
    "#;

    const REVERSE_ORDER_MATCHING_RULES: &str = r#"
        rule z_rule {
            strings:
                $marker = "AEGISFORGE_ORDER_MARKER"
            condition:
                $marker
        }

        rule a_rule {
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
                let path = std::env::temp_dir().join(format!(
                    "aegisforge-analyzer-tests-{}-{id}",
                    std::process::id()
                ));

                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("temporary test directory should be creatable: {error}"),
                }
            }
        }

        fn write_file(&self, name: &str, contents: &[u8]) -> PathBuf {
            let path = self.path.join(name);
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

    fn artifact(path: PathBuf, file_type: ArtifactType) -> Artifact {
        Artifact::new(
            path,
            0,
            Some("jpg".to_string()),
            "test-sha256".to_string(),
            file_type,
        )
    }

    fn assert_status(result: &AnalysisResult, detector: Detector, outcome: DetectorOutcome) {
        assert!(
            result
                .detector_statuses
                .iter()
                .any(|status| { status.detector == detector && status.outcome == outcome })
        );
    }

    #[test]
    fn yara_failure_preserves_completed_detector_evidence() {
        let temp_dir = TempDir::new();
        let missing_path = temp_dir.missing_child("missing.jpg");
        let artifact = artifact(missing_path.clone(), ArtifactType::MachO);

        let dependencies = MachODependencies {
            libraries: vec!["@rpath/libExample.dylib".to_string()],
            rpaths: vec!["/tmp/plugins".to_string()],
        };

        let result = analyze_artifact_with_yara(
            &artifact,
            MachODependencyContext::Available(&dependencies),
            || Err("simulated YARA failure".to_string()),
        );

        assert!(
            result
                .evidence
                .iter()
                .any(|evidence| evidence.kind == EvidenceKind::FileTypeMismatch)
        );
        assert!(
            result
                .evidence
                .iter()
                .any(|evidence| evidence.kind == EvidenceKind::RiskyRpath)
        );
        assert!(
            result
                .evidence
                .iter()
                .all(|evidence| evidence.kind != EvidenceKind::YaraRuleMatch)
        );
        assert_eq!(
            result.detector_statuses,
            vec![
                DetectorStatus::new(Detector::FileTypeMismatch, DetectorOutcome::Completed),
                DetectorStatus::new(Detector::RiskyRpath, DetectorOutcome::Completed),
                DetectorStatus::new(Detector::Yara, DetectorOutcome::Failed),
            ]
        );
        assert_eq!(result.diagnostics.len(), 1);
        assert_eq!(result.diagnostics[0].kind, DiagnosticKind::Yara);
        assert_eq!(result.diagnostics[0].path.as_ref(), Some(&missing_path));
        assert_eq!(result.diagnostics[0].message, "simulated YARA failure");
    }

    #[test]
    fn non_macho_dependencies_mark_rpath_not_applicable() {
        let temp_dir = TempDir::new();
        let path = temp_dir.write_file("readable.jpg", b"ordinary readable test data");
        let engine = YaraEngine::from_source(TEST_RULE).expect("YARA rule should compile");
        let artifact = artifact(path, ArtifactType::Unknown);

        let result = analyze_artifact_result(
            &artifact,
            b"ordinary readable test data",
            &engine,
            MachODependencyContext::NotApplicable,
        );

        assert_status(
            &result,
            Detector::RiskyRpath,
            DetectorOutcome::NotApplicable,
        );
    }

    #[test]
    fn available_safe_dependencies_complete_without_rpath_evidence() {
        let temp_dir = TempDir::new();
        let path = temp_dir.write_file("readable.jpg", b"ordinary readable test data");
        let engine = YaraEngine::from_source(TEST_RULE).expect("YARA rule should compile");
        let artifact = artifact(path, ArtifactType::MachO);
        let dependencies = MachODependencies {
            libraries: Vec::new(),
            rpaths: Vec::new(),
        };

        let result = analyze_artifact_result(
            &artifact,
            b"ordinary readable test data",
            &engine,
            MachODependencyContext::Available(&dependencies),
        );

        assert_status(&result, Detector::RiskyRpath, DetectorOutcome::Completed);
        assert!(
            result
                .evidence
                .iter()
                .all(|evidence| evidence.kind != EvidenceKind::RiskyRpath)
        );
    }

    #[test]
    fn successful_yara_records_completed_status() {
        let temp_dir = TempDir::new();
        let path = temp_dir.write_file("readable.jpg", b"ordinary readable test data");
        let engine = YaraEngine::from_source(TEST_RULE).expect("YARA rule should compile");
        let artifact = artifact(path, ArtifactType::MachO);

        let result = analyze_artifact_result(
            &artifact,
            b"ordinary readable test data",
            &engine,
            MachODependencyContext::NotApplicable,
        );

        assert_status(&result, Detector::Yara, DetectorOutcome::Completed);
        assert!(result.diagnostics.is_empty());
    }

    #[test]
    fn yara_match_evidence_is_sorted_after_preceding_detector_evidence() {
        let temp_dir = TempDir::new();
        let path = temp_dir.write_file("matching.jpg", b"AEGISFORGE_ORDER_MARKER");
        let engine = YaraEngine::from_source(REVERSE_ORDER_MATCHING_RULES)
            .expect("YARA rules should compile");
        let artifact = artifact(path, ArtifactType::MachO);
        let dependencies = MachODependencies {
            libraries: vec!["@rpath/libExample.dylib".to_string()],
            rpaths: vec!["/tmp/plugins".to_string()],
        };

        let result = analyze_artifact_result(
            &artifact,
            b"AEGISFORGE_ORDER_MARKER",
            &engine,
            MachODependencyContext::Available(&dependencies),
        );

        assert_eq!(
            result
                .evidence
                .iter()
                .map(|evidence| evidence.kind)
                .collect::<Vec<_>>(),
            vec![
                EvidenceKind::FileTypeMismatch,
                EvidenceKind::RiskyRpath,
                EvidenceKind::YaraRuleMatch,
                EvidenceKind::YaraRuleMatch,
            ]
        );
        assert_eq!(result.evidence[2].message, "YARA rule matched: a_rule");
        assert_eq!(result.evidence[3].message, "YARA rule matched: z_rule");
    }
}
