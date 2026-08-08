use std::path::Path;

use crate::detection::analyzer::{MachODependencyContext, analyze_artifact_result};
use crate::detection::verdict::determine_verdict;
use crate::detection::yara::YaraEngine;

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

    Ok(assemble_scan_result(
        path,
        target_type,
        discovery,
        &yara_engine,
    ))
}

#[cfg(test)]
fn scan_path_with_yara(path: &Path, yara_engine: &YaraEngine) -> Result<ScanResult, String> {
    let target_type = inspect_path(path)?;
    let discovery = discover_files_with_diagnostics(path)?;

    Ok(assemble_scan_result(
        path,
        target_type,
        discovery,
        yara_engine,
    ))
}

fn assemble_scan_result(
    target: &Path,
    target_type: PathType,
    mut discovery: DiscoveryResult,
    yara_engine: &YaraEngine,
) -> ScanResult {
    let mut diagnostics = discovery.diagnostics;
    let mut artifacts = Vec::new();
    let mut failed = 0;
    discovery.files.sort();

    for file in discovery.files {
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
        diagnostics,
        summary,
    }
}

fn diagnostic_kind_rank(kind: DiagnosticKind) -> u8 {
    match kind {
        DiagnosticKind::Discovery => 0,
        DiagnosticKind::Metadata => 1,
        DiagnosticKind::MachOHeader => 2,
        DiagnosticKind::MachODependencies => 3,
        DiagnosticKind::Yara => 4,
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn non_macho_scan_marks_macho_detectors_not_applicable() {
        let fixture = TempDir::new();
        let path = fixture.write_file("ordinary.txt", b"ordinary readable content");
        let engine = no_match_engine();

        let result = scan_path_with_yara(&path, &engine).expect("scan should succeed");

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

        let result =
            scan_path_with_yara(fixture.path(), &engine).expect("directory scan should succeed");
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
            diagnostics: Vec::new(),
        };
        let engine = no_match_engine();

        let result = assemble_scan_result(fixture.path(), PathType::Directory, discovery, &engine);

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
            diagnostics: Vec::new(),
        };
        let engine = YaraEngine::from_source(REPLACEMENT_MATCH_RULE)
            .expect("replacement-detecting YARA rule should compile");

        let result = assemble_scan_result(fixture.path(), PathType::Directory, discovery, &engine);

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
                diagnostics: Vec::new(),
            };
            let engine = no_match_engine();
            let result = assemble_scan_result(&target, PathType::Directory, discovery, &engine);
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
            diagnostics: Vec::new(),
        };
        let engine = no_match_engine();

        let result = assemble_scan_result(fixture.path(), PathType::Directory, discovery, &engine);

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

        let result = assemble_scan_result(fixture.path(), PathType::Directory, discovery, &engine);

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

        let result = scan_path_with_yara(&path, &engine).expect("scan should complete");
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
