use std::path::PathBuf;

use crate::detection::evidence::Evidence;
use crate::detection::verdict::Verdict;

use super::artifact::Artifact;
use super::macho::MachOInfo;
use super::macho_dependencies::MachODependencies;
use super::path::PathType;

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

impl ScanDiagnostic {
    pub fn new(kind: DiagnosticKind, path: Option<PathBuf>, message: String) -> Self {
        Self {
            kind,
            path,
            message,
        }
    }
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
    /// Reserved for detectors whose platform capability is unavailable.
    #[allow(dead_code)]
    Unavailable,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorStatus {
    pub detector: Detector,
    pub outcome: DetectorOutcome,
}

impl DetectorStatus {
    pub fn new(detector: Detector, outcome: DetectorOutcome) -> Self {
        Self { detector, outcome }
    }
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

impl ScanSummary {
    pub fn from_artifacts(failed: usize, artifacts: &[ArtifactResult]) -> Self {
        let analyzed = artifacts.len();
        let mut unknown = 0;
        let mut suspicious = 0;
        let mut malicious = 0;

        for artifact in artifacts {
            match artifact.verdict {
                Verdict::Unknown => unknown += 1,
                Verdict::Suspicious => suspicious += 1,
                Verdict::Malicious => malicious += 1,
            }
        }

        Self {
            discovered: analyzed + failed,
            analyzed,
            failed,
            unknown,
            suspicious,
            malicious,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub target: PathBuf,
    pub target_type: PathType,
    pub artifacts: Vec<ArtifactResult>,
    pub diagnostics: Vec<ScanDiagnostic>,
    pub summary: ScanSummary,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::detection::verdict::Verdict;
    use crate::scanner::artifact::Artifact;
    use crate::scanner::file_type::ArtifactType;

    fn artifact_result(verdict: Verdict) -> ArtifactResult {
        ArtifactResult {
            artifact: Artifact::new(
                PathBuf::from("sample"),
                0,
                None,
                String::new(),
                ArtifactType::Unknown,
            ),
            macho: None,
            macho_dependencies: None,
            evidence: Vec::new(),
            verdict,
            detector_statuses: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn summary_derives_discovered_from_explicit_failures_and_counts_every_verdict() {
        let artifacts = vec![
            artifact_result(Verdict::Unknown),
            artifact_result(Verdict::Suspicious),
            artifact_result(Verdict::Malicious),
        ];

        let summary = ScanSummary::from_artifacts(1, &artifacts);

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
}
