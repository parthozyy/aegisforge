use crate::scanner::artifact::Artifact;

use super::evidence::{Evidence, EvidenceKind, Severity};
use super::file_mismatch::detect_file_type_mismatch;
use super::yara::YaraEngine;

pub fn analyze_artifact(
    artifact: &Artifact,
    yara_engine: &YaraEngine,
) -> Result<Vec<Evidence>, String> {
    let mut evidence = Vec::new();

    evidence.extend(detect_file_type_mismatch(artifact));

    let yara_matches = yara_engine.scan_file(&artifact.path)?;

    for rule_name in yara_matches {
        evidence.push(Evidence::new(
            EvidenceKind::YaraRuleMatch,
            Severity::High,
            format!("YARA rule matched: {rule_name}"),
        ));
    }

    Ok(evidence)
}
