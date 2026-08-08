use crate::scanner::artifact::Artifact;

use super::evidence::Evidence;
use super::file_mismatch::detect_file_type_mismatch;

pub fn analyze_artifact(artifact: &Artifact) -> Vec<Evidence> {
    let mut evidence = Vec::new();

    evidence.extend(detect_file_type_mismatch(artifact));

    evidence
}
