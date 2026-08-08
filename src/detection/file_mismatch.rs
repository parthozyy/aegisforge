use crate::scanner::artifact::Artifact;
use crate::scanner::file_type::ArtifactType;

use super::evidence::{Evidence, EvidenceKind, Severity};

pub fn detect_file_type_mismatch(artifact: &Artifact) -> Vec<Evidence> {
    let mut evidence = Vec::new();

    let extension = match artifact.extension.as_deref() {
        Some(extension) => extension,
        None => return evidence,
    };

    let expected_type = match extension {
        "pdf" => Some(ArtifactType::Pdf),
        "zip" => Some(ArtifactType::Zip),
        "png" => Some(ArtifactType::Png),
        "jpg" | "jpeg" => Some(ArtifactType::Jpeg),
        _ => None,
    };

    let expected_type = match expected_type {
        Some(file_type) => file_type,
        None => return evidence,
    };

    if !same_type(&artifact.file_type, &expected_type) {
        evidence.push(Evidence::new(
            EvidenceKind::FileTypeMismatch,
            Severity::Medium,
            format!(
                "File extension '{}' does not match detected content type '{}'",
                extension,
                artifact.file_type.as_str()
            ),
        ));
    }

    evidence
}

fn same_type(left: &ArtifactType, right: &ArtifactType) -> bool {
    std::mem::discriminant(left) == std::mem::discriminant(right)
}
