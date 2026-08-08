use crate::scanner::artifact::Artifact;
use crate::scanner::file_type::ArtifactType;

use super::evidence::{Evidence, EvidenceKind, Severity};

pub fn detect_file_type_mismatch(artifact: &Artifact) -> Option<Evidence> {
    let extension = artifact.extension.as_deref()?;

    let expected_type = match extension {
        "pdf" => Some(ArtifactType::Pdf),
        "zip" => Some(ArtifactType::Zip),
        "png" => Some(ArtifactType::Png),
        "jpg" | "jpeg" => Some(ArtifactType::Jpeg),
        _ => None,
    };

    let expected_type = expected_type?;

    if same_type(&artifact.file_type, &expected_type) {
        return None;
    }

    Some(Evidence::new(
        EvidenceKind::FileTypeMismatch,
        Severity::Medium,
        format!(
            "File extension '{}' does not match detected content type '{}'",
            extension,
            artifact.file_type.as_str()
        ),
    ))
}

fn same_type(left: &ArtifactType, right: &ArtifactType) -> bool {
    std::mem::discriminant(left) == std::mem::discriminant(right)
}
