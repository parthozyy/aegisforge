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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn create_artifact(
        filename: &str,
        extension: Option<&str>,
        file_type: ArtifactType,
    ) -> Artifact {
        Artifact::new(
            PathBuf::from(filename),
            100,
            extension.map(String::from),
            "test-sha256".to_string(),
            file_type,
        )
    }

    #[test]
    fn matching_jpeg_has_no_evidence() {
        let artifact = create_artifact("photo.jpg", Some("jpg"), ArtifactType::Jpeg);

        let evidence = detect_file_type_mismatch(&artifact);

        assert!(evidence.is_empty());
    }

    #[test]
    fn matching_pdf_has_no_evidence() {
        let artifact = create_artifact("document.pdf", Some("pdf"), ArtifactType::Pdf);

        let evidence = detect_file_type_mismatch(&artifact);

        assert!(evidence.is_empty());
    }

    #[test]
    fn macho_disguised_as_jpeg_is_detected() {
        let artifact = create_artifact("evil.jpg", Some("jpg"), ArtifactType::MachO);

        let evidence = detect_file_type_mismatch(&artifact);

        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].kind, EvidenceKind::FileTypeMismatch);
        assert_eq!(evidence[0].severity, Severity::Medium);
    }

    #[test]
    fn unknown_extension_does_not_create_false_positive() {
        let artifact = create_artifact("Cargo.toml", Some("toml"), ArtifactType::Unknown);

        let evidence = detect_file_type_mismatch(&artifact);

        assert!(evidence.is_empty());
    }

    #[test]
    fn file_without_extension_does_not_create_false_positive() {
        let artifact = create_artifact("executable", None, ArtifactType::MachO);

        let evidence = detect_file_type_mismatch(&artifact);

        assert!(evidence.is_empty());
    }
}
