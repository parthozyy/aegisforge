use std::path::PathBuf;

use super::file_type::ArtifactType;

#[derive(Debug)]
pub struct Artifact {
    pub path: PathBuf,
    pub size: u64,
    pub extension: Option<String>,
    pub sha256: String,
    pub file_type: ArtifactType,
}

impl Artifact {
    pub fn new(
        path: PathBuf,
        size: u64,
        extension: Option<String>,
        sha256: String,
        file_type: ArtifactType,
    ) -> Self {
        Self {
            path,
            size,
            extension,
            sha256,
            file_type,
        }
    }
}
