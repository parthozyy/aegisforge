use std::fs;
use std::path::Path;

use super::artifact::Artifact;
use super::file_type::detect_file_type;
use super::hashing::calculate_sha256;

pub fn collect_metadata(path: &Path) -> Result<Artifact, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("Failed to read metadata for {}: {}", path.display(), error))?;

    let size = metadata.len();

    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_lowercase());

    let sha256 = calculate_sha256(path)?;

    let file_type = detect_file_type(path)?;

    Ok(Artifact::new(
        path.to_path_buf(),
        size,
        extension,
        sha256,
        file_type,
    ))
}
