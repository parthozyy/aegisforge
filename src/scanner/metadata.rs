use std::fs;
use std::path::Path;

use super::artifact::Artifact;

pub fn collect_metadata(path: &Path) -> Result<Artifact, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("Failed to read metadata for {}: {}", path.display(), error))?;

    let size = metadata.len();

    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_lowercase());

    Ok(Artifact::new(path.to_path_buf(), size, extension))
}
