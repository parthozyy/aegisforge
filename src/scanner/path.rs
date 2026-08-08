use std::fs;
use std::path::Path;

pub enum PathType {
    File,
    Directory,
}

pub fn inspect_path(path: &Path) -> Result<PathType, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Cannot inspect {}: {}", path.display(), error))?;

    if metadata.file_type().is_symlink() {
        return Err(format!(
            "Symbolic links are not supported: {}",
            path.display()
        ));
    }

    if metadata.is_file() {
        return Ok(PathType::File);
    }

    if metadata.is_dir() {
        return Ok(PathType::Directory);
    }

    Err(format!("Unsupported filesystem object: {}", path.display()))
}
