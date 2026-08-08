use std::path::Path;

pub enum PathType {
    File,
    Directory,
}

pub fn inspect_path(path: &Path) -> Result<PathType, String> {
    if !path.exists() {
        return Err(format!("Path does not exist: {}", path.display()));
    }

    if path.is_file() {
        return Ok(PathType::File);
    }

    if path.is_dir() {
        return Ok(PathType::Directory);
    }

    Err(format!("Unsupported filesystem object: {}", path.display()))
}
