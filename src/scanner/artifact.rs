use std::path::PathBuf;

#[derive(Debug)]
pub struct Artifact {
    pub path: PathBuf,
    pub size: u64,
    pub extension: Option<String>,
}

impl Artifact {
    pub fn new(path: PathBuf, size: u64, extension: Option<String>) -> Self {
        Self {
            path,
            size,
            extension,
        }
    }
}
