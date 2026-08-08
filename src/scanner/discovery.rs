use std::fs;
use std::path::{Path, PathBuf};

pub fn discover_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    if !path.is_dir() {
        return Err(format!("Not a valid file or directory: {}", path.display()));
    }

    let mut files = Vec::new();

    discover_directory(path, &mut files)?;

    Ok(files)
}

fn discover_directory(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("Cannot read {}: {}", directory.display(), error))?;

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                eprintln!("Warning: failed to read directory entry: {error}");
                continue;
            }
        };

        let path = entry.path();

        if path.is_file() {
            files.push(path);
        } else if path.is_dir() {
            discover_directory(&path, files)?;
        }
    }

    Ok(())
}
