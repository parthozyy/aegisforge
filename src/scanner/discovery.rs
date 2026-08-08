use std::fs;
use std::path::{Path, PathBuf};

pub fn discover_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Cannot inspect {}: {}", path.display(), error))?;

    if metadata.file_type().is_symlink() {
        return Err(format!(
            "Symbolic links are not followed: {}",
            path.display()
        ));
    }

    if metadata.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    if !metadata.is_dir() {
        return Err(format!("Not a valid file or directory: {}", path.display()));
    }

    let mut files = Vec::new();

    discover_directory(path, &mut files);

    Ok(files)
}

fn discover_directory(directory: &Path, files: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,

        Err(error) => {
            eprintln!(
                "Warning: cannot read directory {}: {}",
                directory.display(),
                error
            );

            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,

            Err(error) => {
                eprintln!("Warning: failed to read directory entry: {error}");
                continue;
            }
        };

        let path = entry.path();

        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,

            Err(error) => {
                eprintln!(
                    "Warning: cannot determine file type for {}: {}",
                    path.display(),
                    error
                );

                continue;
            }
        };

        if file_type.is_symlink() {
            eprintln!("Skipping symbolic link: {}", path.display());

            continue;
        }

        if file_type.is_file() {
            files.push(path);
        } else if file_type.is_dir() {
            discover_directory(&path, files);
        }
    }
}
