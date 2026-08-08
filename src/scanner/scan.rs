use std::path::Path;

use crate::detection::file_mismatch::detect_file_type_mismatch;

use super::discovery::discover_files;
use super::metadata::collect_metadata;
use super::path::{PathType, inspect_path};

pub fn scan_path(path: &Path) -> Result<(), String> {
    println!("AegisForge");

    let path_type = inspect_path(path)?;

    match path_type {
        PathType::File => {
            println!("Target: {}", path.display());
            println!("Type: File");
        }

        PathType::Directory => {
            println!("Target: {}", path.display());
            println!("Type: Directory");
        }
    }

    let files = discover_files(path)?;

    for file in &files {
        match collect_metadata(file) {
            Ok(artifact) => {
                let extension = artifact.extension.as_deref().unwrap_or("none");

                println!(
                    "{} | {} bytes | extension: {} | type: {}",
                    artifact.path.display(),
                    artifact.size,
                    extension,
                    artifact.file_type.as_str()
                );

                println!("SHA-256: {}", artifact.sha256);

                if let Some(evidence) = detect_file_type_mismatch(&artifact) {
                    println!(
                        "Evidence [{}]: {}",
                        evidence.severity.as_str(),
                        evidence.message
                    );
                }
            }

            Err(error) => {
                eprintln!("Warning: {error}");
            }
        }
    }

    println!("\n{} file(s) discovered", files.len());

    Ok(())
}
