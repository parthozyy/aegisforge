use std::path::Path;

use super::discovery::discover_files;
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
        println!("{}", file.display());
    }

    println!("\n{} file(s) discovered", files.len());

    Ok(())
}
