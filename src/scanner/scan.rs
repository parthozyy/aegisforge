use std::path::Path;

use crate::detection::analyzer::analyze_artifact;
use crate::detection::verdict::determine_verdict;
use crate::detection::yara::YaraEngine;

use super::discovery::discover_files;
use super::file_type::ArtifactType;
use super::macho::inspect_macho;
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

    let yara_engine = YaraEngine::from_directory(Path::new("rules/yara"))?;

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

                if matches!(&artifact.file_type, ArtifactType::MachO) {
                    match inspect_macho(&artifact.path) {
                        Ok(info) => {
                            let architecture = info.architecture.as_deref().unwrap_or("multiple");

                            println!(
                                "Mach-O: {} | architecture: {} | endianness: {}",
                                info.format, architecture, info.endianness
                            );
                        }

                        Err(error) => {
                            eprintln!("Warning: {error}");
                        }
                    }
                }

                match analyze_artifact(&artifact, &yara_engine) {
                    Ok(evidence) => {
                        let verdict = determine_verdict(&evidence);

                        for finding in &evidence {
                            println!(
                                "Evidence [{}]: {}",
                                finding.severity.as_str(),
                                finding.message
                            );
                        }

                        println!("Verdict: {}", verdict.as_str());
                    }

                    Err(error) => {
                        eprintln!("Warning: {error}");
                    }
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
