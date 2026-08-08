use std::fs;
use std::path::Path;

use goblin::mach::{Mach, MachO, SingleArch};

#[derive(Debug)]
pub struct MachODependencies {
    pub libraries: Vec<String>,
    pub rpaths: Vec<String>,
}

pub fn inspect_macho_dependencies(path: &Path) -> Result<MachODependencies, String> {
    let data = fs::read(path)
        .map_err(|error| format!("Failed to read Mach-O file {}: {}", path.display(), error))?;

    let mach = Mach::parse(&data)
        .map_err(|error| format!("Failed to parse Mach-O file {}: {}", path.display(), error))?;

    let mut libraries = Vec::new();
    let mut rpaths = Vec::new();

    match mach {
        Mach::Binary(binary) => {
            collect_dependencies(&binary, &mut libraries, &mut rpaths);
        }

        Mach::Fat(fat) => {
            for entry in &fat {
                let entry = entry.map_err(|error| {
                    format!(
                        "Failed to parse architecture in {}: {}",
                        path.display(),
                        error
                    )
                })?;

                match entry {
                    SingleArch::MachO(binary) => {
                        collect_dependencies(&binary, &mut libraries, &mut rpaths);
                    }

                    SingleArch::Archive(_) => {}
                }
            }
        }
    }

    libraries.sort();
    libraries.dedup();

    rpaths.sort();
    rpaths.dedup();

    Ok(MachODependencies { libraries, rpaths })
}

fn collect_dependencies(macho: &MachO<'_>, libraries: &mut Vec<String>, rpaths: &mut Vec<String>) {
    libraries.extend(
        macho
            .libs
            .iter()
            .filter(|library| **library != "self")
            .map(|library| library.to_string()),
    );

    rpaths.extend(macho.rpaths.iter().map(|rpath| rpath.to_string()));
}
