use crate::scanner::macho_dependencies::MachODependencies;

use super::evidence::{Evidence, EvidenceKind, Severity};
use super::rpath::{RpathLocation, classify_rpath};

pub fn detect_rpath_risk(dependencies: &MachODependencies) -> Vec<Evidence> {
    let mut evidence = Vec::new();

    let uses_rpath_dependency = dependencies
        .libraries
        .iter()
        .any(|library| library == "@rpath" || library.starts_with("@rpath/"));

    if !uses_rpath_dependency {
        return evidence;
    }

    for rpath in &dependencies.rpaths {
        match classify_rpath(rpath) {
            RpathLocation::Temporary => {
                evidence.push(Evidence::new(
                    EvidenceKind::RiskyRpath,
                    Severity::Medium,
                    format!(
                        "Potential dylib hijacking exposure: @rpath dependency uses temporary runtime search path '{}'",
                        rpath
                    ),
                ));
            }

            RpathLocation::UserControlled => {
                evidence.push(Evidence::new(
                    EvidenceKind::RiskyRpath,
                    Severity::Low,
                    format!(
                        "Potential dylib loading exposure: @rpath dependency uses user-controlled runtime search path '{}'",
                        rpath
                    ),
                ));
            }

            RpathLocation::Relative => {
                evidence.push(Evidence::new(
                    EvidenceKind::RiskyRpath,
                    Severity::Low,
                    format!(
                        "Relative runtime search path '{}' is used with an @rpath dependency",
                        rpath
                    ),
                ));
            }

            _ => {}
        }
    }

    evidence
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dependencies(libraries: Vec<&str>, rpaths: Vec<&str>) -> MachODependencies {
        MachODependencies {
            libraries: libraries.into_iter().map(String::from).collect(),

            rpaths: rpaths.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn system_rpath_does_not_create_evidence() {
        let deps = dependencies(
            vec!["@rpath/libExample.dylib"],
            vec!["/System/Library/Frameworks"],
        );

        let evidence = detect_rpath_risk(&deps);

        assert!(evidence.is_empty());
    }

    #[test]
    fn temporary_rpath_is_medium_evidence() {
        let deps = dependencies(vec!["@rpath/libExample.dylib"], vec!["/tmp/plugins"]);

        let evidence = detect_rpath_risk(&deps);

        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].kind, EvidenceKind::RiskyRpath);
        assert_eq!(evidence[0].severity, Severity::Medium);
    }

    #[test]
    fn user_rpath_is_low_evidence() {
        let deps = dependencies(
            vec!["@rpath/libExample.dylib"],
            vec!["/Users/example/plugins"],
        );

        let evidence = detect_rpath_risk(&deps);

        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].severity, Severity::Low);
    }

    #[test]
    fn risky_rpath_without_rpath_dependency_is_ignored() {
        let deps = dependencies(vec!["/usr/lib/libSystem.B.dylib"], vec!["/tmp/plugins"]);

        let evidence = detect_rpath_risk(&deps);

        assert!(evidence.is_empty());
    }

    #[test]
    fn loader_path_is_not_automatically_suspicious() {
        let deps = dependencies(
            vec!["@rpath/libExample.dylib"],
            vec!["@loader_path/../Frameworks"],
        );

        let evidence = detect_rpath_risk(&deps);

        assert!(evidence.is_empty());
    }
}
