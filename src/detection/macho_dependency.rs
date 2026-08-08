#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyLocation {
    System,
    Rpath,
    LoaderPath,
    ExecutablePath,
    AbsoluteNonSystem,
    Relative,
}

impl DependencyLocation {
    pub fn as_str(&self) -> &'static str {
        match self {
            DependencyLocation::System => "SYSTEM",
            DependencyLocation::Rpath => "RPATH",
            DependencyLocation::LoaderPath => "LOADER_PATH",
            DependencyLocation::ExecutablePath => "EXECUTABLE_PATH",
            DependencyLocation::AbsoluteNonSystem => "ABSOLUTE_NON_SYSTEM",
            DependencyLocation::Relative => "RELATIVE",
        }
    }
}

pub fn classify_dependency(path: &str) -> DependencyLocation {
    if path.starts_with("/System/Library/") || path.starts_with("/usr/lib/") {
        return DependencyLocation::System;
    }

    if path == "@rpath" || path.starts_with("@rpath/") {
        return DependencyLocation::Rpath;
    }

    if path == "@loader_path" || path.starts_with("@loader_path/") {
        return DependencyLocation::LoaderPath;
    }

    if path == "@executable_path" || path.starts_with("@executable_path/") {
        return DependencyLocation::ExecutablePath;
    }

    if path.starts_with('/') {
        return DependencyLocation::AbsoluteNonSystem;
    }

    DependencyLocation::Relative
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_usr_lib_as_system() {
        let result = classify_dependency("/usr/lib/libSystem.B.dylib");

        assert_eq!(result, DependencyLocation::System);
    }

    #[test]
    fn classifies_system_library_as_system() {
        let result = classify_dependency("/System/Library/Frameworks/Security.framework/Security");

        assert_eq!(result, DependencyLocation::System);
    }

    #[test]
    fn classifies_rpath_dependency() {
        let result = classify_dependency("@rpath/libExample.dylib");

        assert_eq!(result, DependencyLocation::Rpath);
    }

    #[test]
    fn classifies_loader_path_dependency() {
        let result = classify_dependency("@loader_path/libExample.dylib");

        assert_eq!(result, DependencyLocation::LoaderPath);
    }

    #[test]
    fn classifies_executable_path_dependency() {
        let result = classify_dependency("@executable_path/libExample.dylib");

        assert_eq!(result, DependencyLocation::ExecutablePath);
    }

    #[test]
    fn classifies_non_system_absolute_path() {
        let result = classify_dependency("/Users/example/tmp/libExample.dylib");

        assert_eq!(result, DependencyLocation::AbsoluteNonSystem);
    }

    #[test]
    fn classifies_relative_dependency() {
        let result = classify_dependency("libExample.dylib");

        assert_eq!(result, DependencyLocation::Relative);
    }
}
