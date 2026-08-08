#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpathLocation {
    System,
    LoaderPath,
    ExecutablePath,
    Temporary,
    UserControlled,
    AbsoluteOther,
    Relative,
}

impl RpathLocation {
    pub fn as_str(&self) -> &'static str {
        match self {
            RpathLocation::System => "SYSTEM",
            RpathLocation::LoaderPath => "LOADER_PATH",
            RpathLocation::ExecutablePath => "EXECUTABLE_PATH",
            RpathLocation::Temporary => "TEMPORARY",
            RpathLocation::UserControlled => "USER_CONTROLLED",
            RpathLocation::AbsoluteOther => "ABSOLUTE_OTHER",
            RpathLocation::Relative => "RELATIVE",
        }
    }
}

pub fn classify_rpath(path: &str) -> RpathLocation {
    if path.starts_with("/System/Library/") || path.starts_with("/usr/lib/") {
        return RpathLocation::System;
    }

    if path == "@loader_path" || path.starts_with("@loader_path/") {
        return RpathLocation::LoaderPath;
    }

    if path == "@executable_path" || path.starts_with("@executable_path/") {
        return RpathLocation::ExecutablePath;
    }

    if path == "/tmp"
        || path.starts_with("/tmp/")
        || path == "/private/tmp"
        || path.starts_with("/private/tmp/")
        || path == "/var/tmp"
        || path.starts_with("/var/tmp/")
    {
        return RpathLocation::Temporary;
    }

    if path.starts_with("/Users/") {
        return RpathLocation::UserControlled;
    }

    if path.starts_with('/') {
        return RpathLocation::AbsoluteOther;
    }

    RpathLocation::Relative
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_system_rpath() {
        assert_eq!(
            classify_rpath("/System/Library/Frameworks"),
            RpathLocation::System
        );
    }

    #[test]
    fn classifies_loader_path() {
        assert_eq!(
            classify_rpath("@loader_path/../Frameworks"),
            RpathLocation::LoaderPath
        );
    }

    #[test]
    fn classifies_executable_path() {
        assert_eq!(
            classify_rpath("@executable_path/../Frameworks"),
            RpathLocation::ExecutablePath
        );
    }

    #[test]
    fn classifies_tmp_path() {
        assert_eq!(classify_rpath("/tmp/aegis-libs"), RpathLocation::Temporary);
    }

    #[test]
    fn classifies_private_tmp_path() {
        assert_eq!(
            classify_rpath("/private/tmp/libs"),
            RpathLocation::Temporary
        );
    }

    #[test]
    fn classifies_user_path() {
        assert_eq!(
            classify_rpath("/Users/example/libs"),
            RpathLocation::UserControlled
        );
    }

    #[test]
    fn classifies_other_absolute_path() {
        assert_eq!(
            classify_rpath("/Library/Frameworks"),
            RpathLocation::AbsoluteOther
        );
    }

    #[test]
    fn classifies_relative_path() {
        assert_eq!(classify_rpath("../Frameworks"), RpathLocation::Relative);
    }
}
