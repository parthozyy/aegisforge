use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use super::result::{DiagnosticKind, ScanDiagnostic};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryResult {
    pub files: Vec<PathBuf>,
    pub app_bundles: Vec<PathBuf>,
    pub diagnostics: Vec<ScanDiagnostic>,
}

pub fn discover_files_with_diagnostics(path: &Path) -> Result<DiscoveryResult, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Cannot inspect {}: {}", path.display(), error))?;

    if metadata.file_type().is_symlink() {
        return Err(format!(
            "Symbolic links are not followed: {}",
            path.display()
        ));
    }

    if metadata.is_file() {
        return Ok(DiscoveryResult {
            files: vec![path.to_path_buf()],
            app_bundles: Vec::new(),
            diagnostics: Vec::new(),
        });
    }

    if !metadata.is_dir() {
        return Err(format!("Not a valid file or directory: {}", path.display()));
    }

    let mut files = Vec::new();
    let mut app_bundles = Vec::new();
    let mut diagnostics = Vec::new();

    if is_application_bundle(path) {
        app_bundles.push(path.to_path_buf());
    }

    discover_directory(path, &mut files, &mut app_bundles, &mut diagnostics);
    files.sort();
    files.dedup();
    app_bundles.sort();
    app_bundles.dedup();

    Ok(DiscoveryResult {
        files,
        app_bundles,
        diagnostics,
    })
}

fn is_application_bundle(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("app"))
}

fn discover_directory(
    directory: &Path,
    files: &mut Vec<PathBuf>,
    app_bundles: &mut Vec<PathBuf>,
    diagnostics: &mut Vec<ScanDiagnostic>,
) {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,

        Err(error) => {
            diagnostics.push(ScanDiagnostic::new(
                DiagnosticKind::Discovery,
                Some(directory.to_path_buf()),
                format!("cannot read directory {}: {}", directory.display(), error),
            ));

            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,

            Err(error) => {
                diagnostics.push(directory_entry_error_diagnostic(directory, error));
                continue;
            }
        };

        let path = entry.path();

        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,

            Err(error) => {
                diagnostics.push(ScanDiagnostic::new(
                    DiagnosticKind::Discovery,
                    Some(path.clone()),
                    format!(
                        "cannot determine file type for {}: {}",
                        path.display(),
                        error
                    ),
                ));

                continue;
            }
        };

        if file_type.is_symlink() {
            diagnostics.push(ScanDiagnostic::new(
                DiagnosticKind::Discovery,
                Some(path.clone()),
                format!("Skipping symbolic link: {}", path.display()),
            ));

            continue;
        }

        if file_type.is_file() {
            files.push(path);
        } else if file_type.is_dir() {
            if is_application_bundle(&path) {
                app_bundles.push(path.clone());
            }

            discover_directory(&path, files, app_bundles, diagnostics);
        }
    }
}

fn directory_entry_error_diagnostic(directory: &Path, error: std::io::Error) -> ScanDiagnostic {
    ScanDiagnostic::new(
        DiagnosticKind::Discovery,
        Some(directory.to_path_buf()),
        format!("failed to read directory entry: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static NEXT_TEST_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aegisforge-discovery-test-{}-{sequence}",
                std::process::id()
            ));

            fs::create_dir(&path).expect("test directory should be uniquely owned");

            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn create_dir(&self, relative_path: impl AsRef<Path>) -> PathBuf {
            let path = self.path.join(relative_path);
            fs::create_dir_all(&path).expect("test directory hierarchy should be created");
            path
        }

        fn create_file(&self, relative_path: impl AsRef<Path>) -> PathBuf {
            let path = self.path.join(relative_path);

            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("test file parent directories should be created");
            }

            fs::write(&path, b"fixture").expect("test file should be created");
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn directory_results_are_sorted() {
        let fixture = TestDirectory::new();
        fixture.create_file("z.txt");
        fixture.create_file("nested/b.txt");
        fixture.create_file("a.txt");

        let result =
            discover_files_with_diagnostics(fixture.path()).expect("discovery should work");
        let relative_paths: Vec<_> = result
            .files
            .iter()
            .map(|path| {
                path.strip_prefix(fixture.path())
                    .expect("discovered path should belong to fixture")
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();

        assert_eq!(relative_paths, ["a.txt", "nested/b.txt", "z.txt"]);
    }

    #[test]
    fn direct_top_level_application_bundle_is_discovered_once_with_its_contents() {
        let fixture = TestDirectory::new();
        let bundle = fixture.create_dir("Root.app");
        let executable = fixture.create_file("Root.app/Contents/MacOS/main");
        let resource = fixture.create_file("Root.app/Contents/Resources/data");

        let result = discover_files_with_diagnostics(&bundle).expect("discovery should work");

        assert_eq!(result.app_bundles, [bundle]);
        assert_eq!(result.files, [executable, resource]);
    }

    #[test]
    fn nested_application_bundles_are_case_insensitive_sorted_and_unique() {
        let fixture = TestDirectory::new();
        let root_bundle = fixture.create_dir("Root.app");
        let root_executable = fixture.create_file("Root.app/Contents/MacOS/main");
        let root_resource = fixture.create_file("Root.app/Contents/Resources/data");
        let helper_bundle = fixture.create_dir("nested/Helper.APP");
        let helper_executable = fixture.create_file("nested/Helper.APP/Contents/MacOS/helper");
        fixture.create_dir("ordinary");
        let ordinary_file = fixture.create_file("ordinary/file.txt");

        let result =
            discover_files_with_diagnostics(fixture.path()).expect("discovery should work");

        assert_eq!(result.app_bundles, [root_bundle, helper_bundle]);
        assert_eq!(
            result.files,
            [
                root_executable,
                root_resource,
                helper_executable,
                ordinary_file,
            ]
        );
    }

    #[test]
    fn directory_entry_error_diagnostic_names_containing_directory() {
        let directory = Path::new("nested");
        let error = std::io::Error::other("synthetic entry error");

        let diagnostic = directory_entry_error_diagnostic(directory, error);

        assert_eq!(diagnostic.kind, DiagnosticKind::Discovery);
        assert_eq!(diagnostic.path.as_deref(), Some(directory));
        assert_eq!(
            diagnostic.message,
            "failed to read directory entry: synthetic entry error"
        );
    }

    #[cfg(unix)]
    #[test]
    fn nested_symlink_is_skipped_and_diagnosed() {
        use std::os::unix::fs::symlink;

        let fixture = TestDirectory::new();
        let real_file = fixture.create_file("real.txt");
        let symlink_path = fixture.path().join("link.txt");
        symlink(&real_file, &symlink_path).expect("test symlink should be created");

        let result =
            discover_files_with_diagnostics(fixture.path()).expect("discovery should work");

        assert_eq!(result.files, [real_file]);
        assert!(result.diagnostics.iter().any(|diagnostic| {
            diagnostic.kind == crate::scanner::result::DiagnosticKind::Discovery
                && diagnostic.path.as_deref() == Some(symlink_path.as_path())
        }));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_with_application_bundle_suffix_is_not_discovered() {
        use std::os::unix::fs::symlink;

        let fixture = TestDirectory::new();
        let real_bundle = fixture.create_dir("RealBundle");
        fixture.create_file("RealBundle/Contents/MacOS/main");
        let symlink_path = fixture.path().join("Linked.app");
        symlink(&real_bundle, &symlink_path).expect("test symlink should be created");

        let result =
            discover_files_with_diagnostics(fixture.path()).expect("discovery should work");

        assert!(result.app_bundles.is_empty());
        assert!(result.diagnostics.iter().any(|diagnostic| {
            diagnostic.kind == crate::scanner::result::DiagnosticKind::Discovery
                && diagnostic.path.as_deref() == Some(symlink_path.as_path())
        }));
    }

    #[cfg(unix)]
    #[test]
    fn direct_top_level_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let fixture = TestDirectory::new();
        let real_file = fixture.create_file("real.txt");
        let symlink_path = fixture.path().join("link.txt");
        symlink(&real_file, &symlink_path).expect("test symlink should be created");

        let error = discover_files_with_diagnostics(&symlink_path)
            .expect_err("top-level symlinks should be rejected");

        assert!(error.contains("Symbolic links are not followed"));
        assert!(error.contains("link.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_nested_directory_is_diagnosed() {
        use std::io::ErrorKind;
        use std::os::unix::fs::PermissionsExt;

        struct PermissionsGuard {
            path: PathBuf,
            original: fs::Permissions,
        }

        impl PermissionsGuard {
            fn deny_all(path: &Path) -> Self {
                let original = fs::metadata(path)
                    .expect("test directory metadata should be readable")
                    .permissions();
                fs::set_permissions(path, fs::Permissions::from_mode(0o000))
                    .expect("test directory permissions should be changed");

                Self {
                    path: path.to_path_buf(),
                    original,
                }
            }
        }

        impl Drop for PermissionsGuard {
            fn drop(&mut self) {
                let _ = fs::set_permissions(&self.path, self.original.clone());
            }
        }

        let fixture = TestDirectory::new();
        let nested = fixture.create_dir("nested");
        fixture.create_file("nested/hidden.txt");
        let _permissions_guard = PermissionsGuard::deny_all(&nested);

        match fs::read_dir(&nested) {
            Err(error) if error.kind() == ErrorKind::PermissionDenied => {}
            // Privileged test hosts can bypass mode bits, so this scenario cannot
            // exercise the intended error branch there.
            Ok(_) => return,
            Err(error) => panic!("expected PermissionDenied, got {error}"),
        }

        let result =
            discover_files_with_diagnostics(fixture.path()).expect("discovery should work");

        assert!(result.diagnostics.iter().any(|diagnostic| {
            diagnostic.kind == crate::scanner::result::DiagnosticKind::Discovery
                && diagnostic.path.as_deref() == Some(nested.as_path())
        }));
    }
}
