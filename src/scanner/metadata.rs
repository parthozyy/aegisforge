use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use super::artifact::Artifact;
use super::file_type::detect_file_type;
use super::hashing::calculate_sha256_and_snapshot;

pub struct CollectedArtifact {
    pub artifact: Artifact,
    pub contents: Vec<u8>,
}

pub fn collect_artifact(path: &Path) -> Result<CollectedArtifact, String> {
    let mut file = open_artifact(path)
        .map_err(|error| format!("Failed to read metadata for {}: {}", path.display(), error))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("Failed to read metadata for {}: {}", path.display(), error))?;

    if !metadata.is_file() {
        return Err(format!("Path is not a regular file: {}", path.display()));
    }

    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_lowercase());

    let (sha256, contents) = calculate_sha256_and_snapshot(&mut file, path)?;
    let size = u64::try_from(contents.len()).map_err(|_| {
        format!(
            "Artifact is too large to report its size: {}",
            path.display()
        )
    })?;
    let file_type = detect_file_type(&contents);

    Ok(CollectedArtifact {
        artifact: Artifact::new(path.to_path_buf(), size, extension, sha256, file_type),
        contents,
    })
}

fn open_artifact(path: &Path) -> io::Result<File> {
    #[cfg(not(unix))]
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "symbolic-link artifacts are not allowed",
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);

    options.open(path)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::ErrorKind;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new() -> Self {
            loop {
                let id = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "aegisforge-metadata-tests-{}-{id}",
                    std::process::id()
                ));

                match OpenOptions::new().write(true).create_new(true).open(&path) {
                    Ok(_) => return Self { path },
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("temporary test file should be creatable: {error}"),
                }
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    #[test]
    fn collected_snapshot_and_hash_do_not_follow_later_path_replacement() {
        let fixture = TempFile::new();
        fs::write(fixture.path(), b"original bytes").expect("test fixture should be writable");

        let collected = collect_artifact(fixture.path()).expect("fixture should be collectable");
        fs::remove_file(fixture.path()).expect("fixture path should be replaceable");
        fs::write(fixture.path(), b"replacement bytes").expect("replacement should be writable");

        assert_eq!(collected.contents, b"original bytes");
        assert_eq!(collected.artifact.size, 14);
        assert_eq!(
            collected.artifact.sha256,
            "52c3935626c104b2cbc9031291a1c4d56614c38f52072a361d658a58a9c48698"
        );
    }
}
