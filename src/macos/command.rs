use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCommandOutput {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeCommandError {
    Unavailable(String),
    Io(String),
}

pub trait NativeCommandRunner {
    fn run(
        &self,
        program: &Path,
        arguments: &[OsString],
    ) -> Result<NativeCommandOutput, NativeCommandError>;
}

pub struct SystemCommandRunner;

impl NativeCommandRunner for SystemCommandRunner {
    fn run(
        &self,
        program: &Path,
        arguments: &[OsString],
    ) -> Result<NativeCommandOutput, NativeCommandError> {
        let output = Command::new(program)
            .args(arguments)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| classify_spawn_error(program, error))?;

        Ok(NativeCommandOutput {
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

fn classify_spawn_error(program: &Path, error: io::Error) -> NativeCommandError {
    let message = format!(
        "failed to execute native command '{}': {error}",
        program.display()
    );

    if error.kind() == io::ErrorKind::NotFound {
        NativeCommandError::Unavailable(message)
    } else {
        NativeCommandError::Io(message)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io;
    use std::path::Path;

    use super::*;

    #[test]
    fn not_found_spawn_errors_are_unavailable() {
        let error = io::Error::from(io::ErrorKind::NotFound);

        let classified = classify_spawn_error(Path::new("/missing/tool"), error);

        assert!(matches!(classified, NativeCommandError::Unavailable(_)));
    }

    #[test]
    fn permission_denied_spawn_errors_are_io_errors() {
        let error = io::Error::from(io::ErrorKind::PermissionDenied);

        let classified = classify_spawn_error(Path::new("/restricted/tool"), error);

        assert!(matches!(classified, NativeCommandError::Io(_)));
    }

    #[test]
    fn other_spawn_errors_are_io_errors() {
        let error = io::Error::from(io::ErrorKind::InvalidInput);

        let classified = classify_spawn_error(Path::new("/invalid/tool"), error);

        assert!(matches!(classified, NativeCommandError::Io(_)));
    }

    #[test]
    fn command_output_preserves_raw_streams_and_exit_status() {
        let output = NativeCommandOutput {
            success: false,
            exit_code: Some(7),
            stdout: vec![0, 1, 2],
            stderr: vec![3, 4, 5],
        };

        assert_eq!(
            output,
            NativeCommandOutput {
                success: false,
                exit_code: Some(7),
                stdout: vec![0, 1, 2],
                stderr: vec![3, 4, 5],
            }
        );
    }

    #[test]
    fn native_command_runner_is_object_safe() {
        fn accepts_runner(_runner: &dyn NativeCommandRunner) {}

        accepts_runner(&SystemCommandRunner);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn system_runner_reports_codesign_nonzero_exit_and_captures_stderr_without_shell() {
        let unique_suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be after the Unix epoch")
            .as_nanos();
        let missing_target = std::env::temp_dir().join(format!(
            "aegisforge-codesign-definitely-missing-{}-{unique_suffix}",
            std::process::id()
        ));
        assert!(missing_target.is_absolute());
        assert!(!missing_target.exists());

        let arguments = [OsString::from("--verify"), missing_target.into_os_string()];

        let output = SystemCommandRunner
            .run(Path::new("/usr/bin/codesign"), &arguments)
            .expect("the macOS codesign executable should be available");

        assert!(!output.success);
        assert!(output.exit_code.is_some());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}
