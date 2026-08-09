use std::ffi::OsString;
use std::io;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

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

const BOUNDED_READER_BUFFER_BYTES: usize = 8 * 1024;
const MAX_NATIVE_OUTPUT_BYTES: usize = 1024 * 1024;
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(10);
const DEFAULT_TERMINATION_GRACE: Duration = Duration::from_millis(100);
const DEFAULT_READER_CLOSE_GRACE: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy)]
struct CommandLimits {
    timeout: Duration,
    output_limit: usize,
    poll_interval: Duration,
    termination_grace: Duration,
    reader_close_grace: Duration,
}

impl Default for CommandLimits {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_COMMAND_TIMEOUT,
            output_limit: MAX_NATIVE_OUTPUT_BYTES,
            poll_interval: DEFAULT_COMMAND_POLL_INTERVAL,
            termination_grace: DEFAULT_TERMINATION_GRACE,
            reader_close_grace: DEFAULT_READER_CLOSE_GRACE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeStream {
    Stdout,
    Stderr,
}

#[derive(Debug, PartialEq, Eq)]
enum ReaderEvent {
    Complete {
        stream: NativeStream,
        bytes: Vec<u8>,
    },
    LimitExceeded {
        stream: NativeStream,
        limit: usize,
    },
    ReadFailed {
        stream: NativeStream,
        message: String,
    },
}

fn read_bounded_stream<R, F>(mut reader: R, stream: NativeStream, limit: usize, mut report: F)
where
    R: Read,
    F: FnMut(ReaderEvent),
{
    let mut retained = vec![0; limit];
    let mut retained_len = 0;
    let mut buffer = [0; BOUNDED_READER_BUFFER_BYTES];
    let mut limit_exceeded = false;

    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                retained.truncate(retained_len);
                if !limit_exceeded {
                    report(ReaderEvent::Complete {
                        stream,
                        bytes: retained,
                    });
                }
                return;
            }
            Ok(bytes_read) => {
                let remaining = limit.saturating_sub(retained_len);
                let bytes_to_retain = bytes_read.min(remaining);
                retained[retained_len..retained_len + bytes_to_retain]
                    .copy_from_slice(&buffer[..bytes_to_retain]);
                retained_len += bytes_to_retain;

                if bytes_to_retain < bytes_read && !limit_exceeded {
                    limit_exceeded = true;
                    report(ReaderEvent::LimitExceeded { stream, limit });
                }
            }
            Err(error) => {
                if !limit_exceeded {
                    report(ReaderEvent::ReadFailed {
                        stream,
                        message: error.to_string(),
                    });
                }
                return;
            }
        }
    }
}

fn spawn_bounded_reader<R>(
    name: &str,
    reader: R,
    stream: NativeStream,
    limit: usize,
    events: Sender<ReaderEvent>,
) -> io::Result<JoinHandle<()>>
where
    R: Read + Send + 'static,
{
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            read_bounded_stream(reader, stream, limit, |event| {
                let _ = events.send(event);
            })
        })
}

trait ReaderSpawner {
    fn spawn(
        &mut self,
        name: &str,
        reader: Box<dyn Read + Send>,
        stream: NativeStream,
        limit: usize,
        events: Sender<ReaderEvent>,
    ) -> io::Result<JoinHandle<()>>;
}

struct SystemReaderSpawner;

impl ReaderSpawner for SystemReaderSpawner {
    fn spawn(
        &mut self,
        name: &str,
        reader: Box<dyn Read + Send>,
        stream: NativeStream,
        limit: usize,
        events: Sender<ReaderEvent>,
    ) -> io::Result<JoinHandle<()>> {
        spawn_bounded_reader(name, reader, stream, limit, events)
    }
}

struct ReaderThread {
    stream: NativeStream,
    handle: JoinHandle<()>,
}

impl NativeCommandRunner for SystemCommandRunner {
    fn run(
        &self,
        program: &Path,
        arguments: &[OsString],
    ) -> Result<NativeCommandOutput, NativeCommandError> {
        run_with_limits(program, arguments, CommandLimits::default())
    }
}

fn run_with_limits(
    program: &Path,
    arguments: &[OsString],
    limits: CommandLimits,
) -> Result<NativeCommandOutput, NativeCommandError> {
    run_with_limits_and_spawner(program, arguments, limits, &mut SystemReaderSpawner)
}

fn run_with_limits_and_spawner<S: ReaderSpawner>(
    program: &Path,
    arguments: &[OsString],
    limits: CommandLimits,
    reader_spawner: &mut S,
) -> Result<NativeCommandOutput, NativeCommandError> {
    validate_limits(program, limits)?;

    let mut command = Command::new(program);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);

    let supervision_started = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| classify_spawn_error(program, error))?;
    #[cfg(unix)]
    let process_group = positive_process_id(child.id());
    #[cfg(not(unix))]
    let process_group = ();
    let (event_sender, event_receiver) = mpsc::channel();
    let mut reader_handles = Vec::with_capacity(2);

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            drop(event_sender);
            return cleanup_error(
                CleanupContext::new(program, &limits),
                &mut child,
                process_group,
                false,
                reader_handles,
                &event_receiver,
                "failed to acquire native command stdout pipe".to_owned(),
            );
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            drop(stdout);
            drop(event_sender);
            return cleanup_error(
                CleanupContext::new(program, &limits),
                &mut child,
                process_group,
                false,
                reader_handles,
                &event_receiver,
                "failed to acquire native command stderr pipe".to_owned(),
            );
        }
    };

    match reader_spawner.spawn(
        "native-command-stdout",
        Box::new(stdout),
        NativeStream::Stdout,
        limits.output_limit,
        event_sender.clone(),
    ) {
        Ok(handle) => reader_handles.push(ReaderThread {
            stream: NativeStream::Stdout,
            handle,
        }),
        Err(error) => {
            drop(stderr);
            drop(event_sender);
            return cleanup_error(
                CleanupContext::new(program, &limits),
                &mut child,
                process_group,
                false,
                reader_handles,
                &event_receiver,
                format!("failed to start native command stdout reader: {error}"),
            );
        }
    }

    match reader_spawner.spawn(
        "native-command-stderr",
        Box::new(stderr),
        NativeStream::Stderr,
        limits.output_limit,
        event_sender.clone(),
    ) {
        Ok(handle) => reader_handles.push(ReaderThread {
            stream: NativeStream::Stderr,
            handle,
        }),
        Err(error) => {
            drop(event_sender);
            return cleanup_error(
                CleanupContext::new(program, &limits),
                &mut child,
                process_group,
                false,
                reader_handles,
                &event_receiver,
                format!("failed to start native command stderr reader: {error}"),
            );
        }
    }
    drop(event_sender);

    supervise_child(
        program,
        &mut child,
        process_group,
        supervision_started,
        limits,
        event_receiver,
        reader_handles,
    )
}

fn validate_limits(program: &Path, limits: CommandLimits) -> Result<(), NativeCommandError> {
    if limits.output_limit > MAX_NATIVE_OUTPUT_BYTES {
        return Err(native_command_io_error(
            program,
            format!(
                "native command output limit {} exceeds the maximum of {MAX_NATIVE_OUTPUT_BYTES} bytes",
                limits.output_limit
            ),
        ));
    }

    let now = Instant::now();
    for (name, duration) in [
        ("timeout", limits.timeout),
        ("poll interval", limits.poll_interval),
        ("termination grace", limits.termination_grace),
        ("reader close grace", limits.reader_close_grace),
    ] {
        if now.checked_add(duration).is_none() {
            return Err(native_command_io_error(
                program,
                format!("native command {name} exceeds the platform duration range"),
            ));
        }
    }

    Ok(())
}

#[cfg(unix)]
fn positive_process_id(id: u32) -> Option<i32> {
    i32::try_from(id).ok().filter(|id| *id > 0)
}

fn supervise_child(
    program: &Path,
    child: &mut Child,
    process_group: NativeProcessGroup,
    supervision_started: Instant,
    limits: CommandLimits,
    event_receiver: Receiver<ReaderEvent>,
    mut reader_handles: Vec<ReaderThread>,
) -> Result<NativeCommandOutput, NativeCommandError> {
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;

    loop {
        if let Err(message) =
            observe_reader_state(&event_receiver, &reader_handles, &mut stdout, &mut stderr)
        {
            return cleanup_error(
                CleanupContext::new(program, &limits),
                child,
                process_group,
                status.is_some(),
                reader_handles,
                &event_receiver,
                message,
            );
        }

        if status.is_none() && stdout.is_some() && stderr.is_some() {
            match child.try_wait() {
                Ok(observed) => status = observed,
                Err(error) => {
                    return cleanup_error(
                        CleanupContext::new(program, &limits),
                        child,
                        process_group,
                        false,
                        reader_handles,
                        &event_receiver,
                        format!("failed to poll native command: {error}"),
                    );
                }
            }
        }

        if let Err(message) =
            observe_reader_state(&event_receiver, &reader_handles, &mut stdout, &mut stderr)
        {
            return cleanup_error(
                CleanupContext::new(program, &limits),
                child,
                process_group,
                status.is_some(),
                reader_handles,
                &event_receiver,
                message,
            );
        }

        let elapsed = supervision_started.elapsed();
        if elapsed < limits.timeout
            && status.is_some()
            && stdout.is_some()
            && stderr.is_some()
            && reader_handles
                .iter()
                .all(|reader| reader.handle.is_finished())
        {
            let mut join_failure = None;
            for reader in reader_handles.drain(..) {
                if reader.handle.join().is_err() {
                    join_failure = Some("native command reader thread panicked".to_owned());
                }
            }
            if let Some(message) = join_failure {
                return cleanup_error(
                    CleanupContext::new(program, &limits),
                    child,
                    process_group,
                    true,
                    reader_handles,
                    &event_receiver,
                    message,
                );
            }

            let completed_status = status.ok_or_else(|| {
                native_command_io_error(program, "native command status disappeared".to_owned())
            })?;
            let completed_stdout = stdout.take().ok_or_else(|| {
                native_command_io_error(program, "native command stdout disappeared".to_owned())
            })?;
            let completed_stderr = stderr.take().ok_or_else(|| {
                native_command_io_error(program, "native command stderr disappeared".to_owned())
            })?;
            return Ok(NativeCommandOutput {
                success: completed_status.success(),
                exit_code: completed_status.code(),
                stdout: completed_stdout,
                stderr: completed_stderr,
            });
        }

        if elapsed >= limits.timeout {
            return cleanup_error(
                CleanupContext::new(program, &limits),
                child,
                process_group,
                status.is_some(),
                reader_handles,
                &event_receiver,
                format!(
                    "native command timed out after {} ms",
                    limits.timeout.as_millis()
                ),
            );
        }

        thread::sleep(
            limits
                .poll_interval
                .min(limits.timeout.saturating_sub(elapsed)),
        );
    }
}

fn observe_reader_state(
    receiver: &Receiver<ReaderEvent>,
    reader_handles: &[ReaderThread],
    stdout: &mut Option<Vec<u8>>,
    stderr: &mut Option<Vec<u8>>,
) -> Result<(), String> {
    observe_reader_state_with(receiver, stdout, stderr, |stdout, stderr| {
        finished_reader_without_outcome(reader_handles, stdout, stderr)
    })
}

fn observe_reader_state_with<F>(
    receiver: &Receiver<ReaderEvent>,
    stdout: &mut Option<Vec<u8>>,
    stderr: &mut Option<Vec<u8>>,
    mut observe_finished: F,
) -> Result<(), String>
where
    F: FnMut(&Option<Vec<u8>>, &Option<Vec<u8>>) -> Option<NativeStream>,
{
    drain_reader_events(receiver, stdout, stderr)?;

    let finished = observe_finished(stdout, stderr);
    if let Some(stream) = finished {
        // A terminal event is sent before its reader thread can finish. Once a finished handle is
        // observed, drain once more so a queued overflow/read/complete event keeps precedence.
        drain_reader_events(receiver, stdout, stderr)?;
        if !stream_has_terminal_outcome(stream, stdout, stderr) {
            return Err(format!(
                "native command {} reader disappeared without a terminal outcome",
                stream_name(stream)
            ));
        }
    }

    Ok(())
}

fn finished_reader_without_outcome(
    reader_handles: &[ReaderThread],
    stdout: &Option<Vec<u8>>,
    stderr: &Option<Vec<u8>>,
) -> Option<NativeStream> {
    reader_handles.iter().find_map(|reader| {
        let has_terminal_outcome = stream_has_terminal_outcome(reader.stream, stdout, stderr);
        (reader.handle.is_finished() && !has_terminal_outcome).then_some(reader.stream)
    })
}

fn stream_has_terminal_outcome(
    stream: NativeStream,
    stdout: &Option<Vec<u8>>,
    stderr: &Option<Vec<u8>>,
) -> bool {
    match stream {
        NativeStream::Stdout => stdout.is_some(),
        NativeStream::Stderr => stderr.is_some(),
    }
}

fn drain_reader_events(
    receiver: &Receiver<ReaderEvent>,
    stdout: &mut Option<Vec<u8>>,
    stderr: &mut Option<Vec<u8>>,
) -> Result<(), String> {
    loop {
        match receiver.try_recv() {
            Ok(ReaderEvent::Complete { stream, bytes }) => {
                let target = match stream {
                    NativeStream::Stdout => &mut *stdout,
                    NativeStream::Stderr => &mut *stderr,
                };
                if target.replace(bytes).is_some() {
                    return Err(format!(
                        "native command {} reader completed more than once",
                        stream_name(stream)
                    ));
                }
            }
            Ok(ReaderEvent::LimitExceeded { stream, limit }) => {
                return Err(format!(
                    "native command {} exceeded its {limit}-byte output limit",
                    stream_name(stream)
                ));
            }
            Ok(ReaderEvent::ReadFailed { stream, message }) => {
                return Err(format!(
                    "native command {} reader failed: {message}",
                    stream_name(stream)
                ));
            }
            Err(TryRecvError::Empty) => return Ok(()),
            Err(TryRecvError::Disconnected) => {
                if stdout.is_some() && stderr.is_some() {
                    return Ok(());
                }
                return Err("native command reader event channel disconnected before both streams completed".to_owned());
            }
        }
    }
}

fn stream_name(stream: NativeStream) -> &'static str {
    match stream {
        NativeStream::Stdout => "stdout",
        NativeStream::Stderr => "stderr",
    }
}

trait TerminationOperations {
    #[cfg(unix)]
    fn signal_group(&mut self, signal: i32) -> io::Result<()>;
    fn try_wait_direct(&mut self) -> io::Result<Option<ExitStatus>>;
    fn kill_direct(&mut self) -> io::Result<()>;
}

struct ChildTerminationOperations<'a> {
    child: &'a mut Child,
    #[cfg(unix)]
    process_group: Option<i32>,
}

#[cfg(unix)]
type NativeProcessGroup = Option<i32>;
#[cfg(not(unix))]
type NativeProcessGroup = ();

impl TerminationOperations for ChildTerminationOperations<'_> {
    #[cfg(unix)]
    fn signal_group(&mut self, signal: i32) -> io::Result<()> {
        let process_group = self.process_group.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "child PID is not a positive i32",
            )
        })?;
        // SAFETY: process_group is a checked positive i32; negation targets only that child's group.
        let result = unsafe { libc::kill(-process_group, signal) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn try_wait_direct(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    fn kill_direct(&mut self) -> io::Result<()> {
        self.child.kill()
    }
}

#[cfg(unix)]
fn terminate_process<T: TerminationOperations>(
    operations: &mut T,
    direct_reaped: bool,
    termination_grace: Duration,
) -> Vec<String> {
    if direct_reaped {
        return Vec::new();
    }

    let mut failures = Vec::new();
    if let Err(error) = operations.signal_group(libc::SIGTERM) {
        failures.push(format!(
            "failed to send SIGTERM to native command group: {error}"
        ));
    }

    let grace_started = Instant::now();
    while grace_started.elapsed() < termination_grace {
        let remaining = termination_grace.saturating_sub(grace_started.elapsed());
        if !remaining.is_zero() {
            thread::sleep(Duration::from_millis(5).min(remaining));
        }
    }

    if let Err(error) = operations.signal_group(libc::SIGKILL) {
        failures.push(format!(
            "failed to send SIGKILL to native command group: {error}"
        ));
    }
    terminate_and_reap_direct(operations, termination_grace, &mut failures);
    failures
}

#[cfg(not(unix))]
fn terminate_process<T: TerminationOperations>(
    operations: &mut T,
    direct_reaped: bool,
    termination_grace: Duration,
) -> Vec<String> {
    if direct_reaped {
        return Vec::new();
    }
    let mut failures = Vec::new();
    terminate_and_reap_direct(operations, termination_grace, &mut failures);
    failures
}

fn terminate_and_reap_direct<T: TerminationOperations>(
    operations: &mut T,
    termination_grace: Duration,
    failures: &mut Vec<String>,
) {
    if let Err(error) = operations.kill_direct() {
        failures.push(format!("failed to kill native command directly: {error}"));
    }

    let reap_started = Instant::now();
    loop {
        match operations.try_wait_direct() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(error) => {
                failures.push(format!(
                    "failed to poll native command during cleanup: {error}"
                ));
                return;
            }
        }

        let elapsed = reap_started.elapsed();
        if elapsed >= termination_grace {
            failures.push(format!(
                "native command remained unreaped after {} ms",
                termination_grace.as_millis()
            ));
            return;
        }
        thread::sleep(Duration::from_millis(5).min(termination_grace.saturating_sub(elapsed)));
    }
}

#[derive(Clone, Copy)]
struct CleanupContext<'a> {
    program: &'a Path,
    limits: &'a CommandLimits,
}

impl<'a> CleanupContext<'a> {
    fn new(program: &'a Path, limits: &'a CommandLimits) -> Self {
        Self { program, limits }
    }
}

fn cleanup_error(
    context: CleanupContext<'_>,
    child: &mut Child,
    process_group: NativeProcessGroup,
    direct_reaped: bool,
    reader_handles: Vec<ReaderThread>,
    event_receiver: &Receiver<ReaderEvent>,
    primary: String,
) -> Result<NativeCommandOutput, NativeCommandError> {
    #[cfg(not(unix))]
    let _ = process_group;
    let mut operations = ChildTerminationOperations {
        child,
        #[cfg(unix)]
        process_group,
    };
    let mut cleanup_failures = terminate_process(
        &mut operations,
        direct_reaped,
        context.limits.termination_grace,
    );
    cleanup_failures.extend(close_readers(
        reader_handles,
        event_receiver,
        context.limits.reader_close_grace,
    ));

    let message = if cleanup_failures.is_empty() {
        primary
    } else {
        format!(
            "{primary}; cleanup failures: {}",
            cleanup_failures.join("; ")
        )
    };
    Err(native_command_io_error(context.program, message))
}

fn close_readers(
    reader_handles: Vec<ReaderThread>,
    event_receiver: &Receiver<ReaderEvent>,
    reader_close_grace: Duration,
) -> Vec<String> {
    let close_started = Instant::now();
    while reader_handles
        .iter()
        .any(|reader| !reader.handle.is_finished())
        && close_started.elapsed() < reader_close_grace
    {
        while event_receiver.try_recv().is_ok() {}
        let remaining = reader_close_grace.saturating_sub(close_started.elapsed());
        if !remaining.is_zero() {
            thread::sleep(Duration::from_millis(5).min(remaining));
        }
    }
    while event_receiver.try_recv().is_ok() {}

    let mut failures = Vec::new();
    for reader in reader_handles {
        if reader.handle.is_finished() && reader.handle.join().is_err() {
            failures.push("native command reader thread panicked during cleanup".to_owned());
        }
    }
    failures
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

fn native_command_io_error(program: &Path, message: String) -> NativeCommandError {
    NativeCommandError::Io(format!("native command '{}': {message}", program.display()))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::io::Write;
    use std::io::{self, Cursor, Read};
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;
    #[cfg(unix)]
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::process::ExitStatus;
    #[cfg(unix)]
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};
    #[cfg(unix)]
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn expect_io_with_program(
        result: Result<NativeCommandOutput, NativeCommandError>,
        program: &Path,
        reason: &str,
    ) -> String {
        let NativeCommandError::Io(message) = result.expect_err("native command should fail")
        else {
            panic!("native command failure should be an I/O error");
        };
        assert!(
            message.contains(&program.display().to_string()),
            "I/O error should name executable {}: {message}",
            program.display()
        );
        assert!(
            message.contains(reason),
            "I/O error should preserve reason {reason:?}: {message}"
        );
        message
    }

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

    #[test]
    fn terminal_event_published_during_finished_observation_keeps_precedence() {
        let (event_sender, event_receiver) = mpsc::channel();
        let mut stdout = None;
        let mut stderr = None;
        let mut observations = 0;

        observe_reader_state_with(&event_receiver, &mut stdout, &mut stderr, |_, _| {
            observations += 1;
            if observations == 1 {
                event_sender
                    .send(ReaderEvent::LimitExceeded {
                        stream: NativeStream::Stdout,
                        limit: 7,
                    })
                    .expect("terminal event should be published deterministically");
                None
            } else {
                Some(NativeStream::Stdout)
            }
        })
        .expect("a fresh finished decision must wait for the next observation cycle");

        let error =
            observe_reader_state_with(&event_receiver, &mut stdout, &mut stderr, |_, _| None)
                .expect_err("the queued terminal event should win on the next observation cycle");
        assert!(error.contains("stdout exceeded its 7-byte output limit"));
        assert!(!error.contains("disappeared"));
    }

    fn run_bounded_reader<R: Read>(
        reader: R,
        stream: NativeStream,
        limit: usize,
    ) -> Vec<ReaderEvent> {
        let mut events = Vec::new();
        read_bounded_stream(reader, stream, limit, |event| events.push(event));

        events
    }

    #[test]
    fn bounded_reader_completes_at_the_exact_cap_with_identical_raw_bytes() {
        let raw_bytes = vec![0, 255, 1, 2, 3, 0, 4, 5];
        let events = run_bounded_reader(
            Cursor::new(raw_bytes.clone()),
            NativeStream::Stdout,
            raw_bytes.len(),
        );

        assert_eq!(
            events,
            vec![ReaderEvent::Complete {
                stream: NativeStream::Stdout,
                bytes: raw_bytes,
            }]
        );
    }

    #[test]
    fn bounded_reader_reports_cap_plus_one_with_its_stream_and_limit() {
        let events = run_bounded_reader(Cursor::new(b"12345"), NativeStream::Stderr, 4);

        assert_eq!(
            events,
            vec![ReaderEvent::LimitExceeded {
                stream: NativeStream::Stderr,
                limit: 4,
            }]
        );
    }

    #[test]
    fn bounded_reader_retained_length_and_capacity_never_exceed_cap() {
        let limit = 5;
        let events = run_bounded_reader(Cursor::new(vec![42; limit]), NativeStream::Stdout, limit);

        assert!(matches!(
            events.as_slice(),
            [ReaderEvent::Complete { stream: NativeStream::Stdout, bytes }]
                if bytes.len() == limit && bytes.capacity() <= limit
        ));
    }

    #[test]
    fn bounded_reader_uses_fixed_eight_kib_read_requests() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let reader = RequestedReadReader {
            cursor: Cursor::new(vec![7; 16 * 1024 + 1]),
            requests: Arc::clone(&requests),
        };

        let events = run_bounded_reader(reader, NativeStream::Stdout, 1);

        assert_eq!(
            events,
            vec![ReaderEvent::LimitExceeded {
                stream: NativeStream::Stdout,
                limit: 1,
            }]
        );
        let requests = requests.lock().expect("request log should not be poisoned");
        assert!(!requests.is_empty());
        assert!(requests.iter().all(|request| *request == 8 * 1024));
    }

    #[test]
    fn bounded_reader_reports_read_failure_with_stream_and_context() {
        let events = run_bounded_reader(FailingReader, NativeStream::Stderr, 10);

        assert!(matches!(
            events.as_slice(),
            [ReaderEvent::ReadFailed { stream: NativeStream::Stderr, message }]
                if message.contains("synthetic read failure")
        ));
    }

    #[test]
    fn bounded_reader_keeps_stdout_and_stderr_events_distinct() {
        let stdout_events = run_bounded_reader(Cursor::new(b"a"), NativeStream::Stdout, 1);
        let stderr_events = run_bounded_reader(Cursor::new(b"a"), NativeStream::Stderr, 1);

        assert_eq!(
            stdout_events,
            vec![ReaderEvent::Complete {
                stream: NativeStream::Stdout,
                bytes: b"a".to_vec(),
            }]
        );
        assert_eq!(
            stderr_events,
            vec![ReaderEvent::Complete {
                stream: NativeStream::Stderr,
                bytes: b"a".to_vec(),
            }]
        );
    }

    #[test]
    fn bounded_reader_does_not_replace_overflow_with_a_later_read_error() {
        let events = run_bounded_reader(
            OverflowThenErrorReader { first_read: true },
            NativeStream::Stdout,
            4,
        );

        assert_eq!(
            events,
            vec![ReaderEvent::LimitExceeded {
                stream: NativeStream::Stdout,
                limit: 4,
            }]
        );
    }

    #[test]
    fn bounded_reader_thread_delivers_complete_bytes_before_verification_join() {
        let raw_bytes = vec![0, 255, 1, 2, 3];
        let (event_sender, event_receiver) = mpsc::channel();
        let handle = spawn_bounded_reader(
            "bounded-reader-complete-test",
            Cursor::new(raw_bytes.clone()),
            NativeStream::Stdout,
            raw_bytes.len(),
            event_sender,
        )
        .expect("reader thread should spawn");

        assert_eq!(
            event_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("complete bytes should arrive without joining"),
            ReaderEvent::Complete {
                stream: NativeStream::Stdout,
                bytes: raw_bytes,
            }
        );
        let verification: () = handle.join().expect("reader thread should finish");
        assert_eq!(verification, ());
    }

    #[test]
    fn bounded_reader_thread_emits_one_overflow_before_draining_to_eof() {
        let limit = 4;
        let input = b"abcdefghi".to_vec();
        let drained = Arc::new(AtomicUsize::new(0));
        let (blocked_at_second_read_sender, blocked_at_second_read_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let (event_sender, event_receiver) = mpsc::channel();
        let reader = BlockingReader {
            input: input.clone(),
            position: 0,
            blocked_at_second_read_sender,
            release_receiver,
            drained: Arc::clone(&drained),
        };

        let handle = spawn_bounded_reader(
            "bounded-reader-test",
            reader,
            NativeStream::Stderr,
            limit,
            event_sender,
        )
        .expect("reader thread should spawn");

        blocked_at_second_read_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("reader should block after emitting its overflow");
        assert_eq!(
            event_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("overflow should arrive before EOF"),
            ReaderEvent::LimitExceeded {
                stream: NativeStream::Stderr,
                limit,
            }
        );
        assert!(matches!(
            event_receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        release_sender
            .send(())
            .expect("reader should be waiting for release");
        let verification: () = handle.join().expect("reader thread should finish");

        assert_eq!(verification, ());
        assert_eq!(drained.load(Ordering::SeqCst), input.len());
        assert!(matches!(
            event_receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected)
        ));
    }

    struct RequestedReadReader {
        cursor: Cursor<Vec<u8>>,
        requests: Arc<Mutex<Vec<usize>>>,
    }

    impl Read for RequestedReadReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.requests
                .lock()
                .expect("request log should not be poisoned")
                .push(buffer.len());
            self.cursor.read(buffer)
        }
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic read failure"))
        }
    }

    struct OverflowThenErrorReader {
        first_read: bool,
    }

    impl Read for OverflowThenErrorReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.first_read {
                self.first_read = false;
                buffer[..5].copy_from_slice(b"12345");
                Ok(5)
            } else {
                Err(io::Error::other("later synthetic read failure"))
            }
        }
    }

    struct BlockingReader {
        input: Vec<u8>,
        position: usize,
        blocked_at_second_read_sender: mpsc::Sender<()>,
        release_receiver: mpsc::Receiver<()>,
        drained: Arc<AtomicUsize>,
    }

    #[cfg(unix)]
    const MARKED_HELPER_PREFIX: &str = "aegisforge-marked-native-command-";
    #[cfg(unix)]
    const MARKED_HELPER_TEST: &str = "macos::command::tests::marked_native_command_helper";
    #[cfg(unix)]
    static TERM_RECEIVED: AtomicBool = AtomicBool::new(false);

    #[cfg(unix)]
    extern "C" fn record_term(_signal: libc::c_int) {
        TERM_RECEIVED.store(true, Ordering::SeqCst);
    }

    #[cfg(unix)]
    fn install_term_handler() {
        TERM_RECEIVED.store(false, Ordering::SeqCst);
        // SAFETY: the handler only stores to a lock-free atomic and has the required C ABI.
        unsafe {
            libc::signal(
                libc::SIGTERM,
                record_term as *const () as libc::sighandler_t,
            );
        }
    }

    #[cfg(unix)]
    fn atomic_write(path: &Path, bytes: &[u8]) {
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, bytes).expect("helper should write its temporary marker");
        fs::rename(temporary, path).expect("helper should atomically publish its marker");
    }

    #[cfg(unix)]
    fn helper_sidecar(argv0: &Path, suffix: &str) -> PathBuf {
        let file_name = argv0
            .file_name()
            .expect("marked helper argv0 should have a file name")
            .to_string_lossy();
        argv0.with_file_name(format!("{file_name}.{suffix}"))
    }

    #[cfg(unix)]
    #[test]
    fn marked_native_command_helper() {
        let raw_arguments: Vec<OsString> = std::env::args_os().collect();
        let argv0 = PathBuf::from(&raw_arguments[0]);
        let Some(file_name) = argv0.file_name().and_then(|name| name.to_str()) else {
            return;
        };
        if !file_name.starts_with(MARKED_HELPER_PREFIX) {
            return;
        }
        assert_eq!(
            raw_arguments[1..],
            [
                OsString::from("--exact"),
                OsString::from(MARKED_HELPER_TEST),
                OsString::from("--nocapture"),
            ],
            "marked helpers must run only in the exact expected libtest context"
        );

        if file_name.contains("escaped-descendant") {
            // SAFETY: this single-threaded helper intentionally leaves its inherited process
            // group, reproducing a pipe-holding descendant outside the recorded child group.
            assert!(
                unsafe { libc::setsid() } > 0,
                "helper should create a new session"
            );
            atomic_write(
                &helper_sidecar(&argv0, "pid"),
                std::process::id().to_string().as_bytes(),
            );
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(2) {
                thread::sleep(Duration::from_millis(5));
            }
            return;
        }

        if file_name.contains("escaped-leader") {
            atomic_write(
                &helper_sidecar(&argv0, "pid"),
                std::process::id().to_string().as_bytes(),
            );
            let descendant = argv0.with_file_name(file_name.replace("leader", "descendant"));
            let mut child = Command::new(&descendant)
                .args(["--exact", MARKED_HELPER_TEST, "--nocapture"])
                .stdin(Stdio::null())
                .spawn()
                .expect("escaped leader should spawn its session descendant");
            wait_for_path(&helper_sidecar(&descendant, "pid"), Duration::from_secs(1));
            let _ = child.try_wait();
            return;
        }

        if file_name.contains("direct-term") || file_name.contains("descendant") {
            install_term_handler();
            atomic_write(
                &helper_sidecar(&argv0, "pid"),
                std::process::id().to_string().as_bytes(),
            );
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(5) {
                if TERM_RECEIVED.swap(false, Ordering::SeqCst) {
                    atomic_write(&helper_sidecar(&argv0, "term"), b"term");
                }
                thread::sleep(Duration::from_millis(5));
            }
            return;
        }

        if file_name.contains("leader") {
            let descendant_name = file_name.replace("leader", "descendant");
            let descendant = argv0.with_file_name(descendant_name);
            let mut child = Command::new(descendant)
                .args(["--exact", MARKED_HELPER_TEST, "--nocapture"])
                .stdin(Stdio::null())
                .spawn()
                .expect("leader helper should spawn its marked descendant");
            let descendant_pid = helper_sidecar(
                &argv0.with_file_name(file_name.replace("leader", "descendant")),
                "pid",
            );
            wait_for_path(&descendant_pid, Duration::from_secs(2));
            let _ = child.try_wait();
            return;
        }

        if file_name.contains("stdout-overflow") {
            std::io::stdout()
                .write_all(&vec![b'o'; 128 * 1024])
                .expect("helper should write oversized stdout");
            return;
        }

        if file_name.contains("stderr-overflow") {
            std::io::stderr()
                .write_all(&vec![b'e'; 128 * 1024])
                .expect("helper should write oversized stderr");
            return;
        }

        if file_name.contains("raw-output") {
            std::io::stdout()
                .write_all(&[0, 255, b'O', b'U', b'T'])
                .expect("helper should write raw stdout");
            std::io::stderr()
                .write_all(&[0, 254, b'E', b'R', b'R'])
                .expect("helper should write raw stderr");
            std::process::exit(7);
        }

        panic!("unknown marked helper role: {file_name}");
    }

    #[cfg(unix)]
    struct MarkedHelper {
        directory: PathBuf,
        executable: PathBuf,
    }

    #[cfg(unix)]
    impl MarkedHelper {
        fn new(role: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "aegisforge-native-command-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&directory).expect("test helper directory should be created");
            let executable = directory.join(format!("{MARKED_HELPER_PREFIX}{role}-{nonce}"));
            let current_executable = std::env::current_exe()
                .expect("test executable path should be available")
                .canonicalize()
                .expect("test executable path should be absolute and canonical");
            std::os::unix::fs::symlink(current_executable, &executable)
                .expect("marked helper symlink should be created");
            Self {
                directory,
                executable,
            }
        }

        fn arguments() -> [OsString; 3] {
            [
                OsString::from("--exact"),
                OsString::from(MARKED_HELPER_TEST),
                OsString::from("--nocapture"),
            ]
        }

        fn sidecar(&self, suffix: &str) -> PathBuf {
            helper_sidecar(&self.executable, suffix)
        }

        fn wait_for_exit(&self, timeout: Duration) {
            wait_for_esrch(&self.sidecar("pid"), timeout);
        }
    }

    #[cfg(unix)]
    impl Drop for MarkedHelper {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[cfg(unix)]
    fn wait_for_path(path: &Path, timeout: Duration) {
        let started = Instant::now();
        while !path.exists() && started.elapsed() < timeout {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(path.exists(), "timed out waiting for {}", path.display());
    }

    #[cfg(unix)]
    fn wait_for_esrch(pid_sidecar: &Path, timeout: Duration) {
        let pid = fs::read_to_string(pid_sidecar)
            .expect("helper pid should have been published")
            .parse::<i32>()
            .expect("helper pid should be a valid i32");
        let started = Instant::now();
        loop {
            // SAFETY: signal zero does not alter the process and pid is helper-published.
            let result = unsafe { libc::kill(pid, 0) };
            if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                fs::remove_file(pid_sidecar).expect("confirmed-dead helper PID should be consumed");
                return;
            }
            assert!(started.elapsed() < timeout, "PID {pid} remained alive");
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn test_limits(timeout: Duration, output_limit: usize) -> CommandLimits {
        CommandLimits {
            timeout,
            output_limit,
            poll_interval: Duration::from_millis(5),
            termination_grace: Duration::from_millis(100),
            reader_close_grace: Duration::from_millis(100),
        }
    }

    #[test]
    fn oversized_limit_is_rejected_before_spawn_while_zero_and_small_are_valid() {
        let missing = Path::new("/aegisforge/definitely/missing/native-command");
        let arguments = [];

        let oversized = run_with_limits(
            missing,
            &arguments,
            test_limits(Duration::from_millis(10), MAX_NATIVE_OUTPUT_BYTES + 1),
        );
        expect_io_with_program(oversized, missing, "output limit");

        for valid_limit in [0, 7] {
            let result = run_with_limits(
                missing,
                &arguments,
                test_limits(Duration::from_millis(10), valid_limit),
            );
            assert!(matches!(result, Err(NativeCommandError::Unavailable(_))));
        }
    }

    #[test]
    fn duration_max_limits_are_structured_io_errors_before_spawn() {
        let program = Path::new("/aegisforge/definitely/missing/native-command");
        let base = test_limits(Duration::from_millis(10), 1024);
        let pathological_limits = [
            (
                "timeout",
                CommandLimits {
                    timeout: Duration::MAX,
                    ..base
                },
            ),
            (
                "poll interval",
                CommandLimits {
                    poll_interval: Duration::MAX,
                    ..base
                },
            ),
            (
                "termination grace",
                CommandLimits {
                    termination_grace: Duration::MAX,
                    ..base
                },
            ),
            (
                "reader close grace",
                CommandLimits {
                    reader_close_grace: Duration::MAX,
                    ..base
                },
            ),
        ];

        for (reason, limits) in pathological_limits {
            let result = std::panic::catch_unwind(|| run_with_limits(program, &[], limits));
            let command_result = result.expect("pathological duration must not panic");
            expect_io_with_program(command_result, program, reason);
        }
    }

    #[cfg(unix)]
    #[test]
    fn timeout_sends_term_then_kill_and_reaps_direct_helper() {
        let helper = MarkedHelper::new("direct-term");
        let result = run_with_limits(
            &helper.executable,
            &MarkedHelper::arguments(),
            test_limits(Duration::from_millis(250), 64 * 1024),
        );

        expect_io_with_program(result, &helper.executable, "timed out");
        wait_for_path(&helper.sidecar("term"), Duration::from_secs(1));
        helper.wait_for_exit(Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn escaped_session_descendant_returns_promptly_through_full_supervision() {
        let helper = MarkedHelper::new("escaped-leader");
        let descendant = helper.executable.with_file_name(
            helper
                .executable
                .file_name()
                .expect("escaped leader should have a file name")
                .to_string_lossy()
                .replace("leader", "descendant"),
        );
        std::os::unix::fs::symlink(
            fs::read_link(&helper.executable).expect("escaped leader symlink should have a target"),
            &descendant,
        )
        .expect("escaped descendant helper symlink should be created");
        let started = Instant::now();
        let result = run_with_limits(
            &helper.executable,
            &MarkedHelper::arguments(),
            test_limits(Duration::from_millis(100), 64 * 1024),
        );
        let elapsed = started.elapsed();

        expect_io_with_program(result, &helper.executable, "timed out");
        helper.wait_for_exit(Duration::from_secs(1));
        wait_for_esrch(&helper_sidecar(&descendant, "pid"), Duration::from_secs(3));
        assert!(
            elapsed < Duration::from_secs(1),
            "escaped-session cleanup blocked for {elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn exited_leader_with_open_descendant_pipe_times_out_and_kills_process_group() {
        let leader = MarkedHelper::new("leader");
        let descendant = leader.executable.with_file_name(
            leader
                .executable
                .file_name()
                .expect("leader should have a file name")
                .to_string_lossy()
                .replace("leader", "descendant"),
        );
        std::os::unix::fs::symlink(
            fs::read_link(&leader.executable).expect("leader symlink should have a target"),
            &descendant,
        )
        .expect("descendant helper symlink should be created");

        let result = run_with_limits(
            &leader.executable,
            &MarkedHelper::arguments(),
            test_limits(Duration::from_millis(350), 64 * 1024),
        );

        expect_io_with_program(result, &leader.executable, "timed out");
        let descendant_term = helper_sidecar(&descendant, "term");
        let descendant_pid = helper_sidecar(&descendant, "pid");
        wait_for_path(&descendant_term, Duration::from_secs(1));
        wait_for_esrch(&descendant_pid, Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn stdout_and_stderr_limits_are_independent() {
        for (role, expected_stream) in
            [("stdout-overflow", "stdout"), ("stderr-overflow", "stderr")]
        {
            let helper = MarkedHelper::new(role);
            let result = run_with_limits(
                &helper.executable,
                &MarkedHelper::arguments(),
                test_limits(Duration::from_secs(2), 1024),
            );
            let message = expect_io_with_program(result, &helper.executable, "limit");
            assert!(message.contains(expected_stream));
        }
    }

    #[cfg(unix)]
    #[test]
    fn bounded_raw_streams_and_exit_code_are_preserved() {
        let helper = MarkedHelper::new("raw-output");
        let output = run_with_limits(
            &helper.executable,
            &MarkedHelper::arguments(),
            test_limits(Duration::from_secs(2), 64 * 1024),
        )
        .expect("bounded helper should complete");

        assert!(!output.success);
        assert_eq!(output.exit_code, Some(7));
        assert!(
            output
                .stdout
                .windows(5)
                .any(|bytes| bytes == [0, 255, b'O', b'U', b'T'])
        );
        assert!(
            output
                .stderr
                .windows(5)
                .any(|bytes| bytes == [0, 254, b'E', b'R', b'R'])
        );
    }

    #[cfg(unix)]
    #[test]
    fn direct_sleep_timeout_returns_promptly() {
        let started = Instant::now();
        let program = Path::new("/bin/sleep");
        let result = run_with_limits(
            program,
            &[OsString::from("10")],
            test_limits(Duration::from_millis(50), 1024),
        );

        expect_io_with_program(result, program, "timed out");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(unix)]
    struct SyntheticReaderSpawner {
        behavior: SyntheticReaderBehavior,
        calls: usize,
        wait_for_pid: Option<PathBuf>,
        sibling_release: Option<mpsc::Receiver<()>>,
    }

    #[cfg(unix)]
    enum SyntheticReaderBehavior {
        ReadFailed,
        Disconnect,
        SinglePanicBlockedSibling,
        SetupFailure,
        JoinFailure,
    }

    #[cfg(unix)]
    impl ReaderSpawner for SyntheticReaderSpawner {
        fn spawn(
            &mut self,
            _name: &str,
            reader: Box<dyn Read + Send>,
            stream: NativeStream,
            _limit: usize,
            events: mpsc::Sender<ReaderEvent>,
        ) -> io::Result<JoinHandle<()>> {
            self.calls += 1;
            if let Some(pid) = &self.wait_for_pid {
                wait_for_path(pid, Duration::from_secs(2));
            }
            match self.behavior {
                SyntheticReaderBehavior::SetupFailure => {
                    drop(reader);
                    Err(io::Error::other("synthetic reader setup failure"))
                }
                SyntheticReaderBehavior::ReadFailed => thread::Builder::new().spawn(move || {
                    drop(reader);
                    if stream == NativeStream::Stdout {
                        let _ = events.send(ReaderEvent::ReadFailed {
                            stream,
                            message: "synthetic supervision read failure".to_owned(),
                        });
                    }
                }),
                SyntheticReaderBehavior::Disconnect => thread::Builder::new().spawn(move || {
                    drop(reader);
                    drop(events);
                    panic!("synthetic reader disappearance");
                }),
                SyntheticReaderBehavior::SinglePanicBlockedSibling => {
                    if stream == NativeStream::Stdout {
                        thread::Builder::new().spawn(move || {
                            drop(reader);
                            drop(events);
                            panic!("synthetic stdout reader disappearance");
                        })
                    } else {
                        let release = self
                            .sibling_release
                            .take()
                            .expect("blocked sibling release should be configured");
                        thread::Builder::new().spawn(move || {
                            let _ = release.recv_timeout(Duration::from_secs(2));
                            drop(reader);
                            drop(events);
                        })
                    }
                }
                SyntheticReaderBehavior::JoinFailure => thread::Builder::new().spawn(move || {
                    drop(reader);
                    let _ = events.send(ReaderEvent::Complete {
                        stream,
                        bytes: Vec::new(),
                    });
                    if stream == NativeStream::Stdout {
                        panic!("synthetic reader join failure");
                    }
                }),
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn synthetic_read_failure_triggers_cleanup_and_io() {
        let started = Instant::now();
        let program = Path::new("/bin/sleep");
        let mut spawner = SyntheticReaderSpawner {
            behavior: SyntheticReaderBehavior::ReadFailed,
            calls: 0,
            wait_for_pid: None,
            sibling_release: None,
        };
        let result = run_with_limits_and_spawner(
            program,
            &[OsString::from("10")],
            test_limits(Duration::from_secs(2), 1024),
            &mut spawner,
        );

        expect_io_with_program(result, program, "synthetic supervision read failure");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(spawner.calls, 2);
    }

    #[cfg(unix)]
    #[test]
    fn post_spawn_reader_setup_failure_kills_and_reaps_running_child() {
        let helper = MarkedHelper::new("direct-term");
        let mut spawner = SyntheticReaderSpawner {
            behavior: SyntheticReaderBehavior::SetupFailure,
            calls: 0,
            wait_for_pid: Some(helper.sidecar("pid")),
            sibling_release: None,
        };
        let result = run_with_limits_and_spawner(
            &helper.executable,
            &MarkedHelper::arguments(),
            test_limits(Duration::from_secs(2), 1024),
            &mut spawner,
        );

        expect_io_with_program(result, &helper.executable, "reader setup");
        helper.wait_for_exit(Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn synthetic_cleanup_failure_names_executable_and_preserves_both_reasons() {
        let program = Path::new("/usr/bin/true");
        let mut child = Command::new(program)
            .spawn()
            .expect("synthetic cleanup child should spawn");
        let (event_sender, event_receiver) = mpsc::channel();
        drop(event_sender);

        let result = cleanup_error(
            CleanupContext::new(program, &test_limits(Duration::from_secs(1), 1024)),
            &mut child,
            None,
            false,
            Vec::new(),
            &event_receiver,
            "synthetic primary failure".to_owned(),
        );

        let message = expect_io_with_program(result, program, "synthetic primary failure");
        assert!(message.contains("cleanup failures"));
        assert!(message.contains("SIGTERM"));
    }

    #[cfg(unix)]
    #[test]
    fn synthetic_reader_join_failure_names_executable_and_discards_output() {
        let program = Path::new("/usr/bin/true");
        let mut spawner = SyntheticReaderSpawner {
            behavior: SyntheticReaderBehavior::JoinFailure,
            calls: 0,
            wait_for_pid: None,
            sibling_release: None,
        };

        let result = run_with_limits_and_spawner(
            program,
            &[],
            test_limits(Duration::from_secs(2), 1024),
            &mut spawner,
        );

        expect_io_with_program(result, program, "reader thread panicked");
        assert_eq!(spawner.calls, 2);
    }

    #[cfg(unix)]
    #[test]
    fn recorded_exit_skips_all_termination_operations() {
        let mut operations = RecordingTerminationOperations::default();

        terminate_process(&mut operations, true, Duration::from_millis(1));

        assert!(operations.group_signals.is_empty());
        assert_eq!(operations.direct_kills, 0);
        assert_eq!(operations.direct_polls, 0);
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_keeps_leader_unreaped_until_after_group_kill() {
        let mut operations = RecordingTerminationOperations {
            direct_poll_result: Some(ExitStatus::from_raw(0)),
            ..RecordingTerminationOperations::default()
        };

        terminate_process(&mut operations, false, Duration::from_millis(10));

        assert_eq!(operations.group_signals, vec![libc::SIGTERM, libc::SIGKILL]);
        assert_eq!(
            operations.events,
            vec!["group-term", "group-kill", "direct-kill", "direct-poll"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn ineffective_direct_kill_uses_only_bounded_nonblocking_reap_poll() {
        let mut operations = RecordingTerminationOperations {
            direct_kill_error: true,
            ..RecordingTerminationOperations::default()
        };

        let failures = terminate_process(&mut operations, false, Duration::ZERO);

        assert_eq!(
            operations.events,
            vec!["group-term", "group-kill", "direct-kill", "direct-poll"]
        );
        assert!(failures.iter().any(|failure| failure.contains("directly")));
        assert!(failures.iter().any(|failure| failure.contains("unreaped")));
    }

    #[cfg(unix)]
    #[derive(Default)]
    struct RecordingTerminationOperations {
        group_signals: Vec<i32>,
        direct_kills: usize,
        direct_polls: usize,
        direct_poll_result: Option<ExitStatus>,
        direct_kill_error: bool,
        events: Vec<&'static str>,
    }

    #[cfg(unix)]
    impl TerminationOperations for RecordingTerminationOperations {
        fn signal_group(&mut self, signal: i32) -> io::Result<()> {
            self.group_signals.push(signal);
            self.events.push(if signal == libc::SIGTERM {
                "group-term"
            } else {
                "group-kill"
            });
            Ok(())
        }

        fn try_wait_direct(&mut self) -> io::Result<Option<ExitStatus>> {
            self.direct_polls += 1;
            self.events.push("direct-poll");
            Ok(self.direct_poll_result)
        }

        fn kill_direct(&mut self) -> io::Result<()> {
            self.direct_kills += 1;
            self.events.push("direct-kill");
            if self.direct_kill_error {
                Err(io::Error::other("synthetic direct kill failure"))
            } else {
                Ok(())
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn reader_panics_are_detected_instead_of_timing_out() {
        let started = Instant::now();
        let program = Path::new("/bin/sleep");
        let mut spawner = SyntheticReaderSpawner {
            behavior: SyntheticReaderBehavior::Disconnect,
            calls: 0,
            wait_for_pid: None,
            sibling_release: None,
        };
        let result = run_with_limits_and_spawner(
            program,
            &[OsString::from("10")],
            test_limits(Duration::from_secs(2), 1024),
            &mut spawner,
        );

        expect_io_with_program(result, program, "reader");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn one_reader_panic_is_not_masked_by_a_live_sibling_sender() {
        let (release_sender, release_receiver) = mpsc::channel();
        let started = Instant::now();
        let program = Path::new("/bin/sleep");
        let mut spawner = SyntheticReaderSpawner {
            behavior: SyntheticReaderBehavior::SinglePanicBlockedSibling,
            calls: 0,
            wait_for_pid: None,
            sibling_release: Some(release_receiver),
        };
        let result = run_with_limits_and_spawner(
            program,
            &[OsString::from("10")],
            test_limits(Duration::from_millis(200), 1024),
            &mut spawner,
        );
        let elapsed = started.elapsed();
        let _ = release_sender.send(());

        expect_io_with_program(result, program, "stdout reader disappeared");
        assert!(
            elapsed < Duration::from_secs(1),
            "single-reader disappearance was detected too late: {elapsed:?}"
        );
        assert_eq!(spawner.calls, 2);
    }

    impl Read for BlockingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.position == 5 {
                self.blocked_at_second_read_sender.send(()).map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "test coordinator dropped")
                })?;
                self.release_receiver.recv().map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "test coordinator dropped")
                })?;
            }

            let remaining = &self.input[self.position..];
            let first_chunk_limit = if self.position == 0 { 5 } else { buffer.len() };
            let read = remaining.len().min(first_chunk_limit).min(buffer.len());
            buffer[..read].copy_from_slice(&remaining[..read]);
            self.position += read;
            self.drained.fetch_add(read, Ordering::SeqCst);
            Ok(read)
        }
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
