mod cli;
mod detection;
mod macos;
mod report;
mod scanner;

use std::io::{self, Write};

use clap::Parser;
use cli::{Cli, Commands};
use report::text::write_text;
use scanner::result::ScanResult;
use scanner::scan::scan_path;

fn main() {
    let cli = Cli::parse();

    if let Err(error) = run(cli) {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Scan { path } => {
            let result = scan_path(&path)?;
            let stdout = io::stdout();
            let stderr = io::stderr();
            let mut stdout = stdout.lock();
            let mut stderr = stderr.lock();
            render_scan_result(&result, &mut stdout, &mut stderr)
        }
    }
}

fn render_scan_result<W: Write, E: Write>(
    result: &ScanResult,
    stdout: &mut W,
    stderr: &mut E,
) -> Result<(), String> {
    write_text(result, stdout, stderr)
        .map_err(|error| format!("Failed to write scan report: {error}"))
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::path::PathBuf;

    use crate::scanner::path::PathType;
    use crate::scanner::result::{ScanResult, ScanSummary};

    use super::render_scan_result;

    struct AlwaysFailWriter;

    impl Write for AlwaysFailWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("writer failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("writer failed"))
        }
    }

    fn minimal_scan_result() -> ScanResult {
        ScanResult {
            target: PathBuf::from("sample"),
            target_type: PathType::File,
            artifacts: Vec::new(),
            code_signatures: Vec::new(),
            diagnostics: Vec::new(),
            summary: ScanSummary {
                discovered: 0,
                analyzed: 0,
                failed: 0,
                unknown: 0,
                suspicious: 0,
                malicious: 0,
            },
        }
    }

    #[test]
    fn rendering_failure_is_returned_as_fatal_error() {
        let result = minimal_scan_result();
        let mut stdout = AlwaysFailWriter;
        let mut stderr = Vec::new();

        let error = render_scan_result(&result, &mut stdout, &mut stderr)
            .expect_err("rendering failure should be fatal");

        assert_eq!(error, "Failed to write scan report: writer failed");
    }
}
