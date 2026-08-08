use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::Path;

use crate::detection::macho_dependency::classify_dependency;
use crate::detection::rpath::classify_rpath;
use crate::scanner::path::PathType;
use crate::scanner::result::{ScanDiagnostic, ScanResult};

pub fn write_text<W: Write, E: Write>(
    result: &ScanResult,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<()> {
    writeln!(stdout, "AegisForge")?;
    writeln!(stdout, "Target: {}", escape_path(&result.target))?;
    let target_type = match result.target_type {
        PathType::File => "File",
        PathType::Directory => "Directory",
    };
    writeln!(stdout, "Type: {target_type}")?;

    for artifact_result in &result.artifacts {
        let artifact = &artifact_result.artifact;
        let extension = artifact.extension.as_deref().unwrap_or("none");
        writeln!(
            stdout,
            "{} | {} bytes | extension: {} | type: {}",
            escape_path(&artifact.path),
            artifact.size,
            escape_line(extension),
            artifact.file_type.as_str()
        )?;
        writeln!(stdout, "SHA-256: {}", artifact.sha256)?;

        if let Some(macho) = &artifact_result.macho {
            let architecture = macho.architecture.as_deref().unwrap_or("multiple");
            writeln!(
                stdout,
                "Mach-O: {} | architecture: {} | endianness: {}",
                escape_line(&macho.format),
                escape_line(architecture),
                escape_line(&macho.endianness)
            )?;
        }

        if let Some(dependencies) = &artifact_result.macho_dependencies {
            if !dependencies.libraries.is_empty() {
                writeln!(stdout, "Linked libraries:")?;
                for library in &dependencies.libraries {
                    writeln!(
                        stdout,
                        "  - {} [{}]",
                        escape_line(library),
                        classify_dependency(library).as_str()
                    )?;
                }
            }

            if !dependencies.rpaths.is_empty() {
                writeln!(stdout, "Runtime search paths:")?;
                for rpath in &dependencies.rpaths {
                    writeln!(
                        stdout,
                        "  - {} [{}]",
                        escape_line(rpath),
                        classify_rpath(rpath).as_str()
                    )?;
                }
            }
        }

        for evidence in &artifact_result.evidence {
            writeln!(
                stdout,
                "Evidence [{}]: {}",
                evidence.severity.as_str(),
                escape_line(&evidence.message)
            )?;
        }
        writeln!(stdout, "Verdict: {}", artifact_result.verdict.as_str())?;
    }

    let summary = &result.summary;
    writeln!(
        stdout,
        "Summary: {} discovered | {} analyzed | {} failed | {} unknown | {} suspicious | {} malicious",
        summary.discovered,
        summary.analyzed,
        summary.failed,
        summary.unknown,
        summary.suspicious,
        summary.malicious
    )?;

    for diagnostic in &result.diagnostics {
        write_diagnostic(diagnostic, stderr)?;
    }
    for artifact in &result.artifacts {
        for diagnostic in &artifact.diagnostics {
            write_diagnostic(diagnostic, stderr)?;
        }
    }

    stdout.flush()?;
    stderr.flush()?;

    Ok(())
}

fn write_diagnostic<E: Write>(diagnostic: &ScanDiagnostic, stderr: &mut E) -> io::Result<()> {
    match &diagnostic.path {
        Some(path) => writeln!(
            stderr,
            "Warning: {} (path: {})",
            escape_line(&diagnostic.message),
            escape_path(path)
        ),
        None => writeln!(stderr, "Warning: {}", escape_line(&diagnostic.message)),
    }
}

fn escape_path(path: &Path) -> String {
    escape_os_str(path.as_os_str())
}

fn escape_line(value: &str) -> String {
    escape_str(value, false)
}

fn escape_str(value: &str, escape_backslash: bool) -> String {
    let mut escaped = String::with_capacity(value.len());

    for character in value.chars() {
        match character {
            '\\' if escape_backslash => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if should_escape_unicode(character) => {
                escaped.push_str(&format!("\\u{{{:04X}}}", character as u32));
            }
            character => escaped.push(character),
        }
    }

    escaped
}

fn should_escape_unicode(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
        )
}

#[cfg(unix)]
fn escape_os_str(value: &OsStr) -> String {
    use std::os::unix::ffi::OsStrExt;

    let bytes = value.as_bytes();
    let mut escaped = String::with_capacity(bytes.len());
    let mut remaining = bytes;

    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                escaped.push_str(&escape_str(valid, true));
                break;
            }
            Err(error) => {
                let valid_length = error.valid_up_to();
                if valid_length > 0 {
                    match std::str::from_utf8(&remaining[..valid_length]) {
                        Ok(valid) => escaped.push_str(&escape_str(valid, true)),
                        Err(_) => {
                            for byte in &remaining[..valid_length] {
                                escaped.push_str(&format!("\\x{byte:02X}"));
                            }
                        }
                    }
                }

                let invalid_length = error.error_len().unwrap_or(remaining.len() - valid_length);
                for byte in &remaining[valid_length..valid_length + invalid_length] {
                    escaped.push_str(&format!("\\x{byte:02X}"));
                }
                remaining = &remaining[valid_length + invalid_length..];
            }
        }
    }

    escaped
}

#[cfg(windows)]
fn escape_os_str(value: &OsStr) -> String {
    use std::os::windows::ffi::OsStrExt;

    let mut escaped = String::new();
    for decoded in char::decode_utf16(value.encode_wide()) {
        match decoded {
            Ok(character) => {
                let mut encoded = [0; 4];
                escaped.push_str(&escape_str(character.encode_utf8(&mut encoded), true));
            }
            Err(error) => {
                escaped.push_str(&format!("\\u{{{:04X}}}", error.unpaired_surrogate()));
            }
        }
    }
    escaped
}

#[cfg(not(any(unix, windows)))]
fn escape_os_str(value: &OsStr) -> String {
    escape_str(&value.to_string_lossy(), true)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::path::PathBuf;

    use crate::detection::evidence::{Evidence, EvidenceKind, Severity};
    use crate::detection::verdict::Verdict;
    use crate::scanner::artifact::Artifact;
    use crate::scanner::file_type::ArtifactType;
    use crate::scanner::macho::MachOInfo;
    use crate::scanner::macho_dependencies::MachODependencies;
    use crate::scanner::path::PathType;
    use crate::scanner::result::{
        ArtifactResult, DiagnosticKind, ScanDiagnostic, ScanResult, ScanSummary,
    };

    use super::write_text;

    struct AlwaysFailWriter;

    impl Write for AlwaysFailWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("writer failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("writer failed"))
        }
    }

    #[derive(Default)]
    struct FlushFailWriter {
        bytes: Vec<u8>,
    }

    impl Write for FlushFailWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("flush failed"))
        }
    }

    fn representative_result() -> ScanResult {
        let artifact = ArtifactResult {
            artifact: Artifact::new(
                PathBuf::from("samples/suspicious.bin"),
                42,
                Some("bin".to_string()),
                "0123456789abcdef".to_string(),
                ArtifactType::MachO,
            ),
            macho: None,
            macho_dependencies: None,
            evidence: vec![Evidence::new(
                EvidenceKind::FileTypeMismatch,
                Severity::Medium,
                "extension does not match detected type".to_string(),
            )],
            verdict: Verdict::Suspicious,
            detector_statuses: Vec::new(),
            diagnostics: Vec::new(),
        };

        ScanResult {
            target: PathBuf::from("samples"),
            target_type: PathType::Directory,
            artifacts: vec![artifact],
            diagnostics: Vec::new(),
            summary: ScanSummary {
                discovered: 2,
                analyzed: 1,
                failed: 1,
                unknown: 0,
                suspicious: 1,
                malicious: 0,
            },
        }
    }

    fn rendered_text(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).expect("report output should be UTF-8")
    }

    #[test]
    fn text_report_renders_identity_evidence_verdict_and_summary() {
        let result = representative_result();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_text(&result, &mut stdout, &mut stderr).expect("report should render");

        let stdout = rendered_text(stdout);
        assert!(stdout.contains("AegisForge"));
        assert!(stdout.contains("Target: samples"));
        assert!(stdout.contains("Type: Directory"));
        assert!(stdout.contains("samples/suspicious.bin"));
        assert!(stdout.contains("42 bytes"));
        assert!(stdout.contains("extension: bin"));
        assert!(stdout.contains("type: Mach-O"));
        assert!(stdout.contains("SHA-256: 0123456789abcdef"));
        assert!(stdout.contains("Evidence [MEDIUM]: extension does not match detected type"));
        assert!(stdout.contains("Verdict: SUSPICIOUS"));
        assert!(stdout.contains(
            "Summary: 2 discovered | 1 analyzed | 1 failed | 0 unknown | 1 suspicious | 0 malicious"
        ));
        assert!(stderr.is_empty());
    }

    #[test]
    fn text_report_renders_empty_result() {
        let result = ScanResult {
            target: PathBuf::from("empty"),
            target_type: PathType::File,
            artifacts: Vec::new(),
            diagnostics: Vec::new(),
            summary: ScanSummary {
                discovered: 0,
                analyzed: 0,
                failed: 0,
                unknown: 0,
                suspicious: 0,
                malicious: 0,
            },
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_text(&result, &mut stdout, &mut stderr).expect("report should render");

        assert_eq!(
            rendered_text(stdout),
            "AegisForge\n\
             Target: empty\n\
             Type: File\n\
             Summary: 0 discovered | 0 analyzed | 0 failed | 0 unknown | 0 suspicious | 0 malicious\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn text_report_renders_macho_dependencies_and_rpaths() {
        let mut result = representative_result();
        result.artifacts[0].macho = Some(MachOInfo {
            format: "64-bit".to_string(),
            architecture: Some("arm64".to_string()),
            endianness: "little".to_string(),
        });
        result.artifacts[0].macho_dependencies = Some(MachODependencies {
            libraries: vec!["/usr/lib/libSystem.B.dylib".to_string()],
            rpaths: vec!["@loader_path/../Frameworks".to_string()],
        });
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_text(&result, &mut stdout, &mut stderr).expect("report should render");

        let stdout = rendered_text(stdout);
        assert!(stdout.contains("Mach-O: 64-bit | architecture: arm64 | endianness: little"));
        assert!(stdout.contains("  - /usr/lib/libSystem.B.dylib [SYSTEM]"));
        assert!(stdout.contains("  - @loader_path/../Frameworks [LOADER_PATH]"));
    }

    #[test]
    fn text_report_writes_diagnostics_to_stderr() {
        let mut result = representative_result();
        result.diagnostics.push(ScanDiagnostic::new(
            DiagnosticKind::Discovery,
            Some(PathBuf::from("samples/unreadable")),
            "could not traverse entry".to_string(),
        ));
        result.artifacts[0].diagnostics.push(ScanDiagnostic::new(
            DiagnosticKind::Yara,
            Some(PathBuf::from("samples/suspicious.bin")),
            "rule engine unavailable".to_string(),
        ));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_text(&result, &mut stdout, &mut stderr).expect("report should render");

        let stdout = rendered_text(stdout);
        let stderr = rendered_text(stderr);
        assert_eq!(
            stderr,
            "Warning: could not traverse entry (path: samples/unreadable)\n\
             Warning: rule engine unavailable (path: samples/suspicious.bin)\n"
        );
        assert!(!stdout.contains("could not traverse entry"));
        assert!(!stdout.contains("rule engine unavailable"));
    }

    #[test]
    fn text_report_escapes_untrusted_control_characters() {
        let controls = "\r\t\u{1b}\u{7}é";
        let mut result = representative_result();
        result.target = PathBuf::from(format!("target\nVerdict: INJECTED{controls}"));
        result.artifacts[0].artifact.path =
            PathBuf::from(format!("artifact\nSummary: INJECTED{controls}"));
        result.artifacts[0].artifact.extension = Some(format!("bin\nWarning: INJECTED{controls}"));
        result.artifacts[0].macho = Some(MachOInfo {
            format: format!("64-bit\nVerdict: INJECTED{controls}"),
            architecture: Some(format!("arm64\nSummary: INJECTED{controls}")),
            endianness: format!("little\nWarning: INJECTED{controls}"),
        });
        result.artifacts[0].macho_dependencies = Some(MachODependencies {
            libraries: vec![format!("@rpath/lib\nVerdict: INJECTED{controls}.dylib")],
            rpaths: vec![format!("@loader_path/\nSummary: INJECTED{controls}")],
        });
        result.artifacts[0].evidence[0].message = format!("evidence\nWarning: INJECTED{controls}");
        result.diagnostics.push(ScanDiagnostic::new(
            DiagnosticKind::Discovery,
            Some(PathBuf::from(format!(
                "affected\nVerdict: INJECTED{controls}"
            ))),
            format!("diagnostic\nWarning: INJECTED{controls}"),
        ));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_text(&result, &mut stdout, &mut stderr).expect("report should render");

        let stdout = rendered_text(stdout);
        let stderr = rendered_text(stderr);
        assert!(stdout.contains("target\\nVerdict: INJECTED\\r\\t\\u{001B}\\u{0007}é"));
        assert!(stdout.contains("artifact\\nSummary: INJECTED\\r\\t\\u{001B}\\u{0007}é"));
        assert!(stdout.contains("bin\\nWarning: INJECTED\\r\\t\\u{001B}\\u{0007}é"));
        assert!(stdout.contains("64-bit\\nVerdict: INJECTED\\r\\t\\u{001B}\\u{0007}é"));
        assert!(stdout.contains("arm64\\nSummary: INJECTED\\r\\t\\u{001B}\\u{0007}é"));
        assert!(stdout.contains("little\\nWarning: INJECTED\\r\\t\\u{001B}\\u{0007}é"));
        assert!(
            stdout
                .contains("@rpath/lib\\nVerdict: INJECTED\\r\\t\\u{001B}\\u{0007}é.dylib [RPATH]")
        );
        assert!(
            stdout.contains(
                "@loader_path/\\nSummary: INJECTED\\r\\t\\u{001B}\\u{0007}é [LOADER_PATH]"
            )
        );
        assert!(stdout.contains("evidence\\nWarning: INJECTED\\r\\t\\u{001B}\\u{0007}é"));
        assert!(stderr.contains("diagnostic\\nWarning: INJECTED\\r\\t\\u{001B}\\u{0007}é"));
        assert!(stderr.contains("affected\\nVerdict: INJECTED\\r\\t\\u{001B}\\u{0007}é"));
        assert_eq!(
            stdout
                .lines()
                .filter(|line| line.starts_with("Verdict:"))
                .collect::<Vec<_>>(),
            ["Verdict: SUSPICIOUS"]
        );
        assert_eq!(
            stdout
                .lines()
                .filter(|line| line.starts_with("Summary:"))
                .count(),
            1
        );
        assert_eq!(
            stdout
                .lines()
                .filter(|line| line.starts_with("Warning:"))
                .count(),
            0
        );
        assert_eq!(
            stderr
                .lines()
                .filter(|line| line.starts_with("Warning:"))
                .count(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn text_report_losslessly_escapes_non_utf8_paths_and_backslashes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let mut result = representative_result();
        result.target = PathBuf::from(OsString::from_vec(
            b"target\\literal-\xFF-\nVerdict: INJECTED".to_vec(),
        ));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_text(&result, &mut stdout, &mut stderr).expect("report should render");

        let stdout = rendered_text(stdout);
        assert!(stdout.contains("Target: target\\\\literal-\\xFF-\\nVerdict: INJECTED"));
        assert!(!stdout.contains('\u{FFFD}'));
        assert_eq!(
            stdout
                .lines()
                .filter(|line| line.starts_with("Verdict:"))
                .collect::<Vec<_>>(),
            ["Verdict: SUSPICIOUS"]
        );
    }

    #[test]
    fn text_report_escapes_line_separators_and_bidi_formatting_controls() {
        let dangerous = "\u{2028}\u{2029}\u{061C}\u{200E}\u{200F}\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\u{2066}\u{2067}\u{2068}\u{2069}";
        let escaped = "\\u{2028}\\u{2029}\\u{061C}\\u{200E}\\u{200F}\\u{202A}\\u{202B}\\u{202C}\\u{202D}\\u{202E}\\u{2066}\\u{2067}\\u{2068}\\u{2069}";
        let mut result = representative_result();
        result.target = PathBuf::from(format!("target{dangerous}Verdict: INJECTED"));
        result.artifacts[0].artifact.path =
            PathBuf::from(format!("artifact{dangerous}Summary: INJECTED"));
        result.artifacts[0].artifact.extension = Some(format!("bin{dangerous}Warning: INJECTED"));
        result.artifacts[0].macho = Some(MachOInfo {
            format: format!("64-bit{dangerous}Verdict: INJECTED"),
            architecture: Some(format!("arm64{dangerous}Summary: INJECTED")),
            endianness: format!("little{dangerous}Warning: INJECTED"),
        });
        result.artifacts[0].macho_dependencies = Some(MachODependencies {
            libraries: vec![format!("@rpath/lib{dangerous}Verdict: INJECTED.dylib")],
            rpaths: vec![format!("@loader_path/{dangerous}Summary: INJECTED")],
        });
        result.artifacts[0].evidence[0].message = format!("evidence{dangerous}Warning: INJECTED");
        result.diagnostics.push(ScanDiagnostic::new(
            DiagnosticKind::Discovery,
            Some(PathBuf::from(format!(
                "affected{dangerous}Verdict: INJECTED"
            ))),
            format!("diagnostic{dangerous}Warning: INJECTED"),
        ));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_text(&result, &mut stdout, &mut stderr).expect("report should render");

        let stdout = rendered_text(stdout);
        let stderr = rendered_text(stderr);
        assert!(stdout.contains(&format!("target{escaped}Verdict: INJECTED")));
        assert!(stdout.contains(&format!("artifact{escaped}Summary: INJECTED")));
        assert!(stdout.contains(&format!("bin{escaped}Warning: INJECTED")));
        assert!(stdout.contains(&format!("64-bit{escaped}Verdict: INJECTED")));
        assert!(stdout.contains(&format!("arm64{escaped}Summary: INJECTED")));
        assert!(stdout.contains(&format!("little{escaped}Warning: INJECTED")));
        assert!(stdout.contains(&format!(
            "@rpath/lib{escaped}Verdict: INJECTED.dylib [RPATH]"
        )));
        assert!(stdout.contains(&format!(
            "@loader_path/{escaped}Summary: INJECTED [LOADER_PATH]"
        )));
        assert!(stdout.contains(&format!("evidence{escaped}Warning: INJECTED")));
        assert!(stderr.contains(&format!("diagnostic{escaped}Warning: INJECTED")));
        assert!(stderr.contains(&format!("affected{escaped}Verdict: INJECTED")));
        assert!(!stdout.contains(dangerous));
        assert!(!stderr.contains(dangerous));
    }

    #[test]
    fn text_report_propagates_writer_failure() {
        let result = representative_result();
        let mut stdout = AlwaysFailWriter;
        let mut stderr = Vec::new();

        let error = write_text(&result, &mut stdout, &mut stderr)
            .expect_err("stdout failure should be returned");

        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn text_report_propagates_stdout_flush_failure() {
        let result = representative_result();
        let mut stdout = FlushFailWriter::default();
        let mut stderr = Vec::new();

        let error = write_text(&result, &mut stdout, &mut stderr)
            .expect_err("stdout flush failure should be returned");

        assert_eq!(error.to_string(), "flush failed");
    }

    #[test]
    fn text_report_propagates_stderr_flush_failure() {
        let result = representative_result();
        let mut stdout = Vec::new();
        let mut stderr = FlushFailWriter::default();

        let error = write_text(&result, &mut stdout, &mut stderr)
            .expect_err("stderr flush failure should be returned");

        assert_eq!(error.to_string(), "flush failed");
    }
}
