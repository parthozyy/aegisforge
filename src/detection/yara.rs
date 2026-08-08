use std::fs;
use std::path::Path;

use yara_x::{Compiler, Rules, Scanner};

pub struct YaraEngine {
    rules: Rules,
}

impl YaraEngine {
    pub fn from_source(source: &str) -> Result<Self, String> {
        let mut compiler = Compiler::new();

        compiler.enable_includes(false);

        compiler
            .add_source(source)
            .map_err(|error| format!("Failed to compile YARA rules: {error}"))?;

        let rules = compiler.build();

        Ok(Self { rules })
    }

    pub fn from_directory(directory: &Path) -> Result<Self, String> {
        let mut compiler = Compiler::new();

        compiler.enable_includes(false);

        let entries = fs::read_dir(directory).map_err(|error| {
            format!(
                "Failed to read YARA rules directory {}: {}",
                directory.display(),
                error
            )
        })?;

        let mut rules_loaded = 0;

        for entry in entries {
            let entry =
                entry.map_err(|error| format!("Failed to read YARA rule entry: {error}"))?;

            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            let extension = path.extension().and_then(|extension| extension.to_str());

            if extension != Some("yar") && extension != Some("yara") {
                continue;
            }

            let source = fs::read_to_string(&path).map_err(|error| {
                format!("Failed to read YARA rule {}: {}", path.display(), error)
            })?;

            compiler.add_source(source.as_str()).map_err(|error| {
                format!("Failed to compile YARA rule {}: {}", path.display(), error)
            })?;

            rules_loaded += 1;
        }

        if rules_loaded == 0 {
            return Err(format!("No YARA rules found in {}", directory.display()));
        }

        let rules = compiler.build();

        Ok(Self { rules })
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<String>, String> {
        let mut scanner = Scanner::new(&self.rules);

        let results = scanner
            .scan(data)
            .map_err(|error| format!("YARA scan failed: {error}"))?;

        let matches = results
            .matching_rules()
            .map(|rule| rule.identifier().to_string())
            .collect();

        Ok(matches)
    }

    pub fn scan_file(&self, path: &Path) -> Result<Vec<String>, String> {
        let data = fs::read(path).map_err(|error| {
            format!(
                "Failed to read {} for YARA scanning: {}",
                path.display(),
                error
            )
        })?;

        self.scan_bytes(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RULE: &str = r#"
        rule aegisforge_test_marker {
            strings:
                $marker = "AEGISFORGE_TEST_SIGNATURE"

            condition:
                $marker
        }
    "#;

    #[test]
    fn yara_detects_matching_data() {
        let engine = YaraEngine::from_source(TEST_RULE).expect("YARA rule should compile");

        let data = b"This file contains AEGISFORGE_TEST_SIGNATURE inside it.";

        let matches = engine.scan_bytes(data).expect("YARA scan should succeed");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], "aegisforge_test_marker");
    }

    #[test]
    fn yara_does_not_match_unrelated_data() {
        let engine = YaraEngine::from_source(TEST_RULE).expect("YARA rule should compile");

        let data = b"This is an ordinary harmless test string.";

        let matches = engine.scan_bytes(data).expect("YARA scan should succeed");

        assert!(matches.is_empty());
    }
}
