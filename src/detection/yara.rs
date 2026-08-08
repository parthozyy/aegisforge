use yara_x::{Compiler, Rules, Scanner};

pub struct YaraEngine {
    rules: Rules,
}

impl YaraEngine {
    pub fn from_source(source: &str) -> Result<Self, String> {
        let mut compiler = Compiler::new();

        // We do not need rule includes yet.
        compiler.enable_includes(false);

        compiler
            .add_source(source)
            .map_err(|error| format!("Failed to compile YARA rules: {error}"))?;

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
