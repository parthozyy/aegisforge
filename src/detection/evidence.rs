#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    /// Reserved for future detectors that can establish critical-confidence evidence.
    #[allow(dead_code)]
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    FileTypeMismatch,
    YaraRuleMatch,
    RiskyRpath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub severity: Severity,
    pub message: String,
}

impl Evidence {
    pub fn new(kind: EvidenceKind, severity: Severity, message: String) -> Self {
        Self {
            kind,
            severity,
            message,
        }
    }
}
