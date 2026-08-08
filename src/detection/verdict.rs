use super::evidence::{Evidence, Severity};

#[derive(Debug)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
    Unknown,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Clean => "CLEAN",
            Verdict::Suspicious => "SUSPICIOUS",
            Verdict::Malicious => "MALICIOUS",
            Verdict::Unknown => "UNKNOWN",
        }
    }
}

pub fn determine_verdict(evidence: &[Evidence]) -> Verdict {
    if evidence.is_empty() {
        return Verdict::Clean;
    }

    let mut has_medium = false;
    let mut has_high = false;
    let mut has_critical = false;

    for finding in evidence {
        match finding.severity {
            Severity::Low => {}
            Severity::Medium => {
                has_medium = true;
            }
            Severity::High => {
                has_high = true;
            }
            Severity::Critical => {
                has_critical = true;
            }
        }
    }

    if has_critical || has_high {
        return Verdict::Malicious;
    }

    if has_medium {
        return Verdict::Suspicious;
    }

    Verdict::Unknown
}
