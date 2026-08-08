use super::evidence::{Evidence, EvidenceKind, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        return Verdict::Unknown;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence_with_severity(severity: Severity) -> Evidence {
        Evidence::new(
            EvidenceKind::FileTypeMismatch,
            severity,
            "test evidence".to_string(),
        )
    }

    #[test]
    fn no_evidence_returns_unknown() {
        let evidence = Vec::new();

        let verdict = determine_verdict(&evidence);

        assert_eq!(verdict, Verdict::Unknown);
    }

    #[test]
    fn low_evidence_returns_unknown() {
        let evidence = vec![evidence_with_severity(Severity::Low)];

        let verdict = determine_verdict(&evidence);

        assert_eq!(verdict, Verdict::Unknown);
    }

    #[test]
    fn medium_evidence_returns_suspicious() {
        let evidence = vec![evidence_with_severity(Severity::Medium)];

        let verdict = determine_verdict(&evidence);

        assert_eq!(verdict, Verdict::Suspicious);
    }

    #[test]
    fn high_evidence_returns_malicious() {
        let evidence = vec![evidence_with_severity(Severity::High)];

        let verdict = determine_verdict(&evidence);

        assert_eq!(verdict, Verdict::Malicious);
    }

    #[test]
    fn critical_evidence_returns_malicious() {
        let evidence = vec![evidence_with_severity(Severity::Critical)];

        let verdict = determine_verdict(&evidence);

        assert_eq!(verdict, Verdict::Malicious);
    }

    #[test]
    fn highest_severity_controls_verdict() {
        let evidence = vec![
            evidence_with_severity(Severity::Low),
            evidence_with_severity(Severity::Medium),
            evidence_with_severity(Severity::High),
        ];

        let verdict = determine_verdict(&evidence);

        assert_eq!(verdict, Verdict::Malicious);
    }
}
