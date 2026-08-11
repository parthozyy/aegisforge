#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_ENTITLEMENT_BYTES: usize = 256 * 1024;
pub const MAX_ENTITLEMENT_DEPTH: usize = 32;
pub const MAX_ENTITLEMENT_NODES: usize = 4_096;
pub const MAX_ENTITLEMENT_MATERIALIZED_BYTES: usize = 256 * 1024;
#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_ENTITLEMENT_REPORT_BYTES: usize = 3 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementEntry {
    pub key: String,
    pub value: EntitlementValue,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntitlementValue {
    Boolean(bool),
    SignedInteger(i64),
    UnsignedInteger(u64),
    String(String),
    Data(Vec<u8>),
    Array(Vec<EntitlementValue>),
    Dictionary(Vec<EntitlementEntry>),
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntitlementSource {
    CodesignDerOutput,
    LegacyPropertyListNonAuthoritative,
}

#[cfg_attr(not(test), allow(dead_code))]
impl EntitlementSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CodesignDerOutput => "CODESIGN_DER_OUTPUT",
            Self::LegacyPropertyListNonAuthoritative => "LEGACY_PROPERTY_LIST_NON_AUTHORITATIVE",
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct EntitlementBudget {
    nodes: usize,
    materialized_bytes: usize,
}

#[cfg_attr(not(test), allow(dead_code))]
impl EntitlementBudget {
    pub(crate) fn new() -> Self {
        Self {
            nodes: 0,
            materialized_bytes: 0,
        }
    }

    pub(crate) fn enter_value(&mut self, depth: usize) -> Result<(), String> {
        if depth == 0 || depth > MAX_ENTITLEMENT_DEPTH {
            return Err(format!(
                "entitlement depth {depth} exceeds the allowed range 1..={MAX_ENTITLEMENT_DEPTH}"
            ));
        }

        self.enter_node()
    }

    pub(crate) fn enter_dictionary_entry(&mut self) -> Result<(), String> {
        self.enter_node()
    }

    pub(crate) fn charge_materialized(&mut self, bytes: usize) -> Result<(), String> {
        let materialized_bytes = self
            .materialized_bytes
            .checked_add(bytes)
            .ok_or_else(|| "entitlement materialized-byte counter overflowed".to_string())?;
        if materialized_bytes > MAX_ENTITLEMENT_MATERIALIZED_BYTES {
            return Err(format!(
                "entitlement materialized bytes exceed {MAX_ENTITLEMENT_MATERIALIZED_BYTES}"
            ));
        }

        self.materialized_bytes = materialized_bytes;
        Ok(())
    }

    fn enter_node(&mut self) -> Result<(), String> {
        let nodes = self
            .nodes
            .checked_add(1)
            .ok_or_else(|| "entitlement node counter overflowed".to_string())?;
        if nodes > MAX_ENTITLEMENT_NODES {
            return Err(format!(
                "entitlement node count exceeds {MAX_ENTITLEMENT_NODES}"
            ));
        }

        self.nodes = nodes;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entitlement_limits_are_exact() {
        assert_eq!(MAX_ENTITLEMENT_BYTES, 256 * 1024);
        assert_eq!(MAX_ENTITLEMENT_DEPTH, 32);
        assert_eq!(MAX_ENTITLEMENT_NODES, 4_096);
        assert_eq!(MAX_ENTITLEMENT_MATERIALIZED_BYTES, 256 * 1024);
        assert_eq!(MAX_ENTITLEMENT_REPORT_BYTES, 3 * 1024 * 1024);
    }

    #[test]
    fn entitlement_source_has_stable_labels_and_is_copy() {
        let source = EntitlementSource::CodesignDerOutput;
        let copied = source;

        assert_eq!(source, copied);
        assert_eq!(source.as_str(), "CODESIGN_DER_OUTPUT");
        assert_eq!(
            EntitlementSource::LegacyPropertyListNonAuthoritative.as_str(),
            "LEGACY_PROPERTY_LIST_NON_AUTHORITATIVE"
        );
    }

    #[test]
    fn entitlement_model_preserves_structure_and_array_order() {
        let entries = vec![EntitlementEntry {
            key: "example".to_string(),
            value: EntitlementValue::Dictionary(vec![
                EntitlementEntry {
                    key: "array".to_string(),
                    value: EntitlementValue::Array(vec![
                        EntitlementValue::Boolean(true),
                        EntitlementValue::SignedInteger(-1),
                        EntitlementValue::UnsignedInteger(u64::MAX),
                    ]),
                },
                EntitlementEntry {
                    key: "scalars".to_string(),
                    value: EntitlementValue::Array(vec![
                        EntitlementValue::String("value".to_string()),
                        EntitlementValue::Data(vec![0, 1, 2]),
                    ]),
                },
            ]),
        }];

        assert_eq!(entries, entries.clone());
        assert_ne!(
            EntitlementValue::Array(vec![
                EntitlementValue::Boolean(true),
                EntitlementValue::Boolean(false),
            ]),
            EntitlementValue::Array(vec![
                EntitlementValue::Boolean(false),
                EntitlementValue::Boolean(true),
            ])
        );
    }

    #[test]
    fn budget_counts_root_values_and_dictionary_entries_as_nodes() {
        let mut budget = EntitlementBudget::new();

        budget.enter_value(1).expect("root value should fit");
        budget
            .enter_dictionary_entry()
            .expect("dictionary entry should fit");

        assert_eq!(budget.nodes, 2);
        assert_eq!(budget.materialized_bytes, 0);
    }

    #[test]
    fn budget_depth_exact_limit_passes_and_one_more_fails() {
        let mut budget = EntitlementBudget::new();

        budget
            .enter_value(MAX_ENTITLEMENT_DEPTH)
            .expect("exact depth limit should pass");
        assert!(budget.enter_value(MAX_ENTITLEMENT_DEPTH + 1).is_err());
        assert_eq!(budget.nodes, 1, "rejected depth must not consume a node");
    }

    #[test]
    fn budget_rejects_depth_zero() {
        let mut budget = EntitlementBudget::new();

        assert!(budget.enter_value(0).is_err());
        assert_eq!(budget.nodes, 0);
    }

    #[test]
    fn value_node_budget_exact_limit_passes_and_one_more_fails() {
        let mut budget = EntitlementBudget::new();

        for _ in 0..MAX_ENTITLEMENT_NODES {
            budget.enter_value(1).expect("node should fit");
        }

        assert_eq!(budget.nodes, MAX_ENTITLEMENT_NODES);
        assert!(budget.enter_value(1).is_err());
        assert_eq!(budget.nodes, MAX_ENTITLEMENT_NODES);
    }

    #[test]
    fn dictionary_entry_node_budget_exact_limit_passes_and_one_more_fails() {
        let mut budget = EntitlementBudget::new();

        for _ in 0..MAX_ENTITLEMENT_NODES {
            budget
                .enter_dictionary_entry()
                .expect("dictionary-entry node should fit");
        }

        assert_eq!(budget.nodes, MAX_ENTITLEMENT_NODES);
        assert!(budget.enter_dictionary_entry().is_err());
        assert_eq!(budget.nodes, MAX_ENTITLEMENT_NODES);
    }

    #[test]
    fn materialized_budget_exact_limit_passes_and_one_more_fails() {
        let mut budget = EntitlementBudget::new();

        budget
            .charge_materialized(MAX_ENTITLEMENT_MATERIALIZED_BYTES)
            .expect("exact materialized-byte limit should pass");

        assert_eq!(
            budget.materialized_bytes,
            MAX_ENTITLEMENT_MATERIALIZED_BYTES
        );
        assert!(budget.charge_materialized(1).is_err());
        assert_eq!(
            budget.materialized_bytes,
            MAX_ENTITLEMENT_MATERIALIZED_BYTES
        );
    }

    #[test]
    fn budget_accepts_future_scalar_materialized_costs() {
        let mut budget = EntitlementBudget::new();

        budget
            .charge_materialized(1)
            .expect("a boolean's byte should fit");
        budget
            .charge_materialized(8)
            .expect("an integer's bytes should fit");

        assert_eq!(budget.materialized_bytes, 9);
    }

    #[test]
    fn node_counter_overflow_is_rejected_without_mutation() {
        let mut value_budget = EntitlementBudget {
            nodes: usize::MAX,
            materialized_bytes: 0,
        };
        let mut entry_budget = EntitlementBudget {
            nodes: usize::MAX,
            materialized_bytes: 0,
        };

        assert!(value_budget.enter_value(1).is_err());
        assert!(entry_budget.enter_dictionary_entry().is_err());
        assert_eq!(value_budget.nodes, usize::MAX);
        assert_eq!(entry_budget.nodes, usize::MAX);
    }

    #[test]
    fn materialized_counter_overflow_is_rejected_without_mutation() {
        let mut budget = EntitlementBudget {
            nodes: 0,
            materialized_bytes: usize::MAX,
        };

        assert!(budget.charge_materialized(1).is_err());
        assert_eq!(budget.materialized_bytes, usize::MAX);
    }
}
