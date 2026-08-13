use std::collections::BTreeMap;

use der::{
    Decode, Reader, SliceReader, Tag, TagNumber, Tagged,
    asn1::{AnyRef, OctetStringRef, Utf8StringRef},
};

use crate::macos::codesign::NativeCheckStatus;

pub const MAX_ENTITLEMENT_BYTES: usize = 256 * 1024;
pub const MAX_ENTITLEMENT_DEPTH: usize = 32;
pub const MAX_ENTITLEMENT_NODES: usize = 4_096;
pub const MAX_ENTITLEMENT_MATERIALIZED_BYTES: usize = 256 * 1024;
const MAX_RECONCILIATION_DIAGNOSTIC_BYTES: usize = 4 * 1024;
#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_ENTITLEMENT_REPORT_BYTES: usize = 3 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementEntry {
    pub key: String,
    pub value: EntitlementValue,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyFormat {
    Xml,
    Binary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum LegacyEntitlementObservation {
    Absent,
    Valid {
        format: LegacyFormat,
        entries: Vec<EntitlementEntry>,
    },
    Invalid {
        reason: String,
    },
    Unobserved {
        reason: String,
    },
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DerEntitlementObservation {
    #[cfg_attr(not(test), allow(dead_code))]
    Parsed { entries: Vec<EntitlementEntry> },
    #[cfg_attr(not(test), allow(dead_code))]
    Absent,
    #[cfg_attr(not(test), allow(dead_code))]
    Unsigned,
    #[cfg_attr(not(test), allow(dead_code))]
    Failed { reason: String },
    #[cfg_attr(not(test), allow(dead_code))]
    Unavailable { reason: String },
    #[cfg_attr(not(test), allow(dead_code))]
    Error { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReconciledEntitlements {
    pub(crate) der_entitlements_status: NativeCheckStatus,
    pub(crate) entitlements_status: NativeCheckStatus,
    pub(crate) entitlement_source: Option<EntitlementSource>,
    pub(crate) entitlements: Vec<EntitlementEntry>,
    pub(crate) positive_signed: bool,
    pub(crate) explicit_unsigned: bool,
    pub(crate) diagnostics: Vec<String>,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn reconcile_entitlements(
    der: DerEntitlementObservation,
    legacy: LegacyEntitlementObservation,
) -> ReconciledEntitlements {
    let (der_entitlements_status, positive_signed, explicit_unsigned) = match &der {
        DerEntitlementObservation::Parsed { .. } => (NativeCheckStatus::Passed, true, false),
        DerEntitlementObservation::Absent => (NativeCheckStatus::NotApplicable, true, false),
        DerEntitlementObservation::Unsigned => (NativeCheckStatus::NotApplicable, false, true),
        DerEntitlementObservation::Failed { .. } => (NativeCheckStatus::Failed, false, false),
        DerEntitlementObservation::Unavailable { .. } => {
            (NativeCheckStatus::Unavailable, false, false)
        }
        DerEntitlementObservation::Error { .. } => (NativeCheckStatus::Error, false, false),
    };

    let mut reconciled = ReconciledEntitlements {
        der_entitlements_status,
        entitlements_status: der_entitlements_status,
        entitlement_source: None,
        entitlements: Vec::new(),
        positive_signed,
        explicit_unsigned,
        diagnostics: Vec::new(),
    };

    match &der {
        DerEntitlementObservation::Failed { reason } => push_reconciliation_diagnostic(
            &mut reconciled,
            &["DER entitlement query failed: ", reason],
        ),
        DerEntitlementObservation::Unavailable { reason } => push_reconciliation_diagnostic(
            &mut reconciled,
            &["DER entitlement query unavailable: ", reason],
        ),
        DerEntitlementObservation::Error { reason } => push_reconciliation_diagnostic(
            &mut reconciled,
            &["DER entitlement query error: ", reason],
        ),
        DerEntitlementObservation::Parsed { .. }
        | DerEntitlementObservation::Absent
        | DerEntitlementObservation::Unsigned => {}
    }

    match (der, legacy) {
        (DerEntitlementObservation::Parsed { entries }, LegacyEntitlementObservation::Absent) => {
            retain_der_entries(&mut reconciled, entries)
        }
        (
            DerEntitlementObservation::Parsed { entries },
            LegacyEntitlementObservation::Unobserved { reason },
        ) => {
            retain_der_entries(&mut reconciled, entries);
            push_reconciliation_diagnostic(
                &mut reconciled,
                &["legacy entitlement comparison was unavailable: ", &reason],
            );
        }
        (
            DerEntitlementObservation::Parsed { entries },
            LegacyEntitlementObservation::Valid {
                format: _,
                entries: legacy_entries,
            },
        ) if entries == legacy_entries => retain_der_entries(&mut reconciled, entries),
        (DerEntitlementObservation::Parsed { .. }, LegacyEntitlementObservation::Valid { .. }) => {
            reconciled.entitlements_status = NativeCheckStatus::Error;
            push_reconciliation_diagnostic(
                &mut reconciled,
                &["authoritative DER and legacy entitlement dictionaries disagree"],
            );
        }
        (DerEntitlementObservation::Absent, LegacyEntitlementObservation::Absent)
        | (DerEntitlementObservation::Unsigned, LegacyEntitlementObservation::Absent) => {}
        (
            DerEntitlementObservation::Absent,
            LegacyEntitlementObservation::Unobserved { reason },
        )
        | (
            DerEntitlementObservation::Unsigned,
            LegacyEntitlementObservation::Unobserved { reason },
        ) => push_reconciliation_diagnostic(
            &mut reconciled,
            &["legacy entitlement comparison was unavailable: ", &reason],
        ),
        (DerEntitlementObservation::Absent, LegacyEntitlementObservation::Valid { .. }) => {
            reconciled.entitlements_status = NativeCheckStatus::Error;
            push_reconciliation_diagnostic(
                &mut reconciled,
                &["authoritative DER absence conflicts with a legacy entitlement dictionary"],
            );
        }
        (DerEntitlementObservation::Unsigned, LegacyEntitlementObservation::Valid { .. }) => {
            reconciled.entitlements_status = NativeCheckStatus::Error;
            push_reconciliation_diagnostic(
                &mut reconciled,
                &[
                    "authoritative unsigned DER observation conflicts with a legacy entitlement dictionary",
                ],
            );
        }
        (
            DerEntitlementObservation::Failed { reason },
            LegacyEntitlementObservation::Valid { entries, .. },
        )
        | (
            DerEntitlementObservation::Unavailable { reason },
            LegacyEntitlementObservation::Valid { entries, .. },
        )
        | (
            DerEntitlementObservation::Error { reason },
            LegacyEntitlementObservation::Valid { entries, .. },
        ) => {
            reconciled.entitlements_status = NativeCheckStatus::Error;
            reconciled.entitlement_source =
                Some(EntitlementSource::LegacyPropertyListNonAuthoritative);
            reconciled.entitlements = entries;
            push_reconciliation_diagnostic(
                &mut reconciled,
                &[
                    "no authoritative DER entitlement observation was established (",
                    der_entitlements_status.as_str(),
                    ": ",
                    &reason,
                    "); retaining non-authoritative legacy compatibility context",
                ],
            );
        }
        (DerEntitlementObservation::Failed { .. }, LegacyEntitlementObservation::Absent)
        | (DerEntitlementObservation::Unavailable { .. }, LegacyEntitlementObservation::Absent)
        | (DerEntitlementObservation::Error { .. }, LegacyEntitlementObservation::Absent) => {}
        (
            DerEntitlementObservation::Failed { .. },
            LegacyEntitlementObservation::Unobserved { reason },
        )
        | (
            DerEntitlementObservation::Unavailable { .. },
            LegacyEntitlementObservation::Unobserved { reason },
        )
        | (
            DerEntitlementObservation::Error { .. },
            LegacyEntitlementObservation::Unobserved { reason },
        ) => push_reconciliation_diagnostic(
            &mut reconciled,
            &["legacy entitlement comparison was unavailable: ", &reason],
        ),
        (_, LegacyEntitlementObservation::Invalid { reason }) => {
            reconciled.entitlements_status = NativeCheckStatus::Error;
            reconciled.entitlement_source = None;
            reconciled.entitlements.clear();
            push_reconciliation_diagnostic(
                &mut reconciled,
                &["legacy entitlement observation is invalid: ", &reason],
            );
        }
    }

    if reconciled.der_entitlements_status != reconciled.entitlements_status {
        let der_status = reconciled.der_entitlements_status.as_str();
        let final_status = reconciled.entitlements_status.as_str();
        push_reconciliation_diagnostic(
            &mut reconciled,
            &[
                "entitlement status comparison: DER ",
                der_status,
                "; final ",
                final_status,
            ],
        );
    }
    reconciled.diagnostics.sort_unstable();
    reconciled.diagnostics.dedup();

    reconciled
}

fn retain_der_entries(reconciled: &mut ReconciledEntitlements, entries: Vec<EntitlementEntry>) {
    reconciled.entitlement_source = Some(EntitlementSource::CodesignDerOutput);
    reconciled.entitlements = entries;
}

fn push_reconciliation_diagnostic(reconciled: &mut ReconciledEntitlements, parts: &[&str]) {
    const TRUNCATED_SUFFIX: &str = "[truncated]";
    let mut diagnostic = String::with_capacity(MAX_RECONCILIATION_DIAGNOSTIC_BYTES);
    let mut truncated = false;
    for part in parts {
        let remaining = MAX_RECONCILIATION_DIAGNOSTIC_BYTES - diagnostic.len();
        if part.len() <= remaining {
            diagnostic.push_str(part);
            continue;
        }

        let mut end = remaining;
        while end > 0 && !part.is_char_boundary(end) {
            end -= 1;
        }
        diagnostic.push_str(&part[..end]);
        truncated = true;
        break;
    }
    if truncated {
        let maximum_prefix = MAX_RECONCILIATION_DIAGNOSTIC_BYTES - TRUNCATED_SUFFIX.len();
        let mut end = diagnostic.len().min(maximum_prefix);
        while end > 0 && !diagnostic.is_char_boundary(end) {
            end -= 1;
        }
        diagnostic.truncate(end);
        diagnostic.push_str(TRUNCATED_SUFFIX);
    }
    reconciled.diagnostics.push(diagnostic);
}

pub(crate) struct EntitlementBudget {
    nodes: usize,
    materialized_bytes: usize,
}

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

    pub(crate) fn remaining_materialized_bytes(&self) -> usize {
        MAX_ENTITLEMENT_MATERIALIZED_BYTES.saturating_sub(self.materialized_bytes)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum StructuredValueKind {
    Boolean,
    Integer,
    String,
    Data,
    Array,
    Dictionary,
    Unsupported,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) trait StructuredEntitlementReader {
    type Value: Copy;

    fn identity(&self, value: Self::Value) -> usize;
    fn kind(&self, value: Self::Value) -> Result<StructuredValueKind, String>;
    fn read_boolean(&self, value: Self::Value) -> Result<bool, String>;
    fn read_integer(&self, value: Self::Value) -> Result<i64, String>;
    fn read_string(&self, value: Self::Value, max_bytes: usize) -> Result<String, String>;
    fn read_data(&self, value: Self::Value, max_bytes: usize) -> Result<Vec<u8>, String>;
    fn array_len(&self, value: Self::Value) -> Result<usize, String>;
    fn array_value(&self, value: Self::Value, index: usize) -> Result<Self::Value, String>;
    fn dictionary_len(&self, value: Self::Value) -> Result<usize, String>;
    fn dictionary_entry(
        &self,
        value: Self::Value,
        index: usize,
    ) -> Result<(Self::Value, Self::Value), String>;
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn decode_structured_entitlements<R: StructuredEntitlementReader>(
    reader: &R,
    root: R::Value,
) -> Result<Vec<EntitlementEntry>, String> {
    let mut budget = EntitlementBudget::new();
    budget.enter_value(1)?;
    if reader.kind(root)? != StructuredValueKind::Dictionary {
        return Err("structured entitlement root is not a dictionary".to_string());
    }

    let mut active_containers = std::collections::BTreeSet::new();
    decode_structured_dictionary(reader, root, 1, &mut budget, &mut active_containers)
}

fn decode_structured_dictionary<R: StructuredEntitlementReader>(
    reader: &R,
    dictionary: R::Value,
    depth: usize,
    budget: &mut EntitlementBudget,
    active_containers: &mut std::collections::BTreeSet<usize>,
) -> Result<Vec<EntitlementEntry>, String> {
    let identity = reader.identity(dictionary);
    if !active_containers.insert(identity) {
        return Err("structured entitlement containers contain a cycle".to_string());
    }

    let result = (|| {
        let count = reader.dictionary_len(dictionary)?;
        let mut entries = BTreeMap::new();
        for index in 0..count {
            budget.enter_dictionary_entry()?;
            let (key_value, value) = reader.dictionary_entry(dictionary, index)?;
            if reader.kind(key_value)? != StructuredValueKind::String {
                return Err("structured entitlement dictionary key is not a string".to_string());
            }
            let key = reader.read_string(key_value, budget.remaining_materialized_bytes())?;
            budget.charge_materialized(key.len())?;

            let vacant = match entries.entry(key) {
                std::collections::btree_map::Entry::Vacant(vacant) => vacant,
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(
                        "structured entitlement dictionary contains a duplicate key".to_string()
                    );
                }
            };
            let child_depth = depth
                .checked_add(1)
                .ok_or_else(|| "structured entitlement depth counter overflowed".to_string())?;
            let decoded =
                decode_structured_value(reader, value, child_depth, budget, active_containers)?;
            vacant.insert(decoded);
        }

        Ok(entries
            .into_iter()
            .map(|(key, value)| EntitlementEntry { key, value })
            .collect())
    })();
    active_containers.remove(&identity);
    result
}

fn decode_structured_value<R: StructuredEntitlementReader>(
    reader: &R,
    value: R::Value,
    depth: usize,
    budget: &mut EntitlementBudget,
    active_containers: &mut std::collections::BTreeSet<usize>,
) -> Result<EntitlementValue, String> {
    budget.enter_value(depth)?;
    match reader.kind(value)? {
        StructuredValueKind::Boolean => {
            let decoded = reader.read_boolean(value)?;
            budget.charge_materialized(1)?;
            Ok(EntitlementValue::Boolean(decoded))
        }
        StructuredValueKind::Integer => {
            let decoded = reader.read_integer(value)?;
            budget.charge_materialized(8)?;
            Ok(EntitlementValue::SignedInteger(decoded))
        }
        StructuredValueKind::String => {
            let decoded = reader.read_string(value, budget.remaining_materialized_bytes())?;
            budget.charge_materialized(decoded.len())?;
            Ok(EntitlementValue::String(decoded))
        }
        StructuredValueKind::Data => {
            let decoded = reader.read_data(value, budget.remaining_materialized_bytes())?;
            budget.charge_materialized(decoded.len())?;
            Ok(EntitlementValue::Data(decoded))
        }
        StructuredValueKind::Array => {
            decode_structured_array(reader, value, depth, budget, active_containers)
        }
        StructuredValueKind::Dictionary => {
            decode_structured_dictionary(reader, value, depth, budget, active_containers)
                .map(EntitlementValue::Dictionary)
        }
        StructuredValueKind::Unsupported => {
            Err("structured entitlement value uses an unsupported type".to_string())
        }
    }
}

fn decode_structured_array<R: StructuredEntitlementReader>(
    reader: &R,
    array: R::Value,
    depth: usize,
    budget: &mut EntitlementBudget,
    active_containers: &mut std::collections::BTreeSet<usize>,
) -> Result<EntitlementValue, String> {
    let identity = reader.identity(array);
    if !active_containers.insert(identity) {
        return Err("structured entitlement containers contain a cycle".to_string());
    }

    let result = (|| {
        let count = reader.array_len(array)?;
        let mut values = Vec::new();
        for index in 0..count {
            let value = reader.array_value(array, index)?;
            let child_depth = depth
                .checked_add(1)
                .ok_or_else(|| "structured entitlement depth counter overflowed".to_string())?;
            values.push(decode_structured_value(
                reader,
                value,
                child_depth,
                budget,
                active_containers,
            )?);
        }
        Ok(EntitlementValue::Array(values))
    })();
    active_containers.remove(&identity);
    result
}

pub(crate) fn classify_legacy_entitlement_blob(bytes: &[u8]) -> Result<LegacyFormat, String> {
    const BLOB_HEADER_BYTES: usize = 8;
    const ENTITLEMENT_BLOB_MAGIC: [u8; 4] = [0xfa, 0xde, 0x71, 0x71];
    const UTF8_BOM: [u8; 3] = [0xef, 0xbb, 0xbf];

    if bytes.len() > MAX_ENTITLEMENT_BYTES {
        return Err(format!(
            "legacy entitlement blob exceeds {MAX_ENTITLEMENT_BYTES} bytes"
        ));
    }
    let header = bytes
        .get(..BLOB_HEADER_BYTES)
        .ok_or_else(|| "legacy entitlement blob is shorter than its header".to_string())?;
    if header[..4] != ENTITLEMENT_BLOB_MAGIC {
        return Err("legacy entitlement blob has the wrong magic".to_string());
    }
    let declared_length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let declared_length = usize::try_from(declared_length)
        .map_err(|_| "legacy entitlement blob length is not representable".to_string())?;
    if declared_length != bytes.len() {
        return Err("legacy entitlement blob length does not match its bytes".to_string());
    }

    let payload = &bytes[BLOB_HEADER_BYTES..];
    if payload.starts_with(b"bplist00") {
        return Ok(LegacyFormat::Binary);
    }

    let payload = payload.strip_prefix(&UTF8_BOM).unwrap_or(payload);
    let xml = std::str::from_utf8(payload)
        .map_err(|_| "legacy XML entitlement payload is not valid UTF-8".to_string())?;
    let xml = xml.trim_start_matches([' ', '\t', '\r', '\n']);
    if xml.starts_with("<?xml") || xml.starts_with("<plist") {
        Ok(LegacyFormat::Xml)
    } else {
        Err("legacy entitlement payload has an unsupported format".to_string())
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn decode_der_entitlements(bytes: &[u8]) -> Result<Vec<EntitlementEntry>, String> {
    if bytes.is_empty() {
        return Err("entitlement DER is empty".to_string());
    }
    if bytes.len() > MAX_ENTITLEMENT_BYTES {
        return Err(format!(
            "entitlement DER exceeds {MAX_ENTITLEMENT_BYTES} bytes"
        ));
    }

    let document =
        AnyRef::from_der(bytes).map_err(|_| "entitlement DER document is malformed".to_string())?;
    if document.tag() != TagNumber::N16.application(true) {
        return Err("entitlement DER document has the wrong application tag".to_string());
    }

    let mut document_reader = SliceReader::new(document.value())
        .map_err(|_| "entitlement DER document body is malformed".to_string())?;
    let version = document_reader
        .decode::<u8>()
        .map_err(|_| "entitlement DER schema version is malformed".to_string())?;
    if version != 1 {
        return Err("entitlement DER schema version is unsupported".to_string());
    }
    let dictionary = document_reader
        .decode::<AnyRef<'_>>()
        .map_err(|_| "entitlement DER root dictionary is missing".to_string())?;
    document_reader
        .finish(())
        .map_err(|_| "entitlement DER document has trailing members".to_string())?;

    let mut budget = EntitlementBudget::new();
    budget.enter_value(1)?;
    decode_der_dictionary(dictionary, 1, &mut budget)
}

fn decode_der_dictionary(
    dictionary: AnyRef<'_>,
    depth: usize,
    budget: &mut EntitlementBudget,
) -> Result<Vec<EntitlementEntry>, String> {
    if dictionary.tag() != TagNumber::N16.context_specific(true) {
        return Err("entitlement DER value is not a dictionary".to_string());
    }

    let mut reader = SliceReader::new(dictionary.value())
        .map_err(|_| "entitlement DER dictionary is malformed".to_string())?;
    let mut entries = BTreeMap::new();

    while !reader.is_finished() {
        budget.enter_dictionary_entry()?;
        let encoded_entry = reader
            .decode::<AnyRef<'_>>()
            .map_err(|_| "entitlement DER dictionary entry is malformed".to_string())?;
        if encoded_entry.tag() != Tag::Sequence {
            return Err("entitlement DER dictionary entry is not a sequence".to_string());
        }

        let mut entry_reader = SliceReader::new(encoded_entry.value())
            .map_err(|_| "entitlement DER dictionary entry body is malformed".to_string())?;
        let encoded_key = entry_reader
            .decode::<AnyRef<'_>>()
            .map_err(|_| "entitlement DER dictionary key is missing".to_string())?;
        let key = encoded_key
            .decode_as::<Utf8StringRef<'_>>()
            .map_err(|_| "entitlement DER dictionary key is not canonical UTF-8".to_string())?;
        budget.charge_materialized(key.as_bytes().len())?;
        let key = key.as_str().to_owned();

        let vacant = match entries.entry(key) {
            std::collections::btree_map::Entry::Vacant(vacant) => vacant,
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err("entitlement DER dictionary contains a duplicate key".to_string());
            }
        };

        let encoded_value = entry_reader
            .decode::<AnyRef<'_>>()
            .map_err(|_| "entitlement DER dictionary value is missing".to_string())?;
        let child_depth = depth
            .checked_add(1)
            .ok_or_else(|| "entitlement DER depth counter overflowed".to_string())?;
        let value = decode_der_value(encoded_value, child_depth, budget)?;
        entry_reader
            .finish(())
            .map_err(|_| "entitlement DER dictionary entry has trailing members".to_string())?;
        vacant.insert(value);
    }

    reader
        .finish(())
        .map_err(|_| "entitlement DER dictionary is not completely consumed".to_string())?;
    Ok(entries
        .into_iter()
        .map(|(key, value)| EntitlementEntry { key, value })
        .collect())
}

fn decode_der_value(
    value: AnyRef<'_>,
    depth: usize,
    budget: &mut EntitlementBudget,
) -> Result<EntitlementValue, String> {
    budget.enter_value(depth)?;

    match value.tag() {
        Tag::Boolean => {
            let decoded = value
                .decode_as::<bool>()
                .map_err(|_| "entitlement DER Boolean is not canonical".to_string())?;
            budget.charge_materialized(1)?;
            Ok(EntitlementValue::Boolean(decoded))
        }
        Tag::Integer => decode_der_integer(value, budget),
        Tag::Utf8String => {
            let decoded = value
                .decode_as::<Utf8StringRef<'_>>()
                .map_err(|_| "entitlement DER string is not canonical UTF-8".to_string())?;
            budget.charge_materialized(decoded.as_bytes().len())?;
            Ok(EntitlementValue::String(decoded.as_str().to_owned()))
        }
        Tag::OctetString => {
            let decoded = value
                .decode_as::<OctetStringRef<'_>>()
                .map_err(|_| "entitlement DER data is malformed".to_string())?;
            budget.charge_materialized(decoded.as_bytes().len())?;
            Ok(EntitlementValue::Data(decoded.as_bytes().to_vec()))
        }
        Tag::Sequence => decode_der_array(value, depth, budget),
        tag if tag == TagNumber::N16.context_specific(true) => {
            decode_der_dictionary(value, depth, budget).map(EntitlementValue::Dictionary)
        }
        _ => Err("entitlement DER value uses an unsupported tag".to_string()),
    }
}

fn decode_der_integer(
    value: AnyRef<'_>,
    budget: &mut EntitlementBudget,
) -> Result<EntitlementValue, String> {
    let first = value
        .value()
        .first()
        .ok_or_else(|| "entitlement DER integer is empty".to_string())?;

    let decoded = if first & 0x80 != 0 {
        value
            .decode_as::<i64>()
            .map(EntitlementValue::SignedInteger)
    } else if let Ok(signed) = value.decode_as::<i64>() {
        Ok(EntitlementValue::SignedInteger(signed))
    } else {
        value
            .decode_as::<u64>()
            .map(EntitlementValue::UnsignedInteger)
    }
    .map_err(|_| "entitlement DER integer is noncanonical or out of range".to_string())?;

    budget.charge_materialized(8)?;
    Ok(decoded)
}

fn decode_der_array(
    array: AnyRef<'_>,
    depth: usize,
    budget: &mut EntitlementBudget,
) -> Result<EntitlementValue, String> {
    if array.tag() != Tag::Sequence {
        return Err("entitlement DER array has the wrong tag".to_string());
    }

    let mut reader = SliceReader::new(array.value())
        .map_err(|_| "entitlement DER array is malformed".to_string())?;
    let mut values = Vec::new();
    while !reader.is_finished() {
        let encoded = reader
            .decode::<AnyRef<'_>>()
            .map_err(|_| "entitlement DER array member is malformed".to_string())?;
        let child_depth = depth
            .checked_add(1)
            .ok_or_else(|| "entitlement DER depth counter overflowed".to_string())?;
        values.push(decode_der_value(encoded, child_depth, budget)?);
    }
    reader
        .finish(())
        .map_err(|_| "entitlement DER array is not completely consumed".to_string())?;
    Ok(EntitlementValue::Array(values))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum FakeValue<'a> {
        Boolean(bool),
        Integer(i64),
        InvalidInteger,
        String(&'a str),
        Data(&'a [u8]),
        Array(&'a [FakeValue<'a>]),
        Dictionary(&'a [(FakeValue<'a>, FakeValue<'a>)]),
        Unsupported,
    }

    struct FakeStructuredReader<'a>(std::marker::PhantomData<&'a ()>);

    impl<'a> StructuredEntitlementReader for FakeStructuredReader<'a> {
        type Value = FakeValue<'a>;

        fn identity(&self, value: Self::Value) -> usize {
            match value {
                FakeValue::Array(values) => values.as_ptr() as usize,
                FakeValue::Dictionary(entries) => entries.as_ptr() as usize,
                FakeValue::String(value) => value.as_ptr() as usize,
                FakeValue::Data(value) => value.as_ptr() as usize,
                FakeValue::Boolean(value) => usize::from(value),
                FakeValue::Integer(value) => value as usize,
                FakeValue::InvalidInteger => usize::MAX - 1,
                FakeValue::Unsupported => usize::MAX,
            }
        }

        fn kind(&self, value: Self::Value) -> Result<StructuredValueKind, String> {
            Ok(match value {
                FakeValue::Boolean(_) => StructuredValueKind::Boolean,
                FakeValue::Integer(_) => StructuredValueKind::Integer,
                FakeValue::InvalidInteger => StructuredValueKind::Integer,
                FakeValue::String(_) => StructuredValueKind::String,
                FakeValue::Data(_) => StructuredValueKind::Data,
                FakeValue::Array(_) => StructuredValueKind::Array,
                FakeValue::Dictionary(_) => StructuredValueKind::Dictionary,
                FakeValue::Unsupported => StructuredValueKind::Unsupported,
            })
        }

        fn read_boolean(&self, value: Self::Value) -> Result<bool, String> {
            match value {
                FakeValue::Boolean(value) => Ok(value),
                _ => Err("not a Boolean".to_string()),
            }
        }

        fn read_integer(&self, value: Self::Value) -> Result<i64, String> {
            match value {
                FakeValue::Integer(value) => Ok(value),
                FakeValue::InvalidInteger => Err("integer conversion failed".to_string()),
                _ => Err("not an integer".to_string()),
            }
        }

        fn read_string(&self, value: Self::Value, max_bytes: usize) -> Result<String, String> {
            match value {
                FakeValue::String(value) if value.len() <= max_bytes => Ok(value.to_string()),
                FakeValue::String(_) => Err("string exceeds bound".to_string()),
                _ => Err("not a string".to_string()),
            }
        }

        fn read_data(&self, value: Self::Value, max_bytes: usize) -> Result<Vec<u8>, String> {
            match value {
                FakeValue::Data(value) if value.len() <= max_bytes => Ok(value.to_vec()),
                FakeValue::Data(_) => Err("data exceeds bound".to_string()),
                _ => Err("not data".to_string()),
            }
        }

        fn array_len(&self, value: Self::Value) -> Result<usize, String> {
            match value {
                FakeValue::Array(values) => Ok(values.len()),
                _ => Err("not an array".to_string()),
            }
        }

        fn array_value(&self, value: Self::Value, index: usize) -> Result<Self::Value, String> {
            match value {
                FakeValue::Array(values) => values
                    .get(index)
                    .copied()
                    .ok_or_else(|| "array index is out of range".to_string()),
                _ => Err("not an array".to_string()),
            }
        }

        fn dictionary_len(&self, value: Self::Value) -> Result<usize, String> {
            match value {
                FakeValue::Dictionary(entries) => Ok(entries.len()),
                _ => Err("not a dictionary".to_string()),
            }
        }

        fn dictionary_entry(
            &self,
            value: Self::Value,
            index: usize,
        ) -> Result<(Self::Value, Self::Value), String> {
            match value {
                FakeValue::Dictionary(entries) => entries
                    .get(index)
                    .copied()
                    .ok_or_else(|| "dictionary index is out of range".to_string()),
                _ => Err("not a dictionary".to_string()),
            }
        }
    }

    #[test]
    fn structured_conversion_sorts_keys_and_preserves_array_order() {
        let array = [FakeValue::Integer(2), FakeValue::Integer(1)];
        let root = [
            (FakeValue::String("z"), FakeValue::Array(&array)),
            (FakeValue::String("a"), FakeValue::Boolean(true)),
            (FakeValue::String("data"), FakeValue::Data(&[1, 2, 3])),
        ];

        assert_eq!(
            decode_structured_entitlements(
                &FakeStructuredReader(std::marker::PhantomData),
                FakeValue::Dictionary(&root)
            ),
            Ok(vec![
                EntitlementEntry {
                    key: "a".to_string(),
                    value: EntitlementValue::Boolean(true),
                },
                EntitlementEntry {
                    key: "data".to_string(),
                    value: EntitlementValue::Data(vec![1, 2, 3]),
                },
                EntitlementEntry {
                    key: "z".to_string(),
                    value: EntitlementValue::Array(vec![
                        EntitlementValue::SignedInteger(2),
                        EntitlementValue::SignedInteger(1),
                    ]),
                },
            ])
        );
    }

    #[test]
    fn structured_conversion_rejects_duplicates_unsupported_values_and_non_dictionary_root() {
        let duplicate = [
            (FakeValue::String("same"), FakeValue::Boolean(true)),
            (FakeValue::String("same"), FakeValue::Boolean(false)),
        ];
        assert!(
            decode_structured_entitlements(
                &FakeStructuredReader(std::marker::PhantomData),
                FakeValue::Dictionary(&duplicate)
            )
            .is_err()
        );

        let unsupported = [(FakeValue::String("bad"), FakeValue::Unsupported)];
        assert!(
            decode_structured_entitlements(
                &FakeStructuredReader(std::marker::PhantomData),
                FakeValue::Dictionary(&unsupported)
            )
            .is_err()
        );
        assert!(
            decode_structured_entitlements(
                &FakeStructuredReader(std::marker::PhantomData),
                FakeValue::Boolean(true)
            )
            .is_err()
        );

        let invalid_integer = [(FakeValue::String("integer"), FakeValue::InvalidInteger)];
        assert!(
            decode_structured_entitlements(
                &FakeStructuredReader(std::marker::PhantomData),
                FakeValue::Dictionary(&invalid_integer)
            )
            .is_err()
        );
    }

    enum GraphNode {
        Boolean(bool),
        String(String),
        Array(Vec<usize>),
        Dictionary(Vec<(usize, usize)>),
    }

    struct GraphStructuredReader {
        nodes: Vec<GraphNode>,
    }

    impl StructuredEntitlementReader for GraphStructuredReader {
        type Value = usize;

        fn identity(&self, value: Self::Value) -> usize {
            value
        }

        fn kind(&self, value: Self::Value) -> Result<StructuredValueKind, String> {
            self.nodes
                .get(value)
                .map(|node| match node {
                    GraphNode::Boolean(_) => StructuredValueKind::Boolean,
                    GraphNode::String(_) => StructuredValueKind::String,
                    GraphNode::Array(_) => StructuredValueKind::Array,
                    GraphNode::Dictionary(_) => StructuredValueKind::Dictionary,
                })
                .ok_or_else(|| "unknown graph node".to_string())
        }

        fn read_boolean(&self, value: Self::Value) -> Result<bool, String> {
            match self.nodes.get(value) {
                Some(GraphNode::Boolean(value)) => Ok(*value),
                _ => Err("not a Boolean".to_string()),
            }
        }

        fn read_integer(&self, _value: Self::Value) -> Result<i64, String> {
            Err("not an integer".to_string())
        }

        fn read_string(&self, value: Self::Value, max_bytes: usize) -> Result<String, String> {
            match self.nodes.get(value) {
                Some(GraphNode::String(value)) if value.len() <= max_bytes => Ok(value.clone()),
                Some(GraphNode::String(_)) => Err("string exceeds bound".to_string()),
                _ => Err("not a string".to_string()),
            }
        }

        fn read_data(&self, _value: Self::Value, _max_bytes: usize) -> Result<Vec<u8>, String> {
            Err("not data".to_string())
        }

        fn array_len(&self, value: Self::Value) -> Result<usize, String> {
            match self.nodes.get(value) {
                Some(GraphNode::Array(values)) => Ok(values.len()),
                _ => Err("not an array".to_string()),
            }
        }

        fn array_value(&self, value: Self::Value, index: usize) -> Result<Self::Value, String> {
            match self.nodes.get(value) {
                Some(GraphNode::Array(values)) => values
                    .get(index)
                    .copied()
                    .ok_or_else(|| "array index is out of range".to_string()),
                _ => Err("not an array".to_string()),
            }
        }

        fn dictionary_len(&self, value: Self::Value) -> Result<usize, String> {
            match self.nodes.get(value) {
                Some(GraphNode::Dictionary(entries)) => Ok(entries.len()),
                _ => Err("not a dictionary".to_string()),
            }
        }

        fn dictionary_entry(
            &self,
            value: Self::Value,
            index: usize,
        ) -> Result<(Self::Value, Self::Value), String> {
            match self.nodes.get(value) {
                Some(GraphNode::Dictionary(entries)) => entries
                    .get(index)
                    .copied()
                    .ok_or_else(|| "dictionary index is out of range".to_string()),
                _ => Err("not a dictionary".to_string()),
            }
        }
    }

    #[test]
    fn structured_conversion_rejects_active_cycles_and_excessive_depth() {
        let cyclic = GraphStructuredReader {
            nodes: vec![
                GraphNode::Dictionary(vec![(1, 0)]),
                GraphNode::String("cycle".to_string()),
            ],
        };
        assert!(decode_structured_entitlements(&cyclic, 0).is_err());

        let mut nodes = vec![
            GraphNode::Dictionary(vec![(1, 2)]),
            GraphNode::String("deep".to_string()),
        ];
        for index in 2..=32 {
            nodes.push(GraphNode::Array(vec![index + 1]));
        }
        nodes.push(GraphNode::Boolean(true));
        assert!(decode_structured_entitlements(&GraphStructuredReader { nodes }, 0).is_err());
    }

    #[test]
    fn structured_conversion_charges_shared_values_per_occurrence_and_caps_nodes() {
        let oversized_shared = "x".repeat(MAX_ENTITLEMENT_MATERIALIZED_BYTES / 2 + 1);
        let shared = GraphStructuredReader {
            nodes: vec![
                GraphNode::Dictionary(vec![(1, 2), (3, 2)]),
                GraphNode::String("first".to_string()),
                GraphNode::String(oversized_shared),
                GraphNode::String("second".to_string()),
            ],
        };
        assert!(decode_structured_entitlements(&shared, 0).is_err());

        let values = vec![2; MAX_ENTITLEMENT_NODES];
        let excessive_nodes = GraphStructuredReader {
            nodes: vec![
                GraphNode::Dictionary(vec![(1, 3)]),
                GraphNode::String("values".to_string()),
                GraphNode::Boolean(true),
                GraphNode::Array(values),
            ],
        };
        assert!(decode_structured_entitlements(&excessive_nodes, 0).is_err());
    }

    #[test]
    fn structured_conversion_handles_many_common_prefix_keys_in_sorted_order() {
        let mut nodes = vec![GraphNode::Dictionary(Vec::new())];
        let mut entries = Vec::new();
        for index in (0..1_500).rev() {
            let key = nodes.len();
            nodes.push(GraphNode::String(format!("common.prefix.{index:04}")));
            let value = nodes.len();
            nodes.push(GraphNode::Boolean(index % 2 == 0));
            entries.push((key, value));
        }
        nodes[0] = GraphNode::Dictionary(entries);

        let decoded = decode_structured_entitlements(&GraphStructuredReader { nodes }, 0)
            .expect("bounded common-prefix dictionary should decode");
        assert_eq!(decoded.len(), 1_500);
        assert_eq!(
            decoded.first().map(|entry| entry.key.as_str()),
            Some("common.prefix.0000")
        );
        assert_eq!(
            decoded.last().map(|entry| entry.key.as_str()),
            Some("common.prefix.1499")
        );
    }

    #[test]
    fn structured_legacy_blob_classification_is_exact() {
        let mut xml_blob = vec![0xfa, 0xde, 0x71, 0x71, 0, 0, 0, 0];
        xml_blob.extend_from_slice(b"<?xml version=\"1.0\"?><plist></plist>");
        let length = u32::try_from(xml_blob.len()).expect("fixture length fits in u32");
        xml_blob[4..8].copy_from_slice(&length.to_be_bytes());

        assert_eq!(
            classify_legacy_entitlement_blob(&xml_blob),
            Ok(LegacyFormat::Xml)
        );

        let mut binary_blob = vec![0xfa, 0xde, 0x71, 0x71, 0, 0, 0, 16];
        binary_blob.extend_from_slice(b"bplist00");
        assert_eq!(
            classify_legacy_entitlement_blob(&binary_blob),
            Ok(LegacyFormat::Binary)
        );
    }

    #[test]
    fn structured_legacy_blob_rejects_bad_framing_and_unknown_payloads() {
        for blob in [
            vec![],
            vec![0xfa, 0xde, 0x71, 0x71, 0, 0, 0],
            vec![0xfa, 0xde, 0x71, 0x72, 0, 0, 0, 8],
            vec![0xfa, 0xde, 0x71, 0x71, 0, 0, 0, 9],
            vec![0xfa, 0xde, 0x71, 0x71, 0, 0, 0, 8],
        ] {
            assert!(classify_legacy_entitlement_blob(&blob).is_err());
        }

        let unknown = legacy_blob(b"not-a-property-list");
        assert!(classify_legacy_entitlement_blob(&unknown).is_err());

        let non_utf8_xml = legacy_blob(&[0xef, 0xbb, 0xbf, b' ', 0xff, b'<', b'p']);
        assert!(classify_legacy_entitlement_blob(&non_utf8_xml).is_err());
    }

    #[test]
    fn structured_legacy_xml_accepts_one_bom_and_only_ascii_xml_whitespace() {
        assert_eq!(
            classify_legacy_entitlement_blob(&legacy_blob(
                b"\xef\xbb\xbf \t\r\n<?xml version=\"1.0\"?>"
            )),
            Ok(LegacyFormat::Xml)
        );
        assert_eq!(
            classify_legacy_entitlement_blob(&legacy_blob(b"\n<plist/>")),
            Ok(LegacyFormat::Xml)
        );
        assert!(
            classify_legacy_entitlement_blob(&legacy_blob(b"\xef\xbb\xbf\xef\xbb\xbf<plist/>"))
                .is_err()
        );
        assert!(
            classify_legacy_entitlement_blob(&legacy_blob("\u{00a0}<plist/>".as_bytes())).is_err()
        );
    }

    #[test]
    fn structured_legacy_blob_enforces_the_raw_byte_ceiling() {
        let mut exact_payload = vec![b'x'; MAX_ENTITLEMENT_BYTES - 8];
        exact_payload[..8].copy_from_slice(b"bplist00");
        let exact = legacy_blob(&exact_payload);
        assert_eq!(exact.len(), MAX_ENTITLEMENT_BYTES);
        assert_eq!(
            classify_legacy_entitlement_blob(&exact),
            Ok(LegacyFormat::Binary)
        );

        let mut over = exact;
        over.push(b'x');
        let length = u32::try_from(over.len()).expect("fixture length fits u32");
        over[4..8].copy_from_slice(&length.to_be_bytes());
        assert!(classify_legacy_entitlement_blob(&over).is_err());
    }

    fn legacy_blob(payload: &[u8]) -> Vec<u8> {
        let length = 8_usize
            .checked_add(payload.len())
            .expect("fixture length does not overflow");
        let length = u32::try_from(length).expect("fixture length fits u32");
        let mut blob = vec![0xfa, 0xde, 0x71, 0x71];
        blob.extend_from_slice(&length.to_be_bytes());
        blob.extend_from_slice(payload);
        blob
    }

    fn der_length(length: usize) -> Vec<u8> {
        if length < 128 {
            return vec![length as u8];
        }

        let bytes = length.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .expect("a long-form DER length is nonzero");
        let encoded = &bytes[first..];
        let mut result = Vec::with_capacity(encoded.len() + 1);
        result.push(0x80 | u8::try_from(encoded.len()).expect("usize width fits in u8"));
        result.extend_from_slice(encoded);
        result
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + der_length(content.len()).len() + content.len());
        result.push(tag);
        result.extend_from_slice(&der_length(content.len()));
        result.extend_from_slice(content);
        result
    }

    fn utf8(value: &str) -> Vec<u8> {
        tlv(0x0c, value.as_bytes())
    }

    fn integer(content: &[u8]) -> Vec<u8> {
        tlv(0x02, content)
    }

    fn boolean(value: bool) -> Vec<u8> {
        tlv(0x01, &[if value { 0xff } else { 0x00 }])
    }

    fn data(value: &[u8]) -> Vec<u8> {
        tlv(0x04, value)
    }

    fn array(values: Vec<Vec<u8>>) -> Vec<u8> {
        tlv(0x30, &values.concat())
    }

    fn entry(key: &str, value: Vec<u8>) -> Vec<u8> {
        let mut content = utf8(key);
        content.extend(value);
        tlv(0x30, &content)
    }

    fn raw_key_entry(key: Vec<u8>, value: Vec<u8>) -> Vec<u8> {
        let mut content = key;
        content.extend(value);
        tlv(0x30, &content)
    }

    fn dictionary(entries: Vec<Vec<u8>>) -> Vec<u8> {
        tlv(0xb0, &entries.concat())
    }

    fn document(entries: Vec<Vec<u8>>) -> Vec<u8> {
        let mut content = integer(&[1]);
        content.extend(dictionary(entries));
        tlv(0x70, &content)
    }

    fn document_with_dictionary(dictionary: Vec<u8>) -> Vec<u8> {
        let mut content = integer(&[1]);
        content.extend(dictionary);
        tlv(0x70, &content)
    }

    fn nested_dictionary_value(current_depth: usize, final_depth: usize) -> Vec<u8> {
        if current_depth == final_depth {
            boolean(true)
        } else {
            dictionary(vec![entry(
                "nested",
                nested_dictionary_value(current_depth + 1, final_depth),
            )])
        }
    }

    fn node_boundary_document(extra_array_children: usize) -> Vec<u8> {
        let mut entries = (0..2_046)
            .map(|index| entry(&format!("k{index:04}"), boolean(false)))
            .collect::<Vec<_>>();
        entries.push(entry(
            "last",
            array((0..extra_array_children).map(|_| boolean(true)).collect()),
        ));
        document(entries)
    }

    #[test]
    fn der_decodes_empty_dictionary_and_all_supported_values() {
        assert_eq!(
            decode_der_entitlements(&[0x70, 5, 2, 1, 1, 0xb0, 0]),
            Ok(vec![])
        );

        let hostile = "safe\n\t[Key] injected.example\n\t[Value]\n\t\t[Bool] true";
        let input = document(vec![
            entry("z-bool", boolean(true)),
            entry("a-false", boolean(false)),
            entry("signed", integer(&[0xff])),
            entry(
                "signed-max",
                integer(&[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            ),
            entry(
                "unsigned",
                integer(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            ),
            entry("string", utf8(hostile)),
            entry("data", data(&[0x00, 0xab, 0xff])),
            entry(
                "array",
                array(vec![utf8("first"), integer(&[2]), boolean(false)]),
            ),
            entry(
                "dictionary",
                dictionary(vec![entry("z", boolean(false)), entry("a", boolean(true))]),
            ),
        ]);

        let decoded = decode_der_entitlements(&input).expect("supported DER should decode");
        assert_eq!(
            decoded
                .iter()
                .map(|entry| entry.key.as_str())
                .collect::<Vec<_>>(),
            vec![
                "a-false",
                "array",
                "data",
                "dictionary",
                "signed",
                "signed-max",
                "string",
                "unsigned",
                "z-bool",
            ]
        );
        assert_eq!(
            decoded
                .iter()
                .find(|entry| entry.key == "signed")
                .unwrap()
                .value,
            EntitlementValue::SignedInteger(-1)
        );
        assert_eq!(
            decoded
                .iter()
                .find(|entry| entry.key == "unsigned")
                .unwrap()
                .value,
            EntitlementValue::UnsignedInteger(u64::MAX)
        );
        assert_eq!(
            decoded
                .iter()
                .find(|entry| entry.key == "string")
                .unwrap()
                .value,
            EntitlementValue::String(hostile.to_string())
        );
        assert_eq!(
            decoded
                .iter()
                .find(|entry| entry.key == "dictionary")
                .unwrap()
                .value,
            EntitlementValue::Dictionary(vec![
                EntitlementEntry {
                    key: "a".to_string(),
                    value: EntitlementValue::Boolean(true),
                },
                EntitlementEntry {
                    key: "z".to_string(),
                    value: EntitlementValue::Boolean(false),
                },
            ])
        );
    }

    #[test]
    fn der_decodes_six_initial_security_keys_as_data_only() {
        let keys = [
            "com.apple.security.get-task-allow",
            "com.apple.security.cs.disable-library-validation",
            "com.apple.security.cs.allow-jit",
            "com.apple.security.cs.allow-unsigned-executable-memory",
            "com.apple.security.cs.allow-dyld-environment-variables",
            "com.apple.security.app-sandbox",
        ];
        let input = document(
            keys.iter()
                .rev()
                .map(|key| entry(key, boolean(true)))
                .collect(),
        );

        let decoded = decode_der_entitlements(&input).expect("security keys are ordinary keys");
        let mut expected = keys.to_vec();
        expected.sort_unstable();
        assert_eq!(
            decoded
                .iter()
                .map(|entry| entry.key.as_str())
                .collect::<Vec<_>>(),
            expected
        );
        assert!(
            decoded
                .iter()
                .all(|entry| entry.value == EntitlementValue::Boolean(true))
        );
    }

    #[test]
    fn der_rejects_wrong_schema_tags_versions_and_members() {
        let empty = document(vec![]);
        let mut primitive_application = empty.clone();
        primitive_application[0] = 0x50;
        let mut wrong_application_number = empty.clone();
        wrong_application_number[0] = 0x71;
        let mut high_tag_application = empty.clone();
        high_tag_application[0] = 0x7f;
        let mut top_level_trailing = empty.clone();
        top_level_trailing.push(0);

        let primitive_dictionary = document_with_dictionary(tlv(0x90, &[]));
        let wrong_dictionary_number = document_with_dictionary(tlv(0xb1, &[]));
        let primitive_entry = document_with_dictionary(dictionary(vec![tlv(
            0x10,
            &[utf8("key"), boolean(true)].concat(),
        )]));
        let wrong_version = tlv(0x70, &[integer(&[2]), dictionary(vec![])].concat());
        let missing_version = tlv(0x70, &dictionary(vec![]));
        let missing_dictionary = tlv(0x70, &integer(&[1]));
        let extra_outer_member = tlv(
            0x70,
            &[integer(&[1]), dictionary(vec![]), boolean(false)].concat(),
        );
        let non_dictionary_root = tlv(0x70, &[integer(&[1]), array(vec![])].concat());

        for invalid in [
            primitive_application,
            wrong_application_number,
            high_tag_application,
            top_level_trailing,
            primitive_dictionary,
            wrong_dictionary_number,
            primitive_entry,
            wrong_version,
            missing_version,
            missing_dictionary,
            extra_outer_member,
            non_dictionary_root,
        ] {
            assert!(decode_der_entitlements(&invalid).is_err());
        }
    }

    #[test]
    fn der_rejects_noncanonical_and_incomplete_lengths() {
        let empty = document(vec![]);
        let mut overlong_outer = vec![0x70, 0x81, 0x05];
        overlong_outer.extend_from_slice(&empty[2..]);
        let indefinite_outer = vec![0x70, 0x80, 0x02, 0x01, 0x01, 0xb0, 0x00, 0x00, 0x00];
        let truncated_outer = empty[..empty.len() - 1].to_vec();

        let overlong_nested = tlv(0x70, &[integer(&[1]), vec![0xb0, 0x81, 0x00]].concat());
        let indefinite_nested = tlv(
            0x70,
            &[integer(&[1]), vec![0xb0, 0x80, 0x00, 0x00]].concat(),
        );

        for invalid in [
            overlong_outer,
            indefinite_outer,
            truncated_outer,
            overlong_nested,
            indefinite_nested,
        ] {
            assert!(decode_der_entitlements(&invalid).is_err());
        }
    }

    #[test]
    fn der_rejects_malformed_entries_and_trailing_container_members() {
        let missing_key = document_with_dictionary(dictionary(vec![tlv(0x30, &boolean(true))]));
        let missing_value = document_with_dictionary(dictionary(vec![tlv(0x30, &utf8("key"))]));
        let extra_value = document_with_dictionary(dictionary(vec![tlv(
            0x30,
            &[utf8("key"), boolean(true), boolean(false)].concat(),
        )]));
        let wrong_entry_tag = document_with_dictionary(dictionary(vec![tlv(
            0x31,
            &[utf8("key"), boolean(true)].concat(),
        )]));
        let array_with_bad_trailing_value = document(vec![entry(
            "array",
            tlv(0x30, &[boolean(true), tlv(0x05, &[])].concat()),
        )]);

        for invalid in [
            missing_key,
            missing_value,
            extra_value,
            wrong_entry_tag,
            array_with_bad_trailing_value,
        ] {
            assert!(decode_der_entitlements(&invalid).is_err());
        }
    }

    #[test]
    fn der_boolean_decoding_is_typed_and_canonical() {
        let decoded = decode_der_entitlements(&document(vec![
            entry("false", boolean(false)),
            entry("true", boolean(true)),
        ]))
        .expect("canonical booleans should decode");
        assert_eq!(decoded[0].value, EntitlementValue::Boolean(false));
        assert_eq!(decoded[1].value, EntitlementValue::Boolean(true));

        for invalid_boolean in [tlv(0x01, &[0x01]), tlv(0x01, &[]), tlv(0x01, &[0, 0])] {
            assert!(
                decode_der_entitlements(&document(vec![entry("bad", invalid_boolean)])).is_err()
            );
        }
    }

    #[test]
    fn der_integer_decoding_normalizes_and_enforces_combined_bounds() {
        let cases = [
            (
                vec![0x80, 0, 0, 0, 0, 0, 0, 0],
                EntitlementValue::SignedInteger(i64::MIN),
            ),
            (vec![0xff], EntitlementValue::SignedInteger(-1)),
            (vec![0], EntitlementValue::SignedInteger(0)),
            (
                vec![0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                EntitlementValue::SignedInteger(i64::MAX),
            ),
            (
                vec![0, 0x80, 0, 0, 0, 0, 0, 0, 0],
                EntitlementValue::UnsignedInteger(i64::MAX as u64 + 1),
            ),
            (
                vec![0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                EntitlementValue::UnsignedInteger(u64::MAX),
            ),
        ];

        for (encoded, expected) in cases {
            let decoded =
                decode_der_entitlements(&document(vec![entry("integer", integer(&encoded))]))
                    .expect("canonical in-range integer should decode");
            assert_eq!(decoded[0].value, expected);
        }

        for invalid in [
            vec![],
            vec![0x00, 0x01],
            vec![0xff, 0xff],
            vec![0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            vec![0x01, 0, 0, 0, 0, 0, 0, 0, 0],
        ] {
            assert!(
                decode_der_entitlements(&document(vec![entry("integer", integer(&invalid))]))
                    .is_err()
            );
        }
    }

    #[test]
    fn der_rejects_invalid_utf8_constructed_scalars_and_unknown_tags() {
        let invalid_key = document_with_dictionary(dictionary(vec![raw_key_entry(
            tlv(0x0c, &[0xff]),
            boolean(true),
        )]));
        let invalid_string = document(vec![entry("value", tlv(0x0c, &[0xff]))]);
        let constructed_octets = document(vec![entry("value", tlv(0x24, &data(&[1])))]);
        let null = document(vec![entry("value", tlv(0x05, &[]))]);
        let set = document(vec![entry("value", tlv(0x31, &[]))]);

        for invalid in [invalid_key, invalid_string, constructed_octets, null, set] {
            assert!(decode_der_entitlements(&invalid).is_err());
        }
    }

    #[test]
    fn der_rejects_duplicate_keys_at_every_dictionary_depth() {
        let root_duplicate = document(vec![
            entry("same", boolean(true)),
            entry("same", boolean(false)),
        ]);
        let nested_duplicate = document(vec![entry(
            "nested",
            dictionary(vec![
                entry("same", boolean(true)),
                entry("same", boolean(false)),
            ]),
        )]);

        assert!(decode_der_entitlements(&root_duplicate).is_err());
        assert!(decode_der_entitlements(&nested_duplicate).is_err());
    }

    #[test]
    fn der_sorts_common_prefix_keys_and_preserves_array_order() {
        let mut keys = (0..512)
            .rev()
            .map(|index| format!("common-prefix-{index:04}"))
            .collect::<Vec<_>>();
        let mut entries = keys
            .iter()
            .map(|key| entry(key, boolean(true)))
            .collect::<Vec<_>>();
        entries.push(entry(
            "array",
            array(vec![utf8("third"), utf8("first"), utf8("second")]),
        ));

        let decoded =
            decode_der_entitlements(&document(entries)).expect("bounded keys should decode");
        keys.push("array".to_string());
        keys.sort();
        assert_eq!(
            decoded
                .iter()
                .map(|entry| entry.key.clone())
                .collect::<Vec<_>>(),
            keys
        );
        let array = decoded.iter().find(|entry| entry.key == "array").unwrap();
        assert_eq!(
            array.value,
            EntitlementValue::Array(vec![
                EntitlementValue::String("third".to_string()),
                EntitlementValue::String("first".to_string()),
                EntitlementValue::String("second".to_string()),
            ])
        );
    }

    #[test]
    fn der_enforces_empty_raw_input_and_exact_raw_byte_limit() {
        assert!(decode_der_entitlements(&[]).is_err());

        let scalar_len = MAX_ENTITLEMENT_BYTES - 28;
        let exact = document(vec![entry("pad", utf8(&"x".repeat(scalar_len)))]);
        assert_eq!(exact.len(), MAX_ENTITLEMENT_BYTES);
        assert!(decode_der_entitlements(&exact).is_ok());

        let too_large = document(vec![entry("pad", utf8(&"x".repeat(scalar_len + 1)))]);
        assert_eq!(too_large.len(), MAX_ENTITLEMENT_BYTES + 1);
        assert!(decode_der_entitlements(&too_large).is_err());
    }

    #[test]
    fn der_enforces_depth_limit_with_root_at_depth_one() {
        let exact = document(vec![entry(
            "root",
            nested_dictionary_value(2, MAX_ENTITLEMENT_DEPTH),
        )]);
        let too_deep = document(vec![entry(
            "root",
            nested_dictionary_value(2, MAX_ENTITLEMENT_DEPTH + 1),
        )]);

        assert!(decode_der_entitlements(&exact).is_ok());
        assert!(decode_der_entitlements(&too_deep).is_err());
    }

    #[test]
    fn der_enforces_exact_logical_node_limit() {
        let exact = node_boundary_document(1);
        let too_many = node_boundary_document(2);

        assert!(exact.len() < MAX_ENTITLEMENT_BYTES);
        assert!(decode_der_entitlements(&exact).is_ok());
        assert!(decode_der_entitlements(&too_many).is_err());
    }

    #[test]
    fn der_dictionary_enforces_exact_cumulative_materialized_limit() {
        let encoded = dictionary(vec![entry("k", utf8("x"))]);
        let dictionary =
            der::asn1::AnyRef::from_der(&encoded).expect("test dictionary should be valid DER");

        let mut exact = EntitlementBudget::new();
        exact.enter_value(1).expect("root node should fit");
        exact
            .charge_materialized(MAX_ENTITLEMENT_MATERIALIZED_BYTES - 2)
            .expect("precharge should fit");
        assert!(decode_der_dictionary(dictionary, 1, &mut exact).is_ok());
        assert_eq!(exact.materialized_bytes, MAX_ENTITLEMENT_MATERIALIZED_BYTES);

        let mut one_too_many = EntitlementBudget::new();
        one_too_many.enter_value(1).expect("root node should fit");
        one_too_many
            .charge_materialized(MAX_ENTITLEMENT_MATERIALIZED_BYTES - 1)
            .expect("precharge should fit");
        assert!(decode_der_dictionary(dictionary, 1, &mut one_too_many).is_err());
        assert_eq!(
            one_too_many.materialized_bytes, MAX_ENTITLEMENT_MATERIALIZED_BYTES,
            "the rejected scalar must not advance the budget past its cap"
        );
    }

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

    fn reconciliation_entries(key: &str) -> Vec<EntitlementEntry> {
        vec![EntitlementEntry {
            key: key.to_string(),
            value: EntitlementValue::Boolean(true),
        }]
    }

    #[test]
    fn reconcile_entitlements_covers_the_complete_status_matrix() {
        use crate::macos::codesign::NativeCheckStatus;

        #[derive(Debug)]
        struct Case {
            name: &'static str,
            der: DerEntitlementObservation,
            legacy: LegacyEntitlementObservation,
            expected_der_status: NativeCheckStatus,
            expected_final_status: NativeCheckStatus,
            expected_source: Option<EntitlementSource>,
            expected_entries: Vec<EntitlementEntry>,
            expected_positive_signed: bool,
            expected_explicit_unsigned: bool,
        }

        let authoritative = reconciliation_entries("authoritative");
        let different = reconciliation_entries("different");
        let compatibility = reconciliation_entries("compatibility");
        let cases = vec![
            Case {
                name: "selector unavailable leaves DER unobserved",
                der: DerEntitlementObservation::Error {
                    reason: "selector unavailable".to_string(),
                },
                legacy: LegacyEntitlementObservation::Unobserved {
                    reason: "selected dictionary unavailable".to_string(),
                },
                expected_der_status: NativeCheckStatus::Error,
                expected_final_status: NativeCheckStatus::Error,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: false,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "parsed DER with absent legacy",
                der: DerEntitlementObservation::Parsed {
                    entries: authoritative.clone(),
                },
                legacy: LegacyEntitlementObservation::Absent,
                expected_der_status: NativeCheckStatus::Passed,
                expected_final_status: NativeCheckStatus::Passed,
                expected_source: Some(EntitlementSource::CodesignDerOutput),
                expected_entries: authoritative.clone(),
                expected_positive_signed: true,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "parsed DER with unobserved legacy",
                der: DerEntitlementObservation::Parsed {
                    entries: authoritative.clone(),
                },
                legacy: LegacyEntitlementObservation::Unobserved {
                    reason: "full dictionary unavailable".to_string(),
                },
                expected_der_status: NativeCheckStatus::Passed,
                expected_final_status: NativeCheckStatus::Passed,
                expected_source: Some(EntitlementSource::CodesignDerOutput),
                expected_entries: authoritative.clone(),
                expected_positive_signed: true,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "parsed DER with equal legacy",
                der: DerEntitlementObservation::Parsed {
                    entries: authoritative.clone(),
                },
                legacy: LegacyEntitlementObservation::Valid {
                    format: LegacyFormat::Xml,
                    entries: authoritative.clone(),
                },
                expected_der_status: NativeCheckStatus::Passed,
                expected_final_status: NativeCheckStatus::Passed,
                expected_source: Some(EntitlementSource::CodesignDerOutput),
                expected_entries: authoritative.clone(),
                expected_positive_signed: true,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "parsed DER with different legacy",
                der: DerEntitlementObservation::Parsed {
                    entries: authoritative.clone(),
                },
                legacy: LegacyEntitlementObservation::Valid {
                    format: LegacyFormat::Binary,
                    entries: different.clone(),
                },
                expected_der_status: NativeCheckStatus::Passed,
                expected_final_status: NativeCheckStatus::Error,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: true,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "parsed DER with invalid legacy",
                der: DerEntitlementObservation::Parsed {
                    entries: authoritative.clone(),
                },
                legacy: LegacyEntitlementObservation::Invalid {
                    reason: "legacy blob is malformed".to_string(),
                },
                expected_der_status: NativeCheckStatus::Passed,
                expected_final_status: NativeCheckStatus::Error,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: true,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "zero-byte absence with absent legacy",
                der: DerEntitlementObservation::Absent,
                legacy: LegacyEntitlementObservation::Absent,
                expected_der_status: NativeCheckStatus::NotApplicable,
                expected_final_status: NativeCheckStatus::NotApplicable,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: true,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "zero-byte absence with unobserved legacy",
                der: DerEntitlementObservation::Absent,
                legacy: LegacyEntitlementObservation::Unobserved {
                    reason: "legacy dictionary unobserved".to_string(),
                },
                expected_der_status: NativeCheckStatus::NotApplicable,
                expected_final_status: NativeCheckStatus::NotApplicable,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: true,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "zero-byte absence with valid legacy",
                der: DerEntitlementObservation::Absent,
                legacy: LegacyEntitlementObservation::Valid {
                    format: LegacyFormat::Xml,
                    entries: compatibility.clone(),
                },
                expected_der_status: NativeCheckStatus::NotApplicable,
                expected_final_status: NativeCheckStatus::Error,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: true,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "zero-byte absence with invalid legacy",
                der: DerEntitlementObservation::Absent,
                legacy: LegacyEntitlementObservation::Invalid {
                    reason: "legacy pair incomplete".to_string(),
                },
                expected_der_status: NativeCheckStatus::NotApplicable,
                expected_final_status: NativeCheckStatus::Error,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: true,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "exact unsigned with absent legacy",
                der: DerEntitlementObservation::Unsigned,
                legacy: LegacyEntitlementObservation::Absent,
                expected_der_status: NativeCheckStatus::NotApplicable,
                expected_final_status: NativeCheckStatus::NotApplicable,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: false,
                expected_explicit_unsigned: true,
            },
            Case {
                name: "exact unsigned with unobserved legacy",
                der: DerEntitlementObservation::Unsigned,
                legacy: LegacyEntitlementObservation::Unobserved {
                    reason: "legacy dictionary unobserved".to_string(),
                },
                expected_der_status: NativeCheckStatus::NotApplicable,
                expected_final_status: NativeCheckStatus::NotApplicable,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: false,
                expected_explicit_unsigned: true,
            },
            Case {
                name: "exact unsigned with valid legacy",
                der: DerEntitlementObservation::Unsigned,
                legacy: LegacyEntitlementObservation::Valid {
                    format: LegacyFormat::Binary,
                    entries: compatibility.clone(),
                },
                expected_der_status: NativeCheckStatus::NotApplicable,
                expected_final_status: NativeCheckStatus::Error,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: false,
                expected_explicit_unsigned: true,
            },
            Case {
                name: "exact unsigned with invalid legacy",
                der: DerEntitlementObservation::Unsigned,
                legacy: LegacyEntitlementObservation::Invalid {
                    reason: "legacy value type unsupported".to_string(),
                },
                expected_der_status: NativeCheckStatus::NotApplicable,
                expected_final_status: NativeCheckStatus::Error,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: false,
                expected_explicit_unsigned: true,
            },
            Case {
                name: "command rejection with absent legacy",
                der: DerEntitlementObservation::Failed {
                    reason: "codesign rejected the request".to_string(),
                },
                legacy: LegacyEntitlementObservation::Absent,
                expected_der_status: NativeCheckStatus::Failed,
                expected_final_status: NativeCheckStatus::Failed,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: false,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "command rejection with unobserved legacy",
                der: DerEntitlementObservation::Failed {
                    reason: "codesign rejected the request".to_string(),
                },
                legacy: LegacyEntitlementObservation::Unobserved {
                    reason: "legacy dictionary unobserved".to_string(),
                },
                expected_der_status: NativeCheckStatus::Failed,
                expected_final_status: NativeCheckStatus::Failed,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: false,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "command rejection with valid legacy compatibility context",
                der: DerEntitlementObservation::Failed {
                    reason: "codesign rejected the request".to_string(),
                },
                legacy: LegacyEntitlementObservation::Valid {
                    format: LegacyFormat::Xml,
                    entries: compatibility.clone(),
                },
                expected_der_status: NativeCheckStatus::Failed,
                expected_final_status: NativeCheckStatus::Error,
                expected_source: Some(EntitlementSource::LegacyPropertyListNonAuthoritative),
                expected_entries: compatibility.clone(),
                expected_positive_signed: false,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "command rejection with invalid legacy",
                der: DerEntitlementObservation::Failed {
                    reason: "codesign rejected the request".to_string(),
                },
                legacy: LegacyEntitlementObservation::Invalid {
                    reason: "legacy blob is malformed".to_string(),
                },
                expected_der_status: NativeCheckStatus::Failed,
                expected_final_status: NativeCheckStatus::Error,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: false,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "runner unavailable with absent legacy",
                der: DerEntitlementObservation::Unavailable {
                    reason: "codesign is unavailable".to_string(),
                },
                legacy: LegacyEntitlementObservation::Absent,
                expected_der_status: NativeCheckStatus::Unavailable,
                expected_final_status: NativeCheckStatus::Unavailable,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: false,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "runner unavailable with unobserved legacy",
                der: DerEntitlementObservation::Unavailable {
                    reason: "codesign is unavailable".to_string(),
                },
                legacy: LegacyEntitlementObservation::Unobserved {
                    reason: "legacy dictionary unobserved".to_string(),
                },
                expected_der_status: NativeCheckStatus::Unavailable,
                expected_final_status: NativeCheckStatus::Unavailable,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: false,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "runner unavailable with valid legacy compatibility context",
                der: DerEntitlementObservation::Unavailable {
                    reason: "codesign is unavailable".to_string(),
                },
                legacy: LegacyEntitlementObservation::Valid {
                    format: LegacyFormat::Binary,
                    entries: compatibility.clone(),
                },
                expected_der_status: NativeCheckStatus::Unavailable,
                expected_final_status: NativeCheckStatus::Error,
                expected_source: Some(EntitlementSource::LegacyPropertyListNonAuthoritative),
                expected_entries: compatibility.clone(),
                expected_positive_signed: false,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "runner unavailable with invalid legacy",
                der: DerEntitlementObservation::Unavailable {
                    reason: "codesign is unavailable".to_string(),
                },
                legacy: LegacyEntitlementObservation::Invalid {
                    reason: "legacy blob is malformed".to_string(),
                },
                expected_der_status: NativeCheckStatus::Unavailable,
                expected_final_status: NativeCheckStatus::Error,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: false,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "runner or parser error with absent legacy",
                der: DerEntitlementObservation::Error {
                    reason: "DER output is malformed".to_string(),
                },
                legacy: LegacyEntitlementObservation::Absent,
                expected_der_status: NativeCheckStatus::Error,
                expected_final_status: NativeCheckStatus::Error,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: false,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "runner or parser error with unobserved legacy",
                der: DerEntitlementObservation::Error {
                    reason: "DER stderr framing is invalid".to_string(),
                },
                legacy: LegacyEntitlementObservation::Unobserved {
                    reason: "legacy dictionary unobserved".to_string(),
                },
                expected_der_status: NativeCheckStatus::Error,
                expected_final_status: NativeCheckStatus::Error,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: false,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "runner or parser error with valid legacy compatibility context",
                der: DerEntitlementObservation::Error {
                    reason: "DER output exceeds its bound".to_string(),
                },
                legacy: LegacyEntitlementObservation::Valid {
                    format: LegacyFormat::Xml,
                    entries: compatibility.clone(),
                },
                expected_der_status: NativeCheckStatus::Error,
                expected_final_status: NativeCheckStatus::Error,
                expected_source: Some(EntitlementSource::LegacyPropertyListNonAuthoritative),
                expected_entries: compatibility.clone(),
                expected_positive_signed: false,
                expected_explicit_unsigned: false,
            },
            Case {
                name: "runner or parser error with invalid legacy",
                der: DerEntitlementObservation::Error {
                    reason: "DER output is malformed".to_string(),
                },
                legacy: LegacyEntitlementObservation::Invalid {
                    reason: "legacy blob is malformed".to_string(),
                },
                expected_der_status: NativeCheckStatus::Error,
                expected_final_status: NativeCheckStatus::Error,
                expected_source: None,
                expected_entries: vec![],
                expected_positive_signed: false,
                expected_explicit_unsigned: false,
            },
        ];

        for case in cases {
            let reconciled = reconcile_entitlements(case.der, case.legacy);
            assert_eq!(
                reconciled.der_entitlements_status, case.expected_der_status,
                "{}: DER status must remain independently truthful",
                case.name
            );
            assert_eq!(
                reconciled.entitlements_status, case.expected_final_status,
                "{}: final status",
                case.name
            );
            assert_eq!(
                reconciled.entitlement_source, case.expected_source,
                "{}: source",
                case.name
            );
            assert_eq!(
                reconciled.entitlements, case.expected_entries,
                "{}: facts",
                case.name
            );
            assert_eq!(
                reconciled.positive_signed, case.expected_positive_signed,
                "{}: accepted signed observation",
                case.name
            );
            assert_eq!(
                reconciled.explicit_unsigned, case.expected_explicit_unsigned,
                "{}: explicit unsigned observation",
                case.name
            );
            if case.expected_der_status != case.expected_final_status {
                let expected_comparison = format!(
                    "DER {}; final {}",
                    case.expected_der_status.as_str(),
                    case.expected_final_status.as_str()
                );
                assert!(
                    reconciled
                        .diagnostics
                        .iter()
                        .any(|diagnostic| diagnostic.contains(&expected_comparison)),
                    "{}: differing DER/final statuses require a comparison diagnostic",
                    case.name
                );
            }
        }
    }

    #[test]
    fn reconcile_entitlements_distinguishes_an_empty_dictionary_from_absence() {
        use crate::macos::codesign::NativeCheckStatus;

        let parsed = reconcile_entitlements(
            DerEntitlementObservation::Parsed { entries: vec![] },
            LegacyEntitlementObservation::Absent,
        );
        let absent = reconcile_entitlements(
            DerEntitlementObservation::Absent,
            LegacyEntitlementObservation::Absent,
        );

        assert_eq!(parsed.der_entitlements_status, NativeCheckStatus::Passed);
        assert_eq!(parsed.entitlements_status, NativeCheckStatus::Passed);
        assert_eq!(
            parsed.entitlement_source,
            Some(EntitlementSource::CodesignDerOutput)
        );
        assert!(parsed.entitlements.is_empty());
        assert!(parsed.positive_signed);
        assert!(!parsed.explicit_unsigned);

        assert_eq!(
            absent.der_entitlements_status,
            NativeCheckStatus::NotApplicable
        );
        assert_eq!(absent.entitlements_status, NativeCheckStatus::NotApplicable);
        assert_eq!(absent.entitlement_source, None);
        assert!(absent.entitlements.is_empty());
        assert!(absent.positive_signed);
        assert!(!absent.explicit_unsigned);
    }

    #[test]
    fn reconcile_entitlements_preserves_the_unsigned_observation_on_legacy_conflict() {
        use crate::macos::codesign::NativeCheckStatus;

        let reconciled = reconcile_entitlements(
            DerEntitlementObservation::Unsigned,
            LegacyEntitlementObservation::Valid {
                format: LegacyFormat::Xml,
                entries: reconciliation_entries("legacy-only"),
            },
        );

        assert_eq!(
            reconciled.der_entitlements_status,
            NativeCheckStatus::NotApplicable
        );
        assert_eq!(reconciled.entitlements_status, NativeCheckStatus::Error);
        assert!(reconciled.explicit_unsigned);
        assert!(!reconciled.positive_signed);
        assert_eq!(reconciled.entitlement_source, None);
        assert!(reconciled.entitlements.is_empty());
    }

    #[test]
    fn reconcile_entitlements_bounds_utf8_diagnostics_and_sorts_them_deterministically() {
        const DIAGNOSTIC_LIMIT: usize = 4 * 1024;

        let oversized = "🛡".repeat(DIAGNOSTIC_LIMIT);
        let cases = [
            reconcile_entitlements(
                DerEntitlementObservation::Error {
                    reason: oversized.clone(),
                },
                LegacyEntitlementObservation::Valid {
                    format: LegacyFormat::Xml,
                    entries: reconciliation_entries("legacy"),
                },
            ),
            reconcile_entitlements(
                DerEntitlementObservation::Parsed {
                    entries: reconciliation_entries("der"),
                },
                LegacyEntitlementObservation::Invalid {
                    reason: oversized.clone(),
                },
            ),
            reconcile_entitlements(
                DerEntitlementObservation::Parsed {
                    entries: reconciliation_entries("der"),
                },
                LegacyEntitlementObservation::Unobserved { reason: oversized },
            ),
        ];

        for reconciled in cases {
            assert!(!reconciled.diagnostics.is_empty());
            assert!(
                reconciled
                    .diagnostics
                    .iter()
                    .all(|diagnostic| diagnostic.len() <= DIAGNOSTIC_LIMIT),
                "every reconciliation diagnostic must obey the byte cap"
            );
            assert!(
                reconciled
                    .diagnostics
                    .windows(2)
                    .all(|pair| pair[0] < pair[1]),
                "diagnostics must be sorted and deduplicated"
            );
        }
    }

    #[test]
    fn reconcile_entitlements_retains_empty_legacy_compatibility_context_with_a_source() {
        use crate::macos::codesign::NativeCheckStatus;

        let reconciled = reconcile_entitlements(
            DerEntitlementObservation::Unavailable {
                reason: "codesign unavailable".to_string(),
            },
            LegacyEntitlementObservation::Valid {
                format: LegacyFormat::Binary,
                entries: vec![],
            },
        );

        assert_eq!(
            reconciled.der_entitlements_status,
            NativeCheckStatus::Unavailable
        );
        assert_eq!(reconciled.entitlements_status, NativeCheckStatus::Error);
        assert_eq!(
            reconciled.entitlement_source,
            Some(EntitlementSource::LegacyPropertyListNonAuthoritative)
        );
        assert!(reconciled.entitlements.is_empty());
    }

    #[test]
    fn reconcile_entitlements_preserves_every_der_failure_reason() {
        let observations = [
            DerEntitlementObservation::Failed {
                reason: "bounded native rejection".to_string(),
            },
            DerEntitlementObservation::Unavailable {
                reason: "codesign missing".to_string(),
            },
            DerEntitlementObservation::Error {
                reason: "runner timed out".to_string(),
            },
        ];

        for observation in observations {
            let expected_reason = match &observation {
                DerEntitlementObservation::Failed { reason }
                | DerEntitlementObservation::Unavailable { reason }
                | DerEntitlementObservation::Error { reason } => reason.clone(),
                _ => unreachable!("fixture contains only DER failures"),
            };
            let reconciled =
                reconcile_entitlements(observation, LegacyEntitlementObservation::Absent);
            assert!(
                reconciled
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.contains(&expected_reason)),
                "DER failure reason must survive reconciliation: {expected_reason}"
            );
        }
    }

    #[test]
    fn reconcile_entitlements_marks_truncated_diagnostics_explicitly() {
        let reconciled = reconcile_entitlements(
            DerEntitlementObservation::Error {
                reason: "🙂".repeat(MAX_RECONCILIATION_DIAGNOSTIC_BYTES),
            },
            LegacyEntitlementObservation::Absent,
        );

        let diagnostic = reconciled
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.contains("DER entitlement query"))
            .expect("DER error must produce a diagnostic");
        assert!(diagnostic.len() <= MAX_RECONCILIATION_DIAGNOSTIC_BYTES);
        assert!(diagnostic.ends_with("[truncated]"));
        assert!(diagnostic.is_char_boundary(diagnostic.len()));
    }
}
