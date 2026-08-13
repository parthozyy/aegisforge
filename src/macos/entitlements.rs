use std::collections::BTreeMap;

use der::{
    Decode, Reader, SliceReader, Tag, TagNumber, Tagged,
    asn1::{AnyRef, OctetStringRef, Utf8StringRef},
};

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
}
