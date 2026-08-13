use std::path::{Path, PathBuf};

use crate::macos::codesign::{CodeSignatureArchitecture, CodeSignatureTargetKind};
use crate::macos::entitlements::LegacyEntitlementObservation;

pub(crate) const K_SEC_CS_DEFAULT_FLAGS: u32 = 0;
pub(crate) const K_SEC_CS_BASIC_VALIDATE_ONLY: u32 = 6;
pub(crate) const K_SEC_CS_NO_NETWORK_ACCESS: u32 = 1 << 29;
pub(crate) const CHECK_FLAGS: u32 = K_SEC_CS_BASIC_VALIDATE_ONLY | K_SEC_CS_NO_NETWORK_ACCESS;
pub(crate) const K_SEC_CS_SIGNING_INFORMATION: u32 = 2;
pub(crate) const K_SEC_CODE_SIGNATURE_ADHOC: u32 = 0x0002;
pub(crate) const K_SEC_CODE_SIGNATURE_RUNTIME: u32 = 0x10000;
pub(crate) const ERR_SEC_CS_UNSIGNED: i32 = -67062;
const MAX_SECURITY_DETAIL_BYTES: usize = 4 * 1024;

pub(crate) const ARTIFACT_REJECTION_STATUSES: &[i32] = &[
    -67061, -67059, -67058, -67052, -67051, -67050, -67049, -67045, -67030, -67029, -67028, -67010,
    -67005, -67004, -67003, -67001, -67000, -66999, -66998, -66997, -66996, -66995, -66994, -66993,
    -66992,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecurityStatusClass {
    Success,
    Unsigned,
    ArtifactRejected,
    OperationalError,
}

pub(crate) fn classify_security_status(status: i32) -> SecurityStatusClass {
    if status == 0 {
        SecurityStatusClass::Success
    } else if status == ERR_SEC_CS_UNSIGNED {
        SecurityStatusClass::Unsigned
    } else if ARTIFACT_REJECTION_STATUSES.contains(&status) {
        SecurityStatusClass::ArtifactRejected
    } else {
        SecurityStatusClass::OperationalError
    }
}

fn bounded_detail(detail: &str) -> String {
    if detail.len() <= MAX_SECURITY_DETAIL_BYTES {
        return detail.to_owned();
    }

    const SUFFIX: &str = "[truncated]";
    let mut end = MAX_SECURITY_DETAIL_BYTES.saturating_sub(SUFFIX.len());
    while !detail.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let mut bounded = String::with_capacity(end + SUFFIX.len());
    bounded.push_str(&detail[..end]);
    bounded.push_str(SUFFIX);
    bounded
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecurityMetadata {
    pub(crate) identifier: String,
    pub(crate) team_identifier: Option<String>,
    pub(crate) authorities: Vec<String>,
    pub(crate) ad_hoc: bool,
    pub(crate) hardened_runtime: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SecurityMetadataObservation {
    Passed(SecurityMetadata),
    Failed { reason: String },
    NotApplicable,
    Unavailable { reason: String },
    Error { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PreliminarySecurityObservation {
    Resolved(PathBuf),
    Unavailable { reason: String },
    Error { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SelectedCodeStatus {
    Signed,
    Unsigned,
    Failed { status: i32, reason: String },
    Unavailable { reason: String },
    Error { status: Option<i32>, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelectedSecurityObservation {
    pub(crate) status: SelectedCodeStatus,
    pub(crate) metadata: SecurityMetadataObservation,
    pub(crate) legacy_entitlements: LegacyEntitlementObservation,
}

impl SelectedSecurityObservation {
    fn unavailable(reason: String) -> Self {
        Self {
            status: SelectedCodeStatus::Unavailable {
                reason: reason.clone(),
            },
            metadata: SecurityMetadataObservation::Unavailable {
                reason: reason.clone(),
            },
            legacy_entitlements: LegacyEntitlementObservation::Unobserved { reason },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SelectedSecurityRequest<'a> {
    pub(crate) path: &'a Path,
    pub(crate) architecture: &'a CodeSignatureArchitecture,
    pub(crate) target_kind: CodeSignatureTargetKind,
}

pub(crate) trait SecurityInfoProvider {
    fn resolve_bundle_main(&self, bundle: &Path) -> PreliminarySecurityObservation;

    fn inspect_selected(
        &self,
        request: &SelectedSecurityRequest<'_>,
        bind_main: &mut dyn FnMut(&Path) -> Result<(), String>,
    ) -> SelectedSecurityObservation;
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct UnavailableSecurityInfoProvider;

impl SecurityInfoProvider for UnavailableSecurityInfoProvider {
    fn resolve_bundle_main(&self, _bundle: &Path) -> PreliminarySecurityObservation {
        PreliminarySecurityObservation::Unavailable {
            reason: "Security.framework signing information is available only on macOS".to_string(),
        }
    }

    fn inspect_selected(
        &self,
        _request: &SelectedSecurityRequest<'_>,
        _bind_main: &mut dyn FnMut(&Path) -> Result<(), String>,
    ) -> SelectedSecurityObservation {
        SelectedSecurityObservation::unavailable(
            "Security.framework signing information is available only on macOS".to_string(),
        )
    }
}

#[cfg(target_os = "macos")]
mod native {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::ffi::{OsString, c_void};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};
    use std::ptr::{self, NonNull};

    use core_foundation_sys::array::{CFArrayGetCount, CFArrayGetTypeID, CFArrayGetValueAtIndex};
    use core_foundation_sys::base::{
        CFGetTypeID, CFIndex, CFRelease, CFTypeID, CFTypeRef, OSStatus,
    };
    use core_foundation_sys::data::{CFDataGetBytePtr, CFDataGetLength, CFDataGetTypeID};
    use core_foundation_sys::dictionary::{
        CFDictionaryCreate, CFDictionaryGetCount, CFDictionaryGetKeysAndValues,
        CFDictionaryGetTypeID, CFDictionaryGetValueIfPresent, CFDictionaryRef,
        kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks,
    };
    use core_foundation_sys::number::{
        CFBooleanGetTypeID, CFBooleanGetValue, CFNumberCreate, CFNumberGetTypeID, CFNumberGetValue,
        CFNumberIsFloatType, kCFNumberSInt32Type, kCFNumberSInt64Type,
    };
    use core_foundation_sys::string::{
        CFStringGetBytes, CFStringGetLength, CFStringGetTypeID, CFStringRef, kCFStringEncodingUTF8,
    };
    use core_foundation_sys::url::{
        CFURLCreateFromFileSystemRepresentation, CFURLGetFileSystemRepresentation, CFURLGetTypeID,
        CFURLRef,
    };

    use super::*;
    use crate::macos::entitlements::{
        LegacyEntitlementObservation, MAX_ENTITLEMENT_BYTES, MAX_ENTITLEMENT_NODES,
        StructuredEntitlementReader, StructuredValueKind, classify_legacy_entitlement_blob,
        decode_structured_entitlements,
    };

    pub(crate) const MAX_METADATA_BYTES: usize = 64 * 1024;
    pub(crate) const MAX_CERTIFICATES: usize = 64;
    pub(crate) const MAX_MAIN_PATH_BYTES: usize = 16 * 1024;

    #[repr(C)]
    pub(crate) struct __SecCode(c_void);
    #[repr(C)]
    pub(crate) struct __SecRequirement(c_void);
    #[repr(C)]
    pub(crate) struct __SecCertificate(c_void);

    pub(crate) type SecStaticCodeRef = *const __SecCode;
    pub(crate) type SecRequirementRef = *mut __SecRequirement;
    pub(crate) type SecCertificateRef = *mut __SecCertificate;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        pub(crate) fn SecStaticCodeCreateWithPath(
            path: CFURLRef,
            flags: u32,
            static_code: *mut SecStaticCodeRef,
        ) -> OSStatus;
        pub(crate) fn SecStaticCodeCreateWithPathAndAttributes(
            path: CFURLRef,
            flags: u32,
            attributes: CFDictionaryRef,
            static_code: *mut SecStaticCodeRef,
        ) -> OSStatus;
        pub(crate) fn SecStaticCodeCheckValidity(
            static_code: SecStaticCodeRef,
            flags: u32,
            requirement: SecRequirementRef,
        ) -> OSStatus;
        pub(crate) fn SecCodeCopySigningInformation(
            code: SecStaticCodeRef,
            flags: u32,
            information: *mut CFDictionaryRef,
        ) -> OSStatus;
        pub(crate) fn SecStaticCodeGetTypeID() -> CFTypeID;
        pub(crate) fn SecCertificateGetTypeID() -> CFTypeID;
        pub(crate) fn SecCertificateCopySubjectSummary(
            certificate: SecCertificateRef,
        ) -> CFStringRef;

        pub(crate) static kSecCodeAttributeArchitecture: CFStringRef;
        pub(crate) static kSecCodeAttributeSubarchitecture: CFStringRef;
        pub(crate) static kSecCodeInfoIdentifier: CFStringRef;
        pub(crate) static kSecCodeInfoTeamIdentifier: CFStringRef;
        pub(crate) static kSecCodeInfoCertificates: CFStringRef;
        pub(crate) static kSecCodeInfoFlags: CFStringRef;
        pub(crate) static kSecCodeInfoMainExecutable: CFStringRef;
        pub(crate) static kSecCodeInfoEntitlements: CFStringRef;
        pub(crate) static kSecCodeInfoEntitlementsDict: CFStringRef;
    }

    pub(crate) trait SecurityApi {
        fn create_with_path(
            &self,
            path: CFURLRef,
            flags: u32,
            output: *mut SecStaticCodeRef,
        ) -> OSStatus;
        fn create_with_path_and_attributes(
            &self,
            path: CFURLRef,
            flags: u32,
            attributes: CFDictionaryRef,
            output: *mut SecStaticCodeRef,
        ) -> OSStatus;
        fn check_validity(
            &self,
            code: SecStaticCodeRef,
            flags: u32,
            requirement: SecRequirementRef,
        ) -> OSStatus;
        fn copy_signing_information(
            &self,
            code: SecStaticCodeRef,
            flags: u32,
            output: *mut CFDictionaryRef,
        ) -> OSStatus;
        fn static_code_type_id(&self) -> CFTypeID;
        fn certificate_type_id(&self) -> CFTypeID;
        fn copy_certificate_subject_summary(&self, certificate: SecCertificateRef) -> CFStringRef;
        fn release(&self, value: CFTypeRef);
    }

    #[derive(Debug, Clone, Copy, Default)]
    struct SystemSecurityApi;

    impl SecurityApi for SystemSecurityApi {
        fn create_with_path(
            &self,
            path: CFURLRef,
            flags: u32,
            output: *mut SecStaticCodeRef,
        ) -> OSStatus {
            // SAFETY: The caller supplies a live CFURL and a writable, initialized out pointer.
            unsafe { SecStaticCodeCreateWithPath(path, flags, output) }
        }

        fn create_with_path_and_attributes(
            &self,
            path: CFURLRef,
            flags: u32,
            attributes: CFDictionaryRef,
            output: *mut SecStaticCodeRef,
        ) -> OSStatus {
            // SAFETY: The caller supplies live CF inputs and a writable, initialized out pointer.
            unsafe { SecStaticCodeCreateWithPathAndAttributes(path, flags, attributes, output) }
        }

        fn check_validity(
            &self,
            code: SecStaticCodeRef,
            flags: u32,
            requirement: SecRequirementRef,
        ) -> OSStatus {
            // SAFETY: The caller supplies a live SecStaticCode and an allowed nullable requirement.
            unsafe { SecStaticCodeCheckValidity(code, flags, requirement) }
        }

        fn copy_signing_information(
            &self,
            code: SecStaticCodeRef,
            flags: u32,
            output: *mut CFDictionaryRef,
        ) -> OSStatus {
            // SAFETY: The caller supplies a live code and a writable, initialized out pointer.
            unsafe { SecCodeCopySigningInformation(code, flags, output) }
        }

        fn static_code_type_id(&self) -> CFTypeID {
            // SAFETY: This public function has no preconditions.
            unsafe { SecStaticCodeGetTypeID() }
        }

        fn certificate_type_id(&self) -> CFTypeID {
            // SAFETY: This public function has no preconditions.
            unsafe { SecCertificateGetTypeID() }
        }

        fn copy_certificate_subject_summary(&self, certificate: SecCertificateRef) -> CFStringRef {
            // SAFETY: The caller checks the exact certificate type and keeps it alive.
            unsafe { SecCertificateCopySubjectSummary(certificate) }
        }

        fn release(&self, value: CFTypeRef) {
            // SAFETY: The caller passes one live create/copy-rule reference exactly once.
            unsafe { CFRelease(value) };
        }
    }

    struct RetainedCf<'a> {
        pointer: NonNull<c_void>,
        api: &'a dyn SecurityApi,
    }

    impl<'a> RetainedCf<'a> {
        fn from_created<T>(
            api: &'a dyn SecurityApi,
            pointer: *const T,
            what: &str,
        ) -> Result<Self, String> {
            NonNull::new(pointer.cast_mut().cast::<c_void>())
                .map(|pointer| Self { pointer, api })
                .ok_or_else(|| format!("{what} returned a null retained reference"))
        }

        fn as_type(&self) -> CFTypeRef {
            self.pointer.as_ptr().cast_const()
        }

        fn cast<T>(&self) -> *const T {
            self.pointer.as_ptr().cast_const().cast()
        }
    }

    impl Drop for RetainedCf<'_> {
        fn drop(&mut self) {
            self.api.release(self.as_type());
        }
    }

    pub(crate) fn cf_string_to_rust(
        value: CFStringRef,
        max_bytes: usize,
    ) -> Result<String, String> {
        require_type(value.cast(), cf_string_type_id(), "CFString")?;
        // SAFETY: value was checked non-null and has the exact CFString type.
        let character_count = unsafe { CFStringGetLength(value) };
        let character_count = nonnegative_index(character_count, "CFString character count")?;
        let range = core_foundation_sys::base::CFRange {
            location: 0,
            length: CFIndex::try_from(character_count)
                .map_err(|_| "CFString character count is not representable".to_string())?,
        };
        let mut required = 0;
        // SAFETY: The range spans the checked string and a null buffer requests its exact UTF-8 size.
        let converted = unsafe {
            CFStringGetBytes(
                value,
                range,
                kCFStringEncodingUTF8,
                0,
                0,
                ptr::null_mut(),
                0,
                &mut required,
            )
        };
        if converted != range.length {
            return Err("CFString could not be completely converted to UTF-8".to_string());
        }
        let required = nonnegative_index(required, "CFString UTF-8 byte count")?;
        if required > max_bytes {
            return Err(format!(
                "CFString exceeds the {max_bytes}-byte conversion bound"
            ));
        }
        let mut bytes = vec![0_u8; required];
        let mut used = 0;
        // SAFETY: bytes has the exact checked capacity and the input/range remain valid.
        let converted = unsafe {
            CFStringGetBytes(
                value,
                range,
                kCFStringEncodingUTF8,
                0,
                0,
                bytes.as_mut_ptr(),
                CFIndex::try_from(bytes.len())
                    .map_err(|_| "CFString output length is not representable".to_string())?,
                &mut used,
            )
        };
        let used = nonnegative_index(used, "CFString converted byte count")?;
        if converted != range.length || used != bytes.len() {
            return Err("CFString UTF-8 conversion was incomplete".to_string());
        }
        String::from_utf8(bytes).map_err(|_| "CFString produced invalid UTF-8".to_string())
    }

    pub(crate) fn cf_url_to_path(value: CFURLRef) -> Result<PathBuf, String> {
        require_type(value.cast(), cf_url_type_id(), "CFURL")?;
        let mut buffer = [0_u8; MAX_MAIN_PATH_BYTES + 1];
        // SAFETY: value is an exact CFURL and buffer is writable for its declared length.
        let success = unsafe {
            CFURLGetFileSystemRepresentation(
                value,
                1,
                buffer.as_mut_ptr(),
                CFIndex::try_from(buffer.len()).expect("fixed path buffer fits CFIndex"),
            )
        };
        if success == 0 {
            return Err(format!(
                "main-executable URL exceeds {MAX_MAIN_PATH_BYTES} filesystem bytes or is not representable"
            ));
        }
        let terminator = buffer
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| "main-executable URL representation was not terminated".to_string())?;
        validate_main_path_bytes(&buffer[..terminator])
    }

    pub(crate) fn validate_main_path_bytes(bytes: &[u8]) -> Result<PathBuf, String> {
        if bytes.is_empty() {
            return Err("main-executable path is empty".to_string());
        }
        if bytes[0] != b'/' {
            return Err("main-executable path is not absolute".to_string());
        }
        if bytes.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return Err("main-executable path contains CR or LF".to_string());
        }
        Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
    }

    fn nonnegative_index(value: CFIndex, what: &str) -> Result<usize, String> {
        usize::try_from(value).map_err(|_| format!("{what} is negative or not representable"))
    }

    fn cf_array_type_id() -> CFTypeID {
        // SAFETY: This public CoreFoundation type-ID function has no preconditions.
        unsafe { CFArrayGetTypeID() }
    }

    fn cf_boolean_type_id() -> CFTypeID {
        // SAFETY: This public CoreFoundation type-ID function has no preconditions.
        unsafe { CFBooleanGetTypeID() }
    }

    fn cf_data_type_id() -> CFTypeID {
        // SAFETY: This public CoreFoundation type-ID function has no preconditions.
        unsafe { CFDataGetTypeID() }
    }

    fn cf_dictionary_type_id() -> CFTypeID {
        // SAFETY: This public CoreFoundation type-ID function has no preconditions.
        unsafe { CFDictionaryGetTypeID() }
    }

    fn cf_number_type_id() -> CFTypeID {
        // SAFETY: This public CoreFoundation type-ID function has no preconditions.
        unsafe { CFNumberGetTypeID() }
    }

    fn cf_string_type_id() -> CFTypeID {
        // SAFETY: This public CoreFoundation type-ID function has no preconditions.
        unsafe { CFStringGetTypeID() }
    }

    fn cf_url_type_id() -> CFTypeID {
        // SAFETY: This public CoreFoundation type-ID function has no preconditions.
        unsafe { CFURLGetTypeID() }
    }

    fn require_type(value: CFTypeRef, expected: CFTypeID, what: &str) -> Result<(), String> {
        if value.is_null() {
            return Err(format!("{what} is null"));
        }
        // SAFETY: value is non-null and points to a live borrowed or retained CF object.
        let actual = unsafe { CFGetTypeID(value) };
        if actual != expected {
            return Err(format!("{what} has an unexpected CoreFoundation type"));
        }
        Ok(())
    }

    pub(crate) fn dictionary_value(
        dictionary: CFDictionaryRef,
        key: CFStringRef,
    ) -> Result<Option<CFTypeRef>, String> {
        require_type(
            dictionary.cast(),
            cf_dictionary_type_id(),
            "signing-information dictionary",
        )?;
        if key.is_null() {
            return Err("Security.framework exported a null dictionary key".to_string());
        }
        let mut value: *const c_void = ptr::null();
        // SAFETY: dictionary and exported key are live; value is a valid out pointer.
        let present = unsafe { CFDictionaryGetValueIfPresent(dictionary, key.cast(), &mut value) };
        if present == 0 {
            Ok(None)
        } else if value.is_null() {
            Err("signing-information dictionary contains a null value".to_string())
        } else {
            Ok(Some(value.cast()))
        }
    }

    pub(crate) fn cf_number_i64(value: CFTypeRef, label: &str) -> Result<i64, String> {
        require_type(value, cf_number_type_id(), label)?;
        let number = value.cast::<core_foundation_sys::number::__CFNumber>();
        // SAFETY: number has the exact CFNumber type.
        if unsafe { CFNumberIsFloatType(number) } != 0 {
            return Err(format!("{label} is floating-point"));
        }
        let mut decoded = 0_i64;
        // SAFETY: decoded points to writable i64 storage matching kCFNumberSInt64Type.
        if !unsafe { CFNumberGetValue(number, kCFNumberSInt64Type, (&raw mut decoded).cast()) } {
            return Err(format!(
                "{label} cannot be represented as a signed 64-bit integer"
            ));
        }
        Ok(decoded)
    }

    fn copy_data(value: CFTypeRef, max_bytes: usize) -> Result<Vec<u8>, String> {
        require_type(value, cf_data_type_id(), "entitlement blob")?;
        let data = value.cast::<core_foundation_sys::data::__CFData>();
        // SAFETY: data has the exact CFData type.
        let length = unsafe { CFDataGetLength(data) };
        let length = nonnegative_index(length, "CFData length")?;
        if length > max_bytes {
            return Err(format!("CFData exceeds the {max_bytes}-byte bound"));
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        // SAFETY: data is live and non-empty; CFDataGetBytePtr is valid for its lifetime.
        let pointer = unsafe { CFDataGetBytePtr(data) };
        if pointer.is_null() {
            return Err("non-empty CFData returned a null byte pointer".to_string());
        }
        // SAFETY: CFData guarantees `length` readable bytes at pointer while data is alive.
        Ok(unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn convert_security_metadata(
        dictionary: CFDictionaryRef,
    ) -> Result<SecurityMetadata, String> {
        convert_security_metadata_with_api(&SystemSecurityApi, dictionary)
    }

    pub(crate) fn convert_security_metadata_with_api(
        api: &dyn SecurityApi,
        dictionary: CFDictionaryRef,
    ) -> Result<SecurityMetadata, String> {
        // SAFETY: Security.framework key globals are immortal borrowed references.
        let identifier_value = dictionary_value(dictionary, unsafe { kSecCodeInfoIdentifier })?
            .ok_or_else(|| "signed information is missing kSecCodeInfoIdentifier".to_string())?;
        let mut remaining = MAX_METADATA_BYTES;
        let identifier = cf_string_to_rust(identifier_value.cast(), remaining)?;
        if identifier.is_empty() {
            return Err("signing identifier is empty".to_string());
        }
        remaining = remaining
            .checked_sub(identifier.len())
            .ok_or_else(|| "metadata byte budget underflowed".to_string())?;

        // SAFETY: Security.framework key globals are immortal borrowed references.
        let team_identifier =
            match dictionary_value(dictionary, unsafe { kSecCodeInfoTeamIdentifier })? {
                Some(value) => {
                    let team = cf_string_to_rust(value.cast(), remaining)?;
                    if team.is_empty() {
                        return Err("team identifier is empty".to_string());
                    }
                    remaining = remaining
                        .checked_sub(team.len())
                        .ok_or_else(|| "metadata byte budget underflowed".to_string())?;
                    Some(team)
                }
                None => None,
            };

        // SAFETY: Security.framework key globals are immortal borrowed references.
        let flags_value = dictionary_value(dictionary, unsafe { kSecCodeInfoFlags })?
            .ok_or_else(|| "signed information is missing kSecCodeInfoFlags".to_string())?;
        let flags = cf_number_i64(flags_value, "code-signature flags")?;
        let flags =
            u32::try_from(flags).map_err(|_| "code-signature flags do not fit u32".to_string())?;

        let mut authorities = Vec::new();
        // SAFETY: Security.framework key globals are immortal borrowed references.
        if let Some(certificates) =
            dictionary_value(dictionary, unsafe { kSecCodeInfoCertificates })?
        {
            require_type(certificates, cf_array_type_id(), "certificate chain")?;
            let array = certificates.cast::<core_foundation_sys::array::__CFArray>();
            // SAFETY: array has the exact CFArray type.
            let count = nonnegative_index(unsafe { CFArrayGetCount(array) }, "certificate count")?;
            if count > MAX_CERTIFICATES {
                return Err(format!("certificate count exceeds {MAX_CERTIFICATES}"));
            }
            authorities.reserve(count);
            for index in 0..count {
                // SAFETY: index is within the checked array count and parent remains alive.
                let certificate = unsafe {
                    CFArrayGetValueAtIndex(
                        array,
                        CFIndex::try_from(index).expect("bounded certificate index fits CFIndex"),
                    )
                };
                require_type(
                    certificate.cast(),
                    api.certificate_type_id(),
                    "certificate chain member",
                )?;
                let summary = api.copy_certificate_subject_summary(certificate.cast_mut().cast());
                let summary =
                    RetainedCf::from_created(api, summary, "certificate subject summary")?;
                let summary = cf_string_to_rust(summary.cast(), remaining)?;
                remaining = remaining
                    .checked_sub(summary.len())
                    .ok_or_else(|| "metadata byte budget underflowed".to_string())?;
                authorities.push(summary);
            }
        }

        Ok(SecurityMetadata {
            identifier,
            team_identifier,
            authorities,
            ad_hoc: flags & K_SEC_CODE_SIGNATURE_ADHOC != 0,
            hardened_runtime: flags & K_SEC_CODE_SIGNATURE_RUNTIME != 0,
        })
    }

    struct CfEntitlementReader {
        dictionaries: RefCell<BTreeMap<usize, Vec<(CFTypeRef, CFTypeRef)>>>,
    }

    impl CfEntitlementReader {
        fn new() -> Self {
            Self {
                dictionaries: RefCell::new(BTreeMap::new()),
            }
        }
    }

    impl StructuredEntitlementReader for CfEntitlementReader {
        type Value = CFTypeRef;

        fn identity(&self, value: Self::Value) -> usize {
            value.addr()
        }

        fn kind(&self, value: Self::Value) -> Result<StructuredValueKind, String> {
            if value.is_null() {
                return Err("structured entitlement contains a null value".to_string());
            }
            // SAFETY: value is non-null and borrowed from a retained parent dictionary.
            let actual = unsafe { CFGetTypeID(value) };
            // Boolean must precede Number because CFBoolean is number-like on Apple platforms.
            if actual == cf_boolean_type_id() {
                Ok(StructuredValueKind::Boolean)
            } else if actual == cf_number_type_id() {
                let number = value.cast::<core_foundation_sys::number::__CFNumber>();
                // SAFETY: actual is the exact CFNumber type.
                if unsafe { CFNumberIsFloatType(number) } != 0 {
                    Ok(StructuredValueKind::Unsupported)
                } else {
                    Ok(StructuredValueKind::Integer)
                }
            } else if actual == cf_string_type_id() {
                Ok(StructuredValueKind::String)
            } else if actual == cf_data_type_id() {
                Ok(StructuredValueKind::Data)
            } else if actual == cf_array_type_id() {
                Ok(StructuredValueKind::Array)
            } else if actual == cf_dictionary_type_id() {
                Ok(StructuredValueKind::Dictionary)
            } else {
                Ok(StructuredValueKind::Unsupported)
            }
        }

        fn read_boolean(&self, value: Self::Value) -> Result<bool, String> {
            require_type(value, cf_boolean_type_id(), "CFBoolean")?;
            // SAFETY: value has the exact CFBoolean type.
            Ok(unsafe { CFBooleanGetValue(value.cast()) })
        }

        fn read_integer(&self, value: Self::Value) -> Result<i64, String> {
            cf_number_i64(value, "entitlement CFNumber")
        }

        fn read_string(&self, value: Self::Value, max_bytes: usize) -> Result<String, String> {
            cf_string_to_rust(value.cast(), max_bytes)
        }

        fn read_data(&self, value: Self::Value, max_bytes: usize) -> Result<Vec<u8>, String> {
            copy_data(value, max_bytes)
        }

        fn array_len(&self, value: Self::Value) -> Result<usize, String> {
            require_type(value, cf_array_type_id(), "entitlement CFArray")?;
            // SAFETY: value has the exact CFArray type.
            let count = nonnegative_index(
                unsafe { CFArrayGetCount(value.cast()) },
                "entitlement array count",
            )?;
            if count > MAX_ENTITLEMENT_NODES {
                return Err("entitlement array exceeds the node bound".to_string());
            }
            Ok(count)
        }

        fn array_value(&self, value: Self::Value, index: usize) -> Result<Self::Value, String> {
            let count = self.array_len(value)?;
            if index >= count {
                return Err("entitlement array index is out of range".to_string());
            }
            // SAFETY: index is within the checked array and its retained parent is live.
            let member = unsafe {
                CFArrayGetValueAtIndex(
                    value.cast(),
                    CFIndex::try_from(index).expect("bounded array index fits CFIndex"),
                )
            };
            if member.is_null() {
                Err("entitlement array contains a null member".to_string())
            } else {
                Ok(member.cast())
            }
        }

        fn dictionary_len(&self, value: Self::Value) -> Result<usize, String> {
            require_type(value, cf_dictionary_type_id(), "entitlement CFDictionary")?;
            // SAFETY: value has the exact CFDictionary type.
            let count = nonnegative_index(
                unsafe { CFDictionaryGetCount(value.cast()) },
                "entitlement dictionary count",
            )?;
            if count > MAX_ENTITLEMENT_NODES {
                return Err("entitlement dictionary exceeds the node bound".to_string());
            }
            Ok(count)
        }

        fn dictionary_entry(
            &self,
            value: Self::Value,
            index: usize,
        ) -> Result<(Self::Value, Self::Value), String> {
            let identity = self.identity(value);
            if !self.dictionaries.borrow().contains_key(&identity) {
                let count = self.dictionary_len(value)?;
                let mut keys = vec![ptr::null(); count];
                let mut values = vec![ptr::null(); count];
                // SAFETY: buffers have exactly dictionary count slots and parent is live.
                unsafe {
                    CFDictionaryGetKeysAndValues(
                        value.cast(),
                        keys.as_mut_ptr(),
                        values.as_mut_ptr(),
                    )
                };
                if keys.iter().any(|key| key.is_null())
                    || values.iter().any(|member| member.is_null())
                {
                    return Err("entitlement dictionary contains a null key or value".to_string());
                }
                self.dictionaries.borrow_mut().insert(
                    identity,
                    keys.into_iter()
                        .zip(values)
                        .map(|(key, member)| (key.cast(), member.cast()))
                        .collect(),
                );
            }
            self.dictionaries
                .borrow()
                .get(&identity)
                .and_then(|entries| entries.get(index))
                .copied()
                .ok_or_else(|| "entitlement dictionary index is out of range".to_string())
        }
    }

    pub(crate) fn extract_legacy_entitlements(
        dictionary: CFDictionaryRef,
    ) -> LegacyEntitlementObservation {
        // SAFETY: Security.framework key globals are immortal borrowed references.
        let raw = match dictionary_value(dictionary, unsafe { kSecCodeInfoEntitlements }) {
            Ok(value) => value,
            Err(reason) => return LegacyEntitlementObservation::Invalid { reason },
        };
        // SAFETY: Security.framework key globals are immortal borrowed references.
        let typed = match dictionary_value(dictionary, unsafe { kSecCodeInfoEntitlementsDict }) {
            Ok(value) => value,
            Err(reason) => return LegacyEntitlementObservation::Invalid { reason },
        };
        match (raw, typed) {
            (None, None) => LegacyEntitlementObservation::Absent,
            (Some(_), None) | (None, Some(_)) => LegacyEntitlementObservation::Invalid {
                reason: "legacy entitlement blob and dictionary must either both be present or both be absent"
                    .to_string(),
            },
            (Some(raw), Some(typed)) => {
                let bytes = match copy_data(raw, MAX_ENTITLEMENT_BYTES) {
                    Ok(bytes) => bytes,
                    Err(reason) => return LegacyEntitlementObservation::Invalid { reason },
                };
                let format = match classify_legacy_entitlement_blob(&bytes) {
                    Ok(format) => format,
                    Err(reason) => return LegacyEntitlementObservation::Invalid { reason },
                };
                let entries = match decode_structured_entitlements(&CfEntitlementReader::new(), typed)
                {
                    Ok(entries) => entries,
                    Err(reason) => return LegacyEntitlementObservation::Invalid { reason },
                };
                LegacyEntitlementObservation::Valid { format, entries }
            }
        }
    }

    fn create_url<'a>(
        api: &'a dyn SecurityApi,
        path: &Path,
        is_directory: bool,
    ) -> Result<RetainedCf<'a>, String> {
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() {
            return Err("Security.framework query path is empty".to_string());
        }
        let length = CFIndex::try_from(bytes.len())
            .map_err(|_| "Security.framework query path is too long".to_string())?;
        // SAFETY: path bytes remain valid through the copying create call.
        let url = unsafe {
            CFURLCreateFromFileSystemRepresentation(
                ptr::null(),
                bytes.as_ptr(),
                length,
                u8::from(is_directory),
            )
        };
        RetainedCf::from_created(api, url, "CFURLCreateFromFileSystemRepresentation")
    }

    fn create_number_sint32<'a>(
        api: &'a dyn SecurityApi,
        value: i32,
    ) -> Result<RetainedCf<'a>, String> {
        // SAFETY: value is valid signed-32 storage copied synchronously by CFNumberCreate.
        let number =
            unsafe { CFNumberCreate(ptr::null(), kCFNumberSInt32Type, (&raw const value).cast()) };
        RetainedCf::from_created(api, number, "CFNumberCreate")
    }

    fn create_architecture_attributes<'a>(
        api: &'a dyn SecurityApi,
        architecture: &CodeSignatureArchitecture,
    ) -> Result<RetainedCf<'a>, String> {
        let cpu = create_number_sint32(api, architecture.cpu_type)?;
        let subtype = create_number_sint32(api, architecture.cpu_subtype)?;
        // SAFETY: Security.framework key globals are immortal borrowed references.
        let keys = unsafe {
            [
                kSecCodeAttributeArchitecture.cast::<c_void>(),
                kSecCodeAttributeSubarchitecture.cast::<c_void>(),
            ]
        };
        let values = [cpu.as_type(), subtype.as_type()];
        // SAFETY: arrays contain two valid CF objects and type callbacks retain them.
        let dictionary = unsafe {
            CFDictionaryCreate(
                ptr::null(),
                keys.as_ptr(),
                values.as_ptr(),
                2,
                &raw const kCFTypeDictionaryKeyCallBacks,
                &raw const kCFTypeDictionaryValueCallBacks,
            )
        };
        RetainedCf::from_created(api, dictionary, "CFDictionaryCreate")
    }

    fn take_out_pointer<'a, T>(
        api: &'a dyn SecurityApi,
        pointer: *const T,
        what: &str,
    ) -> Result<RetainedCf<'a>, String> {
        RetainedCf::from_created(api, pointer, what)
    }

    fn status_reason(operation: &str, status: i32) -> String {
        bounded_detail(&format!("{operation} returned OSStatus {status}"))
    }

    fn selected_metadata_failure(
        status: Option<i32>,
        reason: &str,
        bundle_unbound: bool,
    ) -> SecurityMetadataObservation {
        if !bundle_unbound
            && matches!(
                status.map(classify_security_status),
                Some(SecurityStatusClass::ArtifactRejected)
            )
        {
            SecurityMetadataObservation::Failed {
                reason: reason.to_string(),
            }
        } else {
            SecurityMetadataObservation::Error {
                reason: reason.to_string(),
            }
        }
    }

    fn copy_information<'a>(
        api: &'a dyn SecurityApi,
        code: SecStaticCodeRef,
        flags: u32,
    ) -> Result<RetainedCf<'a>, (i32, String)> {
        let mut information: CFDictionaryRef = ptr::null();
        let status = api.copy_signing_information(code, flags, &mut information);
        let retained = if information.is_null() {
            None
        } else {
            Some(
                take_out_pointer(api, information, "SecCodeCopySigningInformation")
                    .expect("nonnull pointer must wrap"),
            )
        };
        if status != 0 {
            drop(retained);
            return Err((
                status,
                status_reason("SecCodeCopySigningInformation", status),
            ));
        }
        retained.ok_or_else(|| {
            (
                status,
                "SecCodeCopySigningInformation succeeded with a null dictionary".to_string(),
            )
        })
    }

    enum MainBindingError {
        Observation(String),
        Rejected(String),
    }

    impl MainBindingError {
        fn into_reason(self) -> String {
            match self {
                Self::Observation(reason) | Self::Rejected(reason) => reason,
            }
        }
    }

    fn bind_information_main(
        information: CFDictionaryRef,
        bind_main: &mut dyn FnMut(&Path) -> Result<(), String>,
        required: bool,
    ) -> Result<Option<PathBuf>, MainBindingError> {
        // SAFETY: Security.framework key global is an immortal borrowed reference.
        let main = match dictionary_value(information, unsafe { kSecCodeInfoMainExecutable })
            .map_err(MainBindingError::Observation)?
        {
            Some(main) => main,
            None if !required => return Ok(None),
            None => {
                return Err(MainBindingError::Observation(
                    "signing information is missing kSecCodeInfoMainExecutable".to_string(),
                ));
            }
        };
        let path = cf_url_to_path(main.cast()).map_err(MainBindingError::Observation)?;
        bind_main(&path).map_err(|reason| MainBindingError::Rejected(bounded_detail(&reason)))?;
        Ok(Some(path))
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub(crate) struct SystemSecurityInfoProvider;

    impl SystemSecurityInfoProvider {
        fn create_path_code<'a>(
            api: &'a dyn SecurityApi,
            path: &Path,
            is_directory: bool,
        ) -> Result<RetainedCf<'a>, (Option<i32>, String)> {
            let url = create_url(api, path, is_directory).map_err(|reason| (None, reason))?;
            let mut code: SecStaticCodeRef = ptr::null();
            let status = api.create_with_path(url.cast(), K_SEC_CS_DEFAULT_FLAGS, &mut code);
            let retained = if code.is_null() {
                None
            } else {
                Some(
                    take_out_pointer(api, code, "SecStaticCodeCreateWithPath")
                        .expect("nonnull wraps"),
                )
            };
            if status != 0 {
                drop(retained);
                return Err((
                    Some(status),
                    status_reason("SecStaticCodeCreateWithPath", status),
                ));
            }
            let retained = retained.ok_or_else(|| {
                (
                    Some(status),
                    "SecStaticCodeCreateWithPath succeeded with a null code".to_string(),
                )
            })?;
            if let Err(reason) = require_type(
                retained.as_type(),
                api.static_code_type_id(),
                "SecStaticCodeCreateWithPath result",
            ) {
                return Err((None, reason));
            }
            Ok(retained)
        }

        fn create_selected_code<'a>(
            api: &'a dyn SecurityApi,
            request: &SelectedSecurityRequest<'_>,
        ) -> Result<RetainedCf<'a>, (Option<i32>, String)> {
            let url = create_url(
                api,
                request.path,
                request.target_kind == CodeSignatureTargetKind::ApplicationBundle,
            )
            .map_err(|reason| (None, reason))?;
            let attributes = create_architecture_attributes(api, request.architecture)
                .map_err(|reason| (None, reason))?;
            let mut code: SecStaticCodeRef = ptr::null();
            let status = api.create_with_path_and_attributes(
                url.cast(),
                K_SEC_CS_DEFAULT_FLAGS,
                attributes.cast(),
                &mut code,
            );
            let retained = if code.is_null() {
                None
            } else {
                Some(
                    take_out_pointer(api, code, "SecStaticCodeCreateWithPathAndAttributes")
                        .expect("nonnull wraps"),
                )
            };
            if status != 0 {
                drop(retained);
                return Err((
                    Some(status),
                    status_reason("SecStaticCodeCreateWithPathAndAttributes", status),
                ));
            }
            let retained = retained.ok_or_else(|| {
                (
                    Some(status),
                    "SecStaticCodeCreateWithPathAndAttributes succeeded with a null code"
                        .to_string(),
                )
            })?;
            if let Err(reason) = require_type(
                retained.as_type(),
                api.static_code_type_id(),
                "SecStaticCodeCreateWithPathAndAttributes result",
            ) {
                return Err((None, reason));
            }
            Ok(retained)
        }
    }

    impl SystemSecurityInfoProvider {
        pub(crate) fn resolve_bundle_main_with_api(
            &self,
            api: &dyn SecurityApi,
            bundle: &Path,
        ) -> PreliminarySecurityObservation {
            let code = match Self::create_path_code(api, bundle, true) {
                Ok(code) => code,
                Err((_, reason)) => return PreliminarySecurityObservation::Error { reason },
            };
            let status = api.check_validity(code.cast(), CHECK_FLAGS, ptr::null_mut());
            if status != 0 && status != ERR_SEC_CS_UNSIGNED {
                return PreliminarySecurityObservation::Error {
                    reason: status_reason("SecStaticCodeCheckValidity", status),
                };
            }
            let information = match copy_information(api, code.cast(), K_SEC_CS_DEFAULT_FLAGS) {
                Ok(information) => information,
                Err((_, reason)) => return PreliminarySecurityObservation::Error { reason },
            };
            // SAFETY: Security.framework key global is an immortal borrowed reference.
            let main = match dictionary_value(information.cast(), unsafe {
                kSecCodeInfoMainExecutable
            }) {
                Ok(Some(value)) => value,
                Ok(None) => {
                    return PreliminarySecurityObservation::Error {
                        reason: "preliminary signing information is missing the main executable"
                            .to_string(),
                    };
                }
                Err(reason) => return PreliminarySecurityObservation::Error { reason },
            };
            match cf_url_to_path(main.cast()) {
                Ok(path) => PreliminarySecurityObservation::Resolved(path),
                Err(reason) => PreliminarySecurityObservation::Error { reason },
            }
        }

        pub(crate) fn inspect_selected_with_api(
            &self,
            api: &dyn SecurityApi,
            request: &SelectedSecurityRequest<'_>,
            bind_main: &mut dyn FnMut(&Path) -> Result<(), String>,
        ) -> SelectedSecurityObservation {
            let bundle = request.target_kind == CodeSignatureTargetKind::ApplicationBundle;
            let code = match Self::create_selected_code(api, request) {
                Ok(code) => code,
                Err((status, reason)) => {
                    let selected_status = match status.map(classify_security_status) {
                        Some(SecurityStatusClass::ArtifactRejected) if !bundle => {
                            SelectedCodeStatus::Failed {
                                status: status.expect("classified status exists"),
                                reason: reason.clone(),
                            }
                        }
                        _ => SelectedCodeStatus::Error {
                            status,
                            reason: reason.clone(),
                        },
                    };
                    let metadata = selected_metadata_failure(status, &reason, bundle);
                    return SelectedSecurityObservation {
                        status: selected_status,
                        metadata,
                        legacy_entitlements: LegacyEntitlementObservation::Unobserved { reason },
                    };
                }
            };

            let check_status = api.check_validity(code.cast(), CHECK_FLAGS, ptr::null_mut());
            match classify_security_status(check_status) {
                SecurityStatusClass::Unsigned => {
                    if !bundle {
                        return SelectedSecurityObservation {
                            status: SelectedCodeStatus::Unsigned,
                            metadata: SecurityMetadataObservation::NotApplicable,
                            legacy_entitlements: LegacyEntitlementObservation::Unobserved {
                                reason: "selected unsigned Mach-O has no full signing-information dictionary"
                                    .to_string(),
                            },
                        };
                    }
                    let information =
                        match copy_information(api, code.cast(), K_SEC_CS_DEFAULT_FLAGS) {
                            Ok(information) => information,
                            Err((status, reason)) => {
                                return SelectedSecurityObservation {
                                    status: SelectedCodeStatus::Error {
                                        status: Some(status),
                                        reason: reason.clone(),
                                    },
                                    metadata: SecurityMetadataObservation::Error {
                                        reason: reason.clone(),
                                    },
                                    legacy_entitlements: LegacyEntitlementObservation::Unobserved {
                                        reason,
                                    },
                                };
                            }
                        };
                    if let Err(error) = bind_information_main(information.cast(), bind_main, true) {
                        let reason = error.into_reason();
                        return SelectedSecurityObservation {
                            status: SelectedCodeStatus::Error {
                                status: None,
                                reason: reason.clone(),
                            },
                            metadata: SecurityMetadataObservation::Error {
                                reason: reason.clone(),
                            },
                            legacy_entitlements: LegacyEntitlementObservation::Unobserved {
                                reason,
                            },
                        };
                    }
                    SelectedSecurityObservation {
                        status: SelectedCodeStatus::Unsigned,
                        metadata: SecurityMetadataObservation::NotApplicable,
                        legacy_entitlements: LegacyEntitlementObservation::Unobserved {
                            reason: "unsigned path-only signing information is not inspected for entitlements"
                                .to_string(),
                        },
                    }
                }
                SecurityStatusClass::ArtifactRejected => {
                    let reason = status_reason("SecStaticCodeCheckValidity", check_status);
                    let (status, metadata) = if bundle {
                        (
                            SelectedCodeStatus::Error {
                                status: Some(check_status),
                                reason: reason.clone(),
                            },
                            SecurityMetadataObservation::Error {
                                reason: reason.clone(),
                            },
                        )
                    } else {
                        (
                            SelectedCodeStatus::Failed {
                                status: check_status,
                                reason: reason.clone(),
                            },
                            SecurityMetadataObservation::Failed {
                                reason: reason.clone(),
                            },
                        )
                    };
                    SelectedSecurityObservation {
                        status,
                        metadata,
                        legacy_entitlements: LegacyEntitlementObservation::Unobserved { reason },
                    }
                }
                SecurityStatusClass::OperationalError => {
                    let reason = status_reason("SecStaticCodeCheckValidity", check_status);
                    SelectedSecurityObservation {
                        status: SelectedCodeStatus::Error {
                            status: Some(check_status),
                            reason: reason.clone(),
                        },
                        metadata: SecurityMetadataObservation::Error {
                            reason: reason.clone(),
                        },
                        legacy_entitlements: LegacyEntitlementObservation::Unobserved { reason },
                    }
                }
                SecurityStatusClass::Success => {
                    let information =
                        match copy_information(api, code.cast(), K_SEC_CS_SIGNING_INFORMATION) {
                            Ok(information) => information,
                            Err((status, reason)) => {
                                let selected_status = if bundle {
                                    SelectedCodeStatus::Error {
                                        status: Some(status),
                                        reason: reason.clone(),
                                    }
                                } else {
                                    SelectedCodeStatus::Signed
                                };
                                let metadata =
                                    selected_metadata_failure(Some(status), &reason, bundle);
                                return SelectedSecurityObservation {
                                    status: selected_status,
                                    metadata,
                                    legacy_entitlements: LegacyEntitlementObservation::Unobserved {
                                        reason,
                                    },
                                };
                            }
                        };
                    if let Err(error) = bind_information_main(information.cast(), bind_main, bundle)
                    {
                        let reason = error.into_reason();
                        return SelectedSecurityObservation {
                            status: SelectedCodeStatus::Error {
                                status: None,
                                reason: reason.clone(),
                            },
                            metadata: SecurityMetadataObservation::Error {
                                reason: reason.clone(),
                            },
                            legacy_entitlements: LegacyEntitlementObservation::Unobserved {
                                reason,
                            },
                        };
                    }
                    let metadata = match convert_security_metadata_with_api(api, information.cast())
                    {
                        Ok(metadata) => SecurityMetadataObservation::Passed(metadata),
                        Err(reason) => SecurityMetadataObservation::Error {
                            reason: bounded_detail(&reason),
                        },
                    };
                    let legacy_entitlements = extract_legacy_entitlements(information.cast());
                    SelectedSecurityObservation {
                        status: SelectedCodeStatus::Signed,
                        metadata,
                        legacy_entitlements,
                    }
                }
            }
        }
    }

    impl SecurityInfoProvider for SystemSecurityInfoProvider {
        fn resolve_bundle_main(&self, bundle: &Path) -> PreliminarySecurityObservation {
            self.resolve_bundle_main_with_api(&SystemSecurityApi, bundle)
        }

        fn inspect_selected(
            &self,
            request: &SelectedSecurityRequest<'_>,
            bind_main: &mut dyn FnMut(&Path) -> Result<(), String>,
        ) -> SelectedSecurityObservation {
            self.inspect_selected_with_api(&SystemSecurityApi, request, bind_main)
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) use native::SystemSecurityInfoProvider;

#[cfg(target_os = "macos")]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn system_security_info_provider() -> impl SecurityInfoProvider {
    SystemSecurityInfoProvider
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn security_constants_and_status_mapping_are_exact() {
        assert_eq!(CHECK_FLAGS, 0x2000_0006);
        assert_eq!(K_SEC_CS_DEFAULT_FLAGS, 0);
        assert_eq!(K_SEC_CS_BASIC_VALIDATE_ONLY, 6);
        assert_eq!(K_SEC_CS_NO_NETWORK_ACCESS, 1 << 29);
        assert_eq!(K_SEC_CS_SIGNING_INFORMATION, 2);
        assert_eq!(K_SEC_CODE_SIGNATURE_ADHOC, 0x0002);
        assert_eq!(K_SEC_CODE_SIGNATURE_RUNTIME, 0x10000);
        assert_eq!(ERR_SEC_CS_UNSIGNED, -67062);

        assert_eq!(
            classify_security_status(ERR_SEC_CS_UNSIGNED),
            SecurityStatusClass::Unsigned
        );
        assert_eq!(
            classify_security_status(-67061),
            SecurityStatusClass::ArtifactRejected
        );
        assert_eq!(
            classify_security_status(-67070),
            SecurityStatusClass::OperationalError
        );

        for status in ARTIFACT_REJECTION_STATUSES {
            assert_eq!(
                classify_security_status(*status),
                SecurityStatusClass::ArtifactRejected,
                "status {status} must remain in the audited artifact allowlist"
            );
        }
        for status in [0, -4, -50, -108, -600, -25291, -25300, -67070] {
            assert_ne!(
                classify_security_status(status),
                SecurityStatusClass::ArtifactRejected,
                "operational status {status} must not be called an artifact rejection"
            );
        }
    }

    #[test]
    fn provider_seam_is_object_safe() {
        fn accepts_provider(_: &dyn SecurityInfoProvider) {}

        let provider = UnavailableSecurityInfoProvider;
        accepts_provider(&provider);
        #[cfg(target_os = "macos")]
        accepts_provider(&system_security_info_provider());
    }

    #[test]
    fn unavailable_provider_returns_only_unavailable_observations() {
        let provider = UnavailableSecurityInfoProvider;
        assert!(matches!(
            provider.resolve_bundle_main(Path::new("/Applications/Example.app")),
            PreliminarySecurityObservation::Unavailable { .. }
        ));

        let architecture = CodeSignatureArchitecture::new(0x0100_000c, 2);
        let request = SelectedSecurityRequest {
            path: Path::new("/Applications/Example.app"),
            architecture: &architecture,
            target_kind: CodeSignatureTargetKind::ApplicationBundle,
        };
        let mut bind_was_called = false;
        let observation = provider.inspect_selected(&request, &mut |_| {
            bind_was_called = true;
            Ok(())
        });
        assert!(!bind_was_called);
        assert!(matches!(
            observation.status,
            SelectedCodeStatus::Unavailable { .. }
        ));
        assert!(matches!(
            observation.metadata,
            SecurityMetadataObservation::Unavailable { .. }
        ));
        assert!(matches!(
            observation.legacy_entitlements,
            LegacyEntitlementObservation::Unobserved { .. }
        ));
    }

    #[test]
    fn detail_truncation_is_utf8_safe_and_bounded() {
        let short = "short";
        assert_eq!(bounded_detail(short), short);

        let oversized = "🙂".repeat(MAX_SECURITY_DETAIL_BYTES);
        let bounded = bounded_detail(&oversized);
        assert!(bounded.len() <= MAX_SECURITY_DETAIL_BYTES);
        assert!(bounded.is_char_boundary(bounded.len()));
        assert!(bounded.ends_with("[truncated]"));
    }

    #[cfg(target_os = "macos")]
    mod macos {
        use std::cell::{Cell, RefCell};
        use std::ffi::c_void;
        use std::os::unix::ffi::OsStringExt;
        use std::ptr;

        use core_foundation_sys::array::{CFArrayCreate, kCFTypeArrayCallBacks};
        use core_foundation_sys::base::{
            CFGetTypeID, CFIndex, CFRelease, CFRetain, CFTypeID, CFTypeRef, OSStatus,
        };
        use core_foundation_sys::data::CFDataCreate;
        use core_foundation_sys::dictionary::{
            CFDictionaryCreate, CFDictionaryGetTypeID, CFDictionaryRef,
            kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks,
        };
        use core_foundation_sys::number::{
            CFNumberCreate, kCFBooleanTrue, kCFNumberFloat64Type, kCFNumberSInt32Type,
            kCFNumberSInt64Type,
        };
        use core_foundation_sys::string::{
            CFStringCreateWithBytes, CFStringRef, kCFStringEncodingUTF8,
        };
        use core_foundation_sys::url::{CFURLCreateFromFileSystemRepresentation, CFURLRef};

        use super::super::native::{
            MAX_CERTIFICATES, MAX_MAIN_PATH_BYTES, MAX_METADATA_BYTES, SecCertificateRef,
            SecRequirementRef, SecStaticCodeRef, SecurityApi, SystemSecurityInfoProvider,
            cf_number_i64, cf_string_to_rust, cf_url_to_path, convert_security_metadata,
            convert_security_metadata_with_api, dictionary_value, extract_legacy_entitlements,
            kSecCodeAttributeArchitecture, kSecCodeAttributeSubarchitecture,
            kSecCodeInfoCertificates, kSecCodeInfoEntitlements, kSecCodeInfoEntitlementsDict,
            kSecCodeInfoFlags, kSecCodeInfoIdentifier, kSecCodeInfoMainExecutable,
            kSecCodeInfoTeamIdentifier, validate_main_path_bytes,
        };
        use super::*;
        use crate::macos::entitlements::{EntitlementEntry, EntitlementValue, LegacyFormat};

        struct TestCf(CFTypeRef);

        impl TestCf {
            fn new(value: CFTypeRef) -> Self {
                assert!(!value.is_null());
                Self(value)
            }

            fn string(&self) -> CFStringRef {
                self.0.cast()
            }

            fn dictionary(&self) -> CFDictionaryRef {
                self.0.cast()
            }
        }

        impl Drop for TestCf {
            fn drop(&mut self) {
                // SAFETY: TestCf owns one create-rule reference and releases it once.
                unsafe { CFRelease(self.0) };
            }
        }

        fn cf_string(value: &str) -> TestCf {
            let length = CFIndex::try_from(value.len()).expect("fixture length fits CFIndex");
            // SAFETY: The byte pointer remains valid for the duration of the copying create call.
            let string = unsafe {
                CFStringCreateWithBytes(
                    ptr::null(),
                    value.as_ptr(),
                    length,
                    kCFStringEncodingUTF8,
                    0,
                )
            };
            TestCf::new(string.cast())
        }

        fn cf_number(value: i64) -> TestCf {
            // SAFETY: The pointer addresses a correctly aligned i64 for the copying create call.
            let number = unsafe {
                CFNumberCreate(ptr::null(), kCFNumberSInt64Type, (&raw const value).cast())
            };
            TestCf::new(number.cast())
        }

        fn cf_float(value: f64) -> TestCf {
            // SAFETY: The pointer addresses a correctly aligned f64 for the copying create call.
            let number = unsafe {
                CFNumberCreate(ptr::null(), kCFNumberFloat64Type, (&raw const value).cast())
            };
            TestCf::new(number.cast())
        }

        fn cf_data(value: &[u8]) -> TestCf {
            // SAFETY: The byte pointer remains valid for the duration of the copying create call.
            let data = unsafe {
                CFDataCreate(
                    ptr::null(),
                    value.as_ptr(),
                    CFIndex::try_from(value.len()).expect("fixture length fits CFIndex"),
                )
            };
            TestCf::new(data.cast())
        }

        fn cf_dictionary(entries: &[(CFStringRef, CFTypeRef)]) -> TestCf {
            let keys = entries
                .iter()
                .map(|(key, _)| (*key).cast::<c_void>())
                .collect::<Vec<_>>();
            let values = entries.iter().map(|(_, value)| *value).collect::<Vec<_>>();
            // SAFETY: The arrays contain valid CF objects, and type callbacks copy ownership.
            let dictionary = unsafe {
                CFDictionaryCreate(
                    ptr::null(),
                    keys.as_ptr(),
                    values.as_ptr(),
                    CFIndex::try_from(entries.len()).expect("fixture count fits CFIndex"),
                    &raw const kCFTypeDictionaryKeyCallBacks,
                    &raw const kCFTypeDictionaryValueCallBacks,
                )
            };
            TestCf::new(dictionary.cast())
        }

        fn cf_array(values: &[CFTypeRef]) -> TestCf {
            // SAFETY: values contains live CF objects and type callbacks retain them.
            let array = unsafe {
                CFArrayCreate(
                    ptr::null(),
                    values.as_ptr(),
                    CFIndex::try_from(values.len()).expect("fixture count fits CFIndex"),
                    &raw const kCFTypeArrayCallBacks,
                )
            };
            TestCf::new(array.cast())
        }

        fn cf_url(path: &[u8], is_directory: bool) -> TestCf {
            // SAFETY: The bytes remain valid for the duration of the copying create call.
            let url = unsafe {
                CFURLCreateFromFileSystemRepresentation(
                    ptr::null(),
                    path.as_ptr(),
                    CFIndex::try_from(path.len()).expect("fixture length fits CFIndex"),
                    u8::from(is_directory),
                )
            };
            TestCf::new(url.cast())
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        enum ApiCall {
            CreatePath(u32),
            CreateSelected(u32),
            Check(u32),
            Copy(u32),
        }

        struct FakeSecurityApi {
            calls: RefCell<Vec<ApiCall>>,
            create_status: Cell<i32>,
            check_status: Cell<i32>,
            copy_status: Cell<i32>,
            create_output: Cell<SecStaticCodeRef>,
            copy_output: Cell<CFDictionaryRef>,
            static_code_type_id: Cell<CFTypeID>,
            certificate_type_id: Cell<CFTypeID>,
            certificate_summary: Cell<CFStringRef>,
            certificate_summary_calls: Cell<usize>,
            releases: Cell<usize>,
        }

        impl FakeSecurityApi {
            fn new() -> Self {
                Self {
                    calls: RefCell::new(Vec::new()),
                    create_status: Cell::new(0),
                    check_status: Cell::new(0),
                    copy_status: Cell::new(0),
                    create_output: Cell::new(ptr::null()),
                    copy_output: Cell::new(ptr::null()),
                    static_code_type_id: Cell::new(0),
                    certificate_type_id: Cell::new(0),
                    certificate_summary: Cell::new(ptr::null()),
                    certificate_summary_calls: Cell::new(0),
                    releases: Cell::new(0),
                }
            }
        }

        impl SecurityApi for FakeSecurityApi {
            fn create_with_path(
                &self,
                _path: CFURLRef,
                flags: u32,
                output: *mut SecStaticCodeRef,
            ) -> OSStatus {
                self.calls.borrow_mut().push(ApiCall::CreatePath(flags));
                assert!(!output.is_null());
                // SAFETY: provider passes a valid writable out pointer initialized to null.
                assert!(unsafe { *output }.is_null());
                // SAFETY: output was validated and points to live storage for this call.
                unsafe { *output = self.create_output.get() };
                self.create_status.get()
            }

            fn create_with_path_and_attributes(
                &self,
                _path: CFURLRef,
                flags: u32,
                attributes: CFDictionaryRef,
                output: *mut SecStaticCodeRef,
            ) -> OSStatus {
                self.calls.borrow_mut().push(ApiCall::CreateSelected(flags));
                // SAFETY: These are immortal Security.framework globals, and attributes is live.
                for (key, expected) in unsafe {
                    [
                        (kSecCodeAttributeArchitecture, 0x0100_000c_i32),
                        (kSecCodeAttributeSubarchitecture, 2_i32),
                    ]
                } {
                    let value = dictionary_value(attributes, key)
                        .expect("attribute dictionary should be readable")
                        .expect("attribute key should be present");
                    assert_eq!(
                        cf_number_i64(value, "fake architecture attribute")
                            .expect("architecture attribute should be integral"),
                        i64::from(expected)
                    );
                    // SAFETY: value was checked as an exact CFNumber.
                    assert_eq!(
                        unsafe { core_foundation_sys::number::CFNumberGetType(value.cast()) },
                        kCFNumberSInt32Type
                    );
                }
                assert!(!output.is_null());
                // SAFETY: provider passes a valid writable out pointer initialized to null.
                assert!(unsafe { *output }.is_null());
                // SAFETY: output was validated and points to live storage for this call.
                unsafe { *output = self.create_output.get() };
                self.create_status.get()
            }

            fn check_validity(
                &self,
                _code: SecStaticCodeRef,
                flags: u32,
                requirement: SecRequirementRef,
            ) -> OSStatus {
                assert!(requirement.is_null());
                self.calls.borrow_mut().push(ApiCall::Check(flags));
                self.check_status.get()
            }

            fn copy_signing_information(
                &self,
                _code: SecStaticCodeRef,
                flags: u32,
                output: *mut CFDictionaryRef,
            ) -> OSStatus {
                self.calls.borrow_mut().push(ApiCall::Copy(flags));
                assert!(!output.is_null());
                // SAFETY: provider passes a valid writable out pointer initialized to null.
                assert!(unsafe { *output }.is_null());
                // SAFETY: output was validated and points to live storage for this call.
                unsafe { *output = self.copy_output.get() };
                self.copy_status.get()
            }

            fn static_code_type_id(&self) -> CFTypeID {
                self.static_code_type_id.get()
            }

            fn certificate_type_id(&self) -> CFTypeID {
                self.certificate_type_id.get()
            }

            fn copy_certificate_subject_summary(
                &self,
                certificate: SecCertificateRef,
            ) -> CFStringRef {
                let _ = certificate;
                self.certificate_summary_calls
                    .set(self.certificate_summary_calls.get() + 1);
                self.certificate_summary.get()
            }

            fn release(&self, value: CFTypeRef) {
                self.releases.set(self.releases.get() + 1);
                // SAFETY: fake outputs are real +1 CF objects and each wrapper releases once.
                unsafe { CFRelease(value) };
            }
        }

        fn fake_code(api: &FakeSecurityApi) -> TestCf {
            let code = cf_string("fake static code");
            // SAFETY: code is a live CF object whose exact runtime type is queried here.
            api.static_code_type_id.set(unsafe { CFGetTypeID(code.0) });
            api.create_output.set(code.0.cast());
            code
        }

        #[test]
        fn low_level_preliminary_sequence_uses_exact_flags_and_releases_every_output() {
            let api = FakeSecurityApi::new();
            let code = fake_code(&api);
            let main = cf_url(b"/tmp/main", false);
            // SAFETY: This is an immortal exported Security.framework key.
            let information = unsafe { cf_dictionary(&[(kSecCodeInfoMainExecutable, main.0)]) };
            api.copy_output.set(information.0.cast());
            // Balance the TestCf owners because fake out pointers transfer another +1.
            // SAFETY: Both objects are live and may be retained for simulated copy results.
            unsafe {
                CFRetain(code.0);
                CFRetain(information.0);
            }

            let observation = SystemSecurityInfoProvider
                .resolve_bundle_main_with_api(&api, Path::new("/tmp/Fake.app"));
            assert_eq!(
                observation,
                PreliminarySecurityObservation::Resolved(PathBuf::from("/tmp/main"))
            );
            assert_eq!(
                api.calls.into_inner(),
                vec![
                    ApiCall::CreatePath(K_SEC_CS_DEFAULT_FLAGS),
                    ApiCall::Check(CHECK_FLAGS),
                    ApiCall::Copy(K_SEC_CS_DEFAULT_FLAGS),
                ]
            );
            // URL input, returned code, and copied dictionary are each released once.
            assert_eq!(api.releases.get(), 3);
        }

        #[test]
        fn low_level_selected_copy_uses_signing_flag_and_preserves_signed_on_copy_error() {
            let api = FakeSecurityApi::new();
            let code = fake_code(&api);
            // SAFETY: code is live and retained for the simulated create result.
            unsafe { CFRetain(code.0) };
            api.copy_status.set(-50);
            let architecture = CodeSignatureArchitecture::new(0x0100_000c, 2);
            let request = SelectedSecurityRequest {
                path: Path::new("/tmp/tool"),
                architecture: &architecture,
                target_kind: CodeSignatureTargetKind::MachOFile,
            };
            let observation =
                SystemSecurityInfoProvider
                    .inspect_selected_with_api(&api, &request, &mut |_| Ok(()));
            assert!(matches!(observation.status, SelectedCodeStatus::Signed));
            assert!(matches!(
                observation.metadata,
                SecurityMetadataObservation::Error { .. }
            ));
            assert_eq!(
                api.calls.into_inner(),
                vec![
                    ApiCall::CreateSelected(K_SEC_CS_DEFAULT_FLAGS),
                    ApiCall::Check(CHECK_FLAGS),
                    ApiCall::Copy(K_SEC_CS_SIGNING_INFORMATION),
                ]
            );
            // URL, both CFNumbers, attribute dictionary, and returned code are released once.
            assert_eq!(api.releases.get(), 5);
        }

        #[test]
        fn low_level_direct_basic_success_survives_missing_main_but_bundle_fails_closed() {
            let architecture = CodeSignatureArchitecture::new(0x0100_000c, 2);
            for (target_kind, expected_signed) in [
                (CodeSignatureTargetKind::MachOFile, true),
                (CodeSignatureTargetKind::ApplicationBundle, false),
            ] {
                let api = FakeSecurityApi::new();
                let code = fake_code(&api);
                let information = cf_dictionary(&[]);
                api.copy_output.set(information.0.cast());
                // SAFETY: Both live objects gain one simulated out-pointer ownership.
                unsafe {
                    CFRetain(code.0);
                    CFRetain(information.0);
                }
                let request = SelectedSecurityRequest {
                    path: Path::new("/tmp/target"),
                    architecture: &architecture,
                    target_kind,
                };
                let observation = SystemSecurityInfoProvider.inspect_selected_with_api(
                    &api,
                    &request,
                    &mut |_| Ok(()),
                );
                assert_eq!(
                    matches!(observation.status, SelectedCodeStatus::Signed),
                    expected_signed
                );
                assert!(matches!(
                    observation.metadata,
                    SecurityMetadataObservation::Error { .. }
                ));
            }
        }

        #[test]
        fn low_level_direct_full_information_does_not_require_a_main_locator() {
            let api = FakeSecurityApi::new();
            let code = fake_code(&api);
            let identifier = cf_string("com.example.tool");
            let flags = cf_number(0);
            // SAFETY: Security.framework keys are immortal exported globals.
            let information = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoIdentifier, identifier.0),
                    (kSecCodeInfoFlags, flags.0),
                ])
            };
            api.copy_output.set(information.0.cast());
            // SAFETY: Both live objects gain one simulated out-pointer ownership.
            unsafe {
                CFRetain(code.0);
                CFRetain(information.0);
            }
            let architecture = CodeSignatureArchitecture::new(0x0100_000c, 2);
            let request = SelectedSecurityRequest {
                path: Path::new("/tmp/tool"),
                architecture: &architecture,
                target_kind: CodeSignatureTargetKind::MachOFile,
            };
            let observation =
                SystemSecurityInfoProvider.inspect_selected_with_api(&api, &request, &mut |_| {
                    panic!("an absent optional direct main must not invoke the binder")
                });

            assert!(matches!(observation.status, SelectedCodeStatus::Signed));
            assert!(matches!(
                observation.metadata,
                SecurityMetadataObservation::Passed(SecurityMetadata {
                    ref identifier,
                    ..
                }) if identifier == "com.example.tool"
            ));
            assert!(matches!(
                observation.legacy_entitlements,
                LegacyEntitlementObservation::Absent
            ));
        }

        #[test]
        fn low_level_main_bound_identifier_failures_preserve_signed_and_legacy_independently() {
            enum IdentifierFixture {
                Missing,
                Null,
                WrongType,
                Empty,
                OverBudget,
            }

            let architecture = CodeSignatureArchitecture::new(0x0100_000c, 2);
            for fixture in [
                IdentifierFixture::Missing,
                IdentifierFixture::Null,
                IdentifierFixture::WrongType,
                IdentifierFixture::Empty,
                IdentifierFixture::OverBudget,
            ] {
                let api = FakeSecurityApi::new();
                let code = fake_code(&api);
                let main = cf_url(b"/tmp/tool", false);
                let flags = cf_number(0);
                let empty = cf_string("");
                let oversized = cf_string(&"i".repeat(MAX_METADATA_BYTES + 1));
                let wrong = cf_number(7);
                let mut entries = vec![
                    // SAFETY: Security.framework globals are immortal borrowed references.
                    (unsafe { kSecCodeInfoMainExecutable }, main.0),
                    // SAFETY: Security.framework globals are immortal borrowed references.
                    (unsafe { kSecCodeInfoFlags }, flags.0),
                ];
                match fixture {
                    IdentifierFixture::Missing => {}
                    IdentifierFixture::Null => {
                        // SAFETY: kCFNull is an immortal exported CoreFoundation global.
                        entries.push((unsafe { kSecCodeInfoIdentifier }, unsafe {
                            core_foundation_sys::base::kCFNull.cast()
                        }));
                    }
                    IdentifierFixture::WrongType => {
                        // SAFETY: Security.framework global is an immortal borrowed reference.
                        entries.push((unsafe { kSecCodeInfoIdentifier }, wrong.0));
                    }
                    IdentifierFixture::Empty => {
                        // SAFETY: Security.framework global is an immortal borrowed reference.
                        entries.push((unsafe { kSecCodeInfoIdentifier }, empty.0));
                    }
                    IdentifierFixture::OverBudget => {
                        // SAFETY: Security.framework global is an immortal borrowed reference.
                        entries.push((unsafe { kSecCodeInfoIdentifier }, oversized.0));
                    }
                }
                let information = cf_dictionary(&entries);
                api.copy_output.set(information.0.cast());
                // SAFETY: Both live objects gain one simulated out-pointer ownership.
                unsafe {
                    CFRetain(code.0);
                    CFRetain(information.0);
                }
                let request = SelectedSecurityRequest {
                    path: Path::new("/tmp/tool"),
                    architecture: &architecture,
                    target_kind: CodeSignatureTargetKind::MachOFile,
                };
                let mut bound = false;
                let observation = SystemSecurityInfoProvider.inspect_selected_with_api(
                    &api,
                    &request,
                    &mut |path| {
                        assert_eq!(path, Path::new("/tmp/tool"));
                        bound = true;
                        Ok(())
                    },
                );

                assert!(bound);
                assert!(matches!(observation.status, SelectedCodeStatus::Signed));
                assert!(matches!(
                    observation.metadata,
                    SecurityMetadataObservation::Error { .. }
                ));
                assert!(matches!(
                    observation.legacy_entitlements,
                    LegacyEntitlementObservation::Absent
                ));
            }
        }

        #[test]
        fn low_level_direct_callback_identity_rejection_fails_closed() {
            let api = FakeSecurityApi::new();
            let code = fake_code(&api);
            let main = cf_url(b"/tmp/main", false);
            let identifier = cf_string("com.example.tool");
            let flags = cf_number(0);
            // SAFETY: Security.framework keys are immortal exported globals.
            let information = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoMainExecutable, main.0),
                    (kSecCodeInfoIdentifier, identifier.0),
                    (kSecCodeInfoFlags, flags.0),
                ])
            };
            api.copy_output.set(information.0.cast());
            // SAFETY: Both live objects gain one simulated out-pointer ownership.
            unsafe {
                CFRetain(code.0);
                CFRetain(information.0);
            }
            let architecture = CodeSignatureArchitecture::new(0x0100_000c, 2);
            let request = SelectedSecurityRequest {
                path: Path::new("/tmp/tool"),
                architecture: &architecture,
                target_kind: CodeSignatureTargetKind::MachOFile,
            };
            let observation =
                SystemSecurityInfoProvider.inspect_selected_with_api(&api, &request, &mut |_| {
                    Err("captured main identity changed".to_string())
                });
            assert!(matches!(
                observation.status,
                SelectedCodeStatus::Error { .. }
            ));
        }

        #[test]
        fn low_level_direct_present_but_invalid_main_fails_closed() {
            let api = FakeSecurityApi::new();
            let code = fake_code(&api);
            let invalid_main = cf_string("/tmp/tool");
            let identifier = cf_string("com.example.tool");
            let flags = cf_number(0);
            // SAFETY: Security.framework keys are immortal exported globals.
            let information = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoMainExecutable, invalid_main.0),
                    (kSecCodeInfoIdentifier, identifier.0),
                    (kSecCodeInfoFlags, flags.0),
                ])
            };
            api.copy_output.set(information.0.cast());
            // SAFETY: Both live objects gain one simulated out-pointer ownership.
            unsafe {
                CFRetain(code.0);
                CFRetain(information.0);
            }
            let architecture = CodeSignatureArchitecture::new(0x0100_000c, 2);
            let request = SelectedSecurityRequest {
                path: Path::new("/tmp/tool"),
                architecture: &architecture,
                target_kind: CodeSignatureTargetKind::MachOFile,
            };
            let observation =
                SystemSecurityInfoProvider.inspect_selected_with_api(&api, &request, &mut |_| {
                    panic!("wrong-typed main must fail before callback binding")
                });

            assert!(matches!(
                observation.status,
                SelectedCodeStatus::Error { .. }
            ));
            assert!(matches!(
                observation.metadata,
                SecurityMetadataObservation::Error { .. }
            ));
            assert!(matches!(
                observation.legacy_entitlements,
                LegacyEntitlementObservation::Unobserved { .. }
            ));
        }

        #[test]
        fn low_level_success_with_null_or_wrong_typed_code_is_error_and_released() {
            let null_api = FakeSecurityApi::new();
            let observation = SystemSecurityInfoProvider
                .resolve_bundle_main_with_api(&null_api, Path::new("/tmp/Fake.app"));
            assert!(matches!(
                observation,
                PreliminarySecurityObservation::Error { .. }
            ));
            // Even success-with-null releases the created input URL.
            assert_eq!(null_api.releases.get(), 1);

            let wrong_api = FakeSecurityApi::new();
            let wrong = cf_string("not a static code");
            // Deliberately require CFDictionary while returning CFString.
            // SAFETY: This public function has no preconditions.
            wrong_api
                .static_code_type_id
                .set(unsafe { CFDictionaryGetTypeID() });
            wrong_api.create_output.set(wrong.0.cast());
            // SAFETY: wrong is live and retained for the simulated create result.
            unsafe { CFRetain(wrong.0) };
            let observation = SystemSecurityInfoProvider
                .resolve_bundle_main_with_api(&wrong_api, Path::new("/tmp/Fake.app"));
            assert!(matches!(
                observation,
                PreliminarySecurityObservation::Error { .. }
            ));
            // The input URL and wrong-typed returned object are both released.
            assert_eq!(wrong_api.releases.get(), 2);
            assert_eq!(wrong_api.calls.into_inner(), vec![ApiCall::CreatePath(0)]);
        }

        #[test]
        fn low_level_preliminary_unsigned_copies_default_but_other_failure_does_not_copy() {
            let unsigned = FakeSecurityApi::new();
            let code = fake_code(&unsigned);
            let main = cf_url(b"/tmp/main", false);
            // SAFETY: This is an immortal Security.framework key.
            let information = unsafe { cf_dictionary(&[(kSecCodeInfoMainExecutable, main.0)]) };
            unsigned.check_status.set(ERR_SEC_CS_UNSIGNED);
            unsigned.copy_output.set(information.0.cast());
            // SAFETY: Both live objects gain one simulated out-pointer ownership.
            unsafe {
                CFRetain(code.0);
                CFRetain(information.0);
            }
            assert!(matches!(
                SystemSecurityInfoProvider
                    .resolve_bundle_main_with_api(&unsigned, Path::new("/tmp/Fake.app")),
                PreliminarySecurityObservation::Resolved(_)
            ));
            assert_eq!(
                unsigned.calls.into_inner(),
                vec![
                    ApiCall::CreatePath(0),
                    ApiCall::Check(CHECK_FLAGS),
                    ApiCall::Copy(0)
                ]
            );

            let rejected = FakeSecurityApi::new();
            let rejected_code = fake_code(&rejected);
            rejected.check_status.set(-67061);
            // SAFETY: live object gains one simulated out-pointer ownership.
            unsafe { CFRetain(rejected_code.0) };
            assert!(matches!(
                SystemSecurityInfoProvider
                    .resolve_bundle_main_with_api(&rejected, Path::new("/tmp/Fake.app")),
                PreliminarySecurityObservation::Error { .. }
            ));
            assert_eq!(
                rejected.calls.into_inner(),
                vec![ApiCall::CreatePath(0), ApiCall::Check(CHECK_FLAGS)]
            );
        }

        #[test]
        fn low_level_selected_unsigned_direct_skips_copy_and_bundle_copies_default_and_binds() {
            let architecture = CodeSignatureArchitecture::new(0x0100_000c, 2);
            let direct_request = SelectedSecurityRequest {
                path: Path::new("/tmp/tool"),
                architecture: &architecture,
                target_kind: CodeSignatureTargetKind::MachOFile,
            };
            let direct = FakeSecurityApi::new();
            let direct_code = fake_code(&direct);
            direct.check_status.set(ERR_SEC_CS_UNSIGNED);
            // SAFETY: live object gains one simulated out-pointer ownership.
            unsafe { CFRetain(direct_code.0) };
            let direct_observation = SystemSecurityInfoProvider.inspect_selected_with_api(
                &direct,
                &direct_request,
                &mut |_| panic!("direct unsigned must not bind"),
            );
            assert!(matches!(
                direct_observation.status,
                SelectedCodeStatus::Unsigned
            ));
            assert_eq!(
                direct.calls.into_inner(),
                vec![ApiCall::CreateSelected(0), ApiCall::Check(CHECK_FLAGS)]
            );

            let bundle_request = SelectedSecurityRequest {
                target_kind: CodeSignatureTargetKind::ApplicationBundle,
                ..direct_request
            };
            let bundle = FakeSecurityApi::new();
            let bundle_code = fake_code(&bundle);
            let main = cf_url(b"/tmp/main", false);
            // SAFETY: This is an immortal Security.framework key.
            let information = unsafe { cf_dictionary(&[(kSecCodeInfoMainExecutable, main.0)]) };
            bundle.check_status.set(ERR_SEC_CS_UNSIGNED);
            bundle.copy_output.set(information.0.cast());
            // SAFETY: Both live objects gain one simulated out-pointer ownership.
            unsafe {
                CFRetain(bundle_code.0);
                CFRetain(information.0);
            }
            let mut bound = None;
            let observation = SystemSecurityInfoProvider.inspect_selected_with_api(
                &bundle,
                &bundle_request,
                &mut |path| {
                    bound = Some(path.to_path_buf());
                    Ok(())
                },
            );
            assert!(matches!(observation.status, SelectedCodeStatus::Unsigned));
            assert_eq!(bound, Some(PathBuf::from("/tmp/main")));
            assert_eq!(
                bundle.calls.into_inner(),
                vec![
                    ApiCall::CreateSelected(0),
                    ApiCall::Check(CHECK_FLAGS),
                    ApiCall::Copy(K_SEC_CS_DEFAULT_FLAGS),
                ]
            );
        }

        #[test]
        fn low_level_selected_artifact_rejection_is_failed_only_after_direct_binding() {
            let architecture = CodeSignatureArchitecture::new(0x0100_000c, 2);

            for (target_kind, expect_failed_metadata) in [
                (CodeSignatureTargetKind::MachOFile, true),
                (CodeSignatureTargetKind::ApplicationBundle, false),
            ] {
                let api = FakeSecurityApi::new();
                let code = fake_code(&api);
                api.check_status.set(-67061);
                // SAFETY: live object gains one simulated out-pointer ownership.
                unsafe { CFRetain(code.0) };
                let request = SelectedSecurityRequest {
                    path: Path::new("/tmp/target"),
                    architecture: &architecture,
                    target_kind,
                };
                let mut bind_was_called = false;
                let observation = SystemSecurityInfoProvider.inspect_selected_with_api(
                    &api,
                    &request,
                    &mut |_| {
                        bind_was_called = true;
                        Ok(())
                    },
                );

                assert!(!bind_was_called);
                assert_eq!(
                    matches!(observation.status, SelectedCodeStatus::Failed { .. }),
                    expect_failed_metadata
                );
                assert_eq!(
                    matches!(
                        observation.metadata,
                        SecurityMetadataObservation::Failed { .. }
                    ),
                    expect_failed_metadata
                );
                assert_eq!(
                    matches!(
                        observation.metadata,
                        SecurityMetadataObservation::Error { .. }
                    ),
                    !expect_failed_metadata
                );
                assert_eq!(
                    api.calls.into_inner(),
                    vec![ApiCall::CreateSelected(0), ApiCall::Check(CHECK_FLAGS)]
                );
            }
        }

        #[test]
        fn low_level_direct_create_artifact_rejection_marks_metadata_failed() {
            let architecture = CodeSignatureArchitecture::new(0x0100_000c, 2);

            for (target_kind, expect_failed) in [
                (CodeSignatureTargetKind::MachOFile, true),
                (CodeSignatureTargetKind::ApplicationBundle, false),
            ] {
                let api = FakeSecurityApi::new();
                let code = fake_code(&api);
                api.create_status.set(-67061);
                // SAFETY: live object gains one simulated error out-pointer ownership.
                unsafe { CFRetain(code.0) };
                let request = SelectedSecurityRequest {
                    path: Path::new("/tmp/target"),
                    architecture: &architecture,
                    target_kind,
                };
                let observation = SystemSecurityInfoProvider.inspect_selected_with_api(
                    &api,
                    &request,
                    &mut |_| panic!("failed create must not attempt main binding"),
                );

                assert_eq!(
                    matches!(observation.status, SelectedCodeStatus::Failed { .. }),
                    expect_failed
                );
                assert_eq!(
                    matches!(
                        observation.metadata,
                        SecurityMetadataObservation::Failed { .. }
                    ),
                    expect_failed
                );
                assert_eq!(
                    matches!(
                        observation.metadata,
                        SecurityMetadataObservation::Error { .. }
                    ),
                    !expect_failed
                );
                assert_eq!(
                    api.calls.into_inner(),
                    vec![ApiCall::CreateSelected(K_SEC_CS_DEFAULT_FLAGS)]
                );
            }
        }

        #[test]
        fn low_level_direct_copy_artifact_rejection_marks_metadata_failed_but_preserves_signed() {
            let architecture = CodeSignatureArchitecture::new(0x0100_000c, 2);

            for (target_kind, expect_signed) in [
                (CodeSignatureTargetKind::MachOFile, true),
                (CodeSignatureTargetKind::ApplicationBundle, false),
            ] {
                let api = FakeSecurityApi::new();
                let code = fake_code(&api);
                api.copy_status.set(-67061);
                // SAFETY: live object gains one simulated out-pointer ownership.
                unsafe { CFRetain(code.0) };
                let request = SelectedSecurityRequest {
                    path: Path::new("/tmp/target"),
                    architecture: &architecture,
                    target_kind,
                };
                let observation = SystemSecurityInfoProvider.inspect_selected_with_api(
                    &api,
                    &request,
                    &mut |_| panic!("failed copy must not attempt main binding"),
                );

                assert_eq!(
                    matches!(observation.status, SelectedCodeStatus::Signed),
                    expect_signed
                );
                assert_eq!(
                    matches!(
                        observation.metadata,
                        SecurityMetadataObservation::Failed { .. }
                    ),
                    expect_signed
                );
                assert_eq!(
                    matches!(
                        observation.metadata,
                        SecurityMetadataObservation::Error { .. }
                    ),
                    !expect_signed
                );
                assert_eq!(
                    api.calls.into_inner(),
                    vec![
                        ApiCall::CreateSelected(K_SEC_CS_DEFAULT_FLAGS),
                        ApiCall::Check(CHECK_FLAGS),
                        ApiCall::Copy(K_SEC_CS_SIGNING_INFORMATION),
                    ]
                );
            }
        }

        #[test]
        fn low_level_error_out_pointers_are_released_and_copy_success_null_is_error() {
            let create_error = FakeSecurityApi::new();
            let returned = fake_code(&create_error);
            create_error.create_status.set(-50);
            // SAFETY: live object gains one simulated out-pointer ownership.
            unsafe { CFRetain(returned.0) };
            let observation = SystemSecurityInfoProvider
                .resolve_bundle_main_with_api(&create_error, Path::new("/tmp/Fake.app"));
            assert!(matches!(
                observation,
                PreliminarySecurityObservation::Error { .. }
            ));
            // Created URL plus nonnull error out-pointer are both released.
            assert_eq!(create_error.releases.get(), 2);

            let copy_error = FakeSecurityApi::new();
            let code = fake_code(&copy_error);
            let copied = cf_dictionary(&[]);
            copy_error.copy_status.set(-50);
            copy_error.copy_output.set(copied.0.cast());
            // SAFETY: Both live objects gain one simulated out-pointer ownership.
            unsafe {
                CFRetain(code.0);
                CFRetain(copied.0);
            }
            let observation = SystemSecurityInfoProvider
                .resolve_bundle_main_with_api(&copy_error, Path::new("/tmp/Fake.app"));
            assert!(matches!(
                observation,
                PreliminarySecurityObservation::Error { .. }
            ));
            assert_eq!(copy_error.releases.get(), 3);

            let copy_null = FakeSecurityApi::new();
            let null_code = fake_code(&copy_null);
            // SAFETY: live object gains one simulated out-pointer ownership.
            unsafe { CFRetain(null_code.0) };
            let observation = SystemSecurityInfoProvider
                .resolve_bundle_main_with_api(&copy_null, Path::new("/tmp/Fake.app"));
            assert!(matches!(
                observation,
                PreliminarySecurityObservation::Error { .. }
            ));
            assert_eq!(
                copy_null.calls.into_inner(),
                vec![
                    ApiCall::CreatePath(0),
                    ApiCall::Check(CHECK_FLAGS),
                    ApiCall::Copy(0)
                ]
            );
        }

        #[test]
        fn cf_string_conversion_is_exact_utf8_and_respects_byte_bound() {
            let value = cf_string("safe\n\u{202e}🙂");
            assert_eq!(
                cf_string_to_rust(value.string(), 64),
                Ok("safe\n\u{202e}🙂".to_string())
            );
            assert!(cf_string_to_rust(value.string(), 4).is_err());
        }

        #[test]
        fn main_url_conversion_is_lossless_and_rejects_unsafe_paths() {
            let absolute = cf_url(b"/tmp/opaque-\xff", false);
            assert_eq!(
                cf_url_to_path(absolute.0.cast::<core_foundation_sys::url::__CFURL>()),
                Ok(PathBuf::from(std::ffi::OsString::from_vec(
                    b"/tmp/opaque-\xff".to_vec()
                )))
            );

            assert!(validate_main_path_bytes(b"relative/file").is_err());
            let newline = cf_url(b"/tmp/a\nb", false);
            assert!(cf_url_to_path(newline.0.cast()).is_err());
        }

        #[test]
        fn metadata_requires_typed_identifier_and_integral_u32_flags() {
            let identifier = cf_string("com.example.safe");
            let team = cf_string("TEAM12345");
            let flags = cf_number(i64::from(K_SEC_CODE_SIGNATURE_RUNTIME));
            // SAFETY: These are immortal exported Security.framework globals.
            let dictionary = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoIdentifier, identifier.0),
                    (kSecCodeInfoTeamIdentifier, team.0),
                    (kSecCodeInfoFlags, flags.0),
                ])
            };
            assert_eq!(
                convert_security_metadata(dictionary.dictionary()),
                Ok(SecurityMetadata {
                    identifier: "com.example.safe".to_string(),
                    team_identifier: Some("TEAM12345".to_string()),
                    authorities: vec![],
                    ad_hoc: false,
                    hardened_runtime: true,
                })
            );

            // SAFETY: This is an immortal exported Security.framework global.
            let missing_identifier = unsafe { cf_dictionary(&[(kSecCodeInfoFlags, flags.0)]) };
            assert!(convert_security_metadata(missing_identifier.dictionary()).is_err());

            let float = cf_float(1.0);
            // SAFETY: These are immortal exported Security.framework globals.
            let floating_flags = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoIdentifier, identifier.0),
                    (kSecCodeInfoFlags, float.0),
                ])
            };
            assert!(convert_security_metadata(floating_flags.dictionary()).is_err());

            let ad_hoc_flags = cf_number(i64::from(K_SEC_CODE_SIGNATURE_ADHOC));
            // SAFETY: These are immortal exported Security.framework globals.
            let ad_hoc = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoIdentifier, identifier.0),
                    (kSecCodeInfoFlags, ad_hoc_flags.0),
                ])
            };
            let metadata = convert_security_metadata(ad_hoc.dictionary())
                .expect("documented ad-hoc flag must convert");
            assert!(metadata.ad_hoc);
            assert!(!metadata.hardened_runtime);
        }

        #[test]
        fn metadata_enforces_empty_and_aggregate_string_bounds() {
            let empty = cf_string("");
            let flags = cf_number(0);
            // SAFETY: Security.framework keys are immortal exported globals.
            let empty_identifier = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoIdentifier, empty.0),
                    (kSecCodeInfoFlags, flags.0),
                ])
            };
            assert!(convert_security_metadata(empty_identifier.dictionary()).is_err());

            let exact = cf_string(&"i".repeat(MAX_METADATA_BYTES));
            // SAFETY: Security.framework keys are immortal exported globals.
            let exact_dictionary = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoIdentifier, exact.0),
                    (kSecCodeInfoFlags, flags.0),
                ])
            };
            assert!(convert_security_metadata(exact_dictionary.dictionary()).is_ok());

            let over = cf_string(&"i".repeat(MAX_METADATA_BYTES + 1));
            // SAFETY: Security.framework keys are immortal exported globals.
            let over_dictionary = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoIdentifier, over.0),
                    (kSecCodeInfoFlags, flags.0),
                ])
            };
            assert!(convert_security_metadata(over_dictionary.dictionary()).is_err());

            let identifier = cf_string(&"i".repeat(MAX_METADATA_BYTES));
            let team = cf_string("t");
            // SAFETY: Security.framework keys are immortal exported globals.
            let aggregate_over = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoIdentifier, identifier.0),
                    (kSecCodeInfoTeamIdentifier, team.0),
                    (kSecCodeInfoFlags, flags.0),
                ])
            };
            assert!(convert_security_metadata(aggregate_over.dictionary()).is_err());
        }

        #[test]
        fn metadata_enforces_certificate_count_before_traversal() {
            let identifier = cf_string("com.example.tool");
            let flags = cf_number(0);
            let placeholder = cf_string("not a certificate");
            let sixty_four = cf_array(&vec![placeholder.0; MAX_CERTIFICATES]);
            let sixty_five = cf_array(&vec![placeholder.0; MAX_CERTIFICATES + 1]);
            // SAFETY: Security.framework keys are immortal exported globals.
            let at_limit = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoIdentifier, identifier.0),
                    (kSecCodeInfoFlags, flags.0),
                    (kSecCodeInfoCertificates, sixty_four.0),
                ])
            };
            let error = convert_security_metadata(at_limit.dictionary())
                .expect_err("placeholder certificate type should fail after count admission");
            assert!(error.contains("certificate chain member"));

            // SAFETY: Security.framework keys are immortal exported globals.
            let over_limit = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoIdentifier, identifier.0),
                    (kSecCodeInfoFlags, flags.0),
                    (kSecCodeInfoCertificates, sixty_five.0),
                ])
            };
            let error = convert_security_metadata(over_limit.dictionary())
                .expect_err("65 certificates must fail at the count bound");
            assert!(error.contains("certificate count exceeds"));
        }

        #[test]
        fn metadata_certificate_summaries_obey_aggregate_bound_and_release_on_every_exit() {
            for (summary_length, expect_success) in
                [(MAX_METADATA_BYTES - 1, true), (MAX_METADATA_BYTES, false)]
            {
                let api = FakeSecurityApi::new();
                let identifier = cf_string("i");
                let flags = cf_number(0);
                let certificate = cf_string("test certificate object");
                let certificates = cf_array(&[certificate.0]);
                let summary = cf_string(&"A".repeat(summary_length));
                // SAFETY: certificate is a live CF object whose exact runtime type is queried.
                api.certificate_type_id
                    .set(unsafe { CFGetTypeID(certificate.0) });
                api.certificate_summary.set(summary.string());
                // SAFETY: summary is live and gains one simulated copy-rule ownership.
                unsafe { CFRetain(summary.0) };
                // SAFETY: Security.framework keys are immortal exported globals.
                let dictionary = unsafe {
                    cf_dictionary(&[
                        (kSecCodeInfoIdentifier, identifier.0),
                        (kSecCodeInfoFlags, flags.0),
                        (kSecCodeInfoCertificates, certificates.0),
                    ])
                };

                let converted = convert_security_metadata_with_api(&api, dictionary.dictionary());
                assert_eq!(converted.is_ok(), expect_success);
                if let Ok(metadata) = converted {
                    assert_eq!(metadata.authorities, vec!["A".repeat(summary_length)]);
                }
                assert_eq!(api.certificate_summary_calls.get(), 1);
                assert_eq!(api.releases.get(), 1);
            }
        }

        #[test]
        fn metadata_rejects_null_or_wrong_typed_certificate_summaries() {
            let identifier = cf_string("com.example.tool");
            let flags = cf_number(0);
            let certificate = cf_string("test certificate object");
            let certificates = cf_array(&[certificate.0]);
            // SAFETY: Security.framework keys are immortal exported globals.
            let dictionary = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoIdentifier, identifier.0),
                    (kSecCodeInfoFlags, flags.0),
                    (kSecCodeInfoCertificates, certificates.0),
                ])
            };

            let null_api = FakeSecurityApi::new();
            // SAFETY: certificate is live and its exact runtime type is queried.
            null_api
                .certificate_type_id
                .set(unsafe { CFGetTypeID(certificate.0) });
            assert!(
                convert_security_metadata_with_api(&null_api, dictionary.dictionary()).is_err()
            );
            assert_eq!(null_api.certificate_summary_calls.get(), 1);
            assert_eq!(null_api.releases.get(), 0);

            let wrong_api = FakeSecurityApi::new();
            // SAFETY: certificate is live and its exact runtime type is queried.
            wrong_api
                .certificate_type_id
                .set(unsafe { CFGetTypeID(certificate.0) });
            let wrong_summary = cf_number(7);
            wrong_api.certificate_summary.set(wrong_summary.0.cast());
            // SAFETY: wrong_summary is live and gains one simulated copy-rule ownership.
            unsafe { CFRetain(wrong_summary.0) };
            assert!(
                convert_security_metadata_with_api(&wrong_api, dictionary.dictionary()).is_err()
            );
            assert_eq!(wrong_api.certificate_summary_calls.get(), 1);
            assert_eq!(wrong_api.releases.get(), 1);
        }

        #[test]
        fn main_url_rejects_wrong_type_and_oversized_representation() {
            let wrong = cf_string("/tmp/main");
            assert!(cf_url_to_path(wrong.0.cast()).is_err());

            let oversized = format!("/{}", "a".repeat(MAX_MAIN_PATH_BYTES + 1));
            let url = cf_url(oversized.as_bytes(), false);
            assert!(cf_url_to_path(url.0.cast()).is_err());
        }

        #[test]
        fn legacy_entitlements_require_the_raw_and_typed_pair() {
            let entitlement_key = cf_string("enabled");
            // SAFETY: kCFBooleanTrue is an immortal exported CoreFoundation global.
            let typed =
                unsafe { cf_dictionary(&[(entitlement_key.string(), kCFBooleanTrue.cast())]) };
            let mut blob = vec![0xfa, 0xde, 0x71, 0x71, 0, 0, 0, 0];
            blob.extend_from_slice(b"bplist00");
            let blob_len = u32::try_from(blob.len()).expect("fixture length fits u32");
            blob[4..8].copy_from_slice(&blob_len.to_be_bytes());
            let raw = cf_data(&blob);

            // SAFETY: These are immortal exported Security.framework globals.
            let both = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoEntitlements, raw.0),
                    (kSecCodeInfoEntitlementsDict, typed.0),
                ])
            };
            assert_eq!(
                extract_legacy_entitlements(both.dictionary()),
                LegacyEntitlementObservation::Valid {
                    format: LegacyFormat::Binary,
                    entries: vec![EntitlementEntry {
                        key: "enabled".to_string(),
                        value: EntitlementValue::Boolean(true),
                    }],
                }
            );

            // SAFETY: This is an immortal exported Security.framework global.
            let raw_only = unsafe { cf_dictionary(&[(kSecCodeInfoEntitlements, raw.0)]) };
            assert!(matches!(
                extract_legacy_entitlements(raw_only.dictionary()),
                LegacyEntitlementObservation::Invalid { .. }
            ));

            // SAFETY: This is an immortal exported Security.framework global.
            let dictionary_only =
                unsafe { cf_dictionary(&[(kSecCodeInfoEntitlementsDict, typed.0)]) };
            assert!(matches!(
                extract_legacy_entitlements(dictionary_only.dictionary()),
                LegacyEntitlementObservation::Invalid { .. }
            ));

            let wrong_raw = cf_string("not data");
            // SAFETY: Security.framework keys are immortal exported globals.
            let wrong_raw_pair = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoEntitlements, wrong_raw.0),
                    (kSecCodeInfoEntitlementsDict, typed.0),
                ])
            };
            assert!(matches!(
                extract_legacy_entitlements(wrong_raw_pair.dictionary()),
                LegacyEntitlementObservation::Invalid { .. }
            ));

            let wrong_typed = cf_string("not dictionary");
            // SAFETY: Security.framework keys are immortal exported globals.
            let wrong_typed_pair = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoEntitlements, raw.0),
                    (kSecCodeInfoEntitlementsDict, wrong_typed.0),
                ])
            };
            assert!(matches!(
                extract_legacy_entitlements(wrong_typed_pair.dictionary()),
                LegacyEntitlementObservation::Invalid { .. }
            ));

            let malformed = cf_data(b"not-a-coded-entitlement-blob");
            // SAFETY: Security.framework keys are immortal exported globals.
            let malformed_pair = unsafe {
                cf_dictionary(&[
                    (kSecCodeInfoEntitlements, malformed.0),
                    (kSecCodeInfoEntitlementsDict, typed.0),
                ])
            };
            assert!(matches!(
                extract_legacy_entitlements(malformed_pair.dictionary()),
                LegacyEntitlementObservation::Invalid { .. }
            ));
        }
    }
}
