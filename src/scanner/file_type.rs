#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactType {
    MachO,
    Elf,
    Pe,
    Pdf,
    Zip,
    Xar,
    Png,
    Jpeg,
    Script,
    Unknown,
}

impl ArtifactType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArtifactType::MachO => "Mach-O",
            ArtifactType::Elf => "ELF",
            ArtifactType::Pe => "PE",
            ArtifactType::Pdf => "PDF",
            ArtifactType::Zip => "ZIP",
            ArtifactType::Xar => "XAR",
            ArtifactType::Png => "PNG",
            ArtifactType::Jpeg => "JPEG",
            ArtifactType::Script => "Script",
            ArtifactType::Unknown => "Unknown",
        }
    }
}

pub fn detect_file_type(bytes: &[u8]) -> ArtifactType {
    if is_macho(bytes) {
        return ArtifactType::MachO;
    }

    if bytes.starts_with(b"\x7FELF") {
        return ArtifactType::Elf;
    }

    if bytes.starts_with(b"MZ") {
        return ArtifactType::Pe;
    }

    if bytes.starts_with(b"%PDF-") {
        return ArtifactType::Pdf;
    }

    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
    {
        return ArtifactType::Zip;
    }

    if bytes.starts_with(b"xar!") {
        return ArtifactType::Xar;
    }

    if bytes.starts_with(b"\x89PNG\r\n\x1A\n") {
        return ArtifactType::Png;
    }

    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return ArtifactType::Jpeg;
    }

    if bytes.starts_with(b"#!") {
        return ArtifactType::Script;
    }

    ArtifactType::Unknown
}

fn is_macho(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }

    let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];

    matches!(
        magic,
        [0xFE, 0xED, 0xFA, 0xCE]
            | [0xCE, 0xFA, 0xED, 0xFE]
            | [0xFE, 0xED, 0xFA, 0xCF]
            | [0xCF, 0xFA, 0xED, 0xFE]
            | [0xCA, 0xFE, 0xBA, 0xBE]
            | [0xBE, 0xBA, 0xFE, 0xCA]
            | [0xCA, 0xFE, 0xBA, 0xBF]
            | [0xBF, 0xBA, 0xFE, 0xCA]
    )
}
