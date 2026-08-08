use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug)]
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

pub fn detect_file_type(path: &Path) -> Result<ArtifactType, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("Failed to open {}: {}", path.display(), error))?;

    let mut buffer = [0u8; 16];

    let bytes_read = file
        .read(&mut buffer)
        .map_err(|error| format!("Failed to read {}: {}", path.display(), error))?;

    let bytes = &buffer[..bytes_read];

    if is_macho(bytes) {
        return Ok(ArtifactType::MachO);
    }

    if bytes.starts_with(b"\x7FELF") {
        return Ok(ArtifactType::Elf);
    }

    if bytes.starts_with(b"MZ") {
        return Ok(ArtifactType::Pe);
    }

    if bytes.starts_with(b"%PDF-") {
        return Ok(ArtifactType::Pdf);
    }

    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
    {
        return Ok(ArtifactType::Zip);
    }

    if bytes.starts_with(b"xar!") {
        return Ok(ArtifactType::Xar);
    }

    if bytes.starts_with(b"\x89PNG\r\n\x1A\n") {
        return Ok(ArtifactType::Png);
    }

    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Ok(ArtifactType::Jpeg);
    }

    if bytes.starts_with(b"#!") {
        return Ok(ArtifactType::Script);
    }

    Ok(ArtifactType::Unknown)
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
