use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug)]
pub struct MachOInfo {
    pub format: String,
    pub architecture: Option<String>,
    pub endianness: String,
}

pub fn inspect_macho(path: &Path) -> Result<MachOInfo, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("Failed to open {}: {}", path.display(), error))?;

    let mut buffer = [0u8; 8];

    let bytes_read = file
        .read(&mut buffer)
        .map_err(|error| format!("Failed to read {}: {}", path.display(), error))?;

    inspect_macho_bytes(&buffer[..bytes_read])
}

fn inspect_macho_bytes(bytes: &[u8]) -> Result<MachOInfo, String> {
    if bytes.len() < 4 {
        return Err("File is too small to contain a Mach-O header".to_string());
    }

    let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];

    match magic {
        // 32-bit little-endian Mach-O
        [0xCE, 0xFA, 0xED, 0xFE] => inspect_thin_macho(bytes, false, true),

        // 32-bit big-endian Mach-O
        [0xFE, 0xED, 0xFA, 0xCE] => inspect_thin_macho(bytes, false, false),

        // 64-bit little-endian Mach-O
        [0xCF, 0xFA, 0xED, 0xFE] => inspect_thin_macho(bytes, true, true),

        // 64-bit big-endian Mach-O
        [0xFE, 0xED, 0xFA, 0xCF] => inspect_thin_macho(bytes, true, false),

        // Universal / Fat binary
        [0xCA, 0xFE, 0xBA, 0xBE] => Ok(MachOInfo {
            format: "Universal".to_string(),
            architecture: None,
            endianness: "big".to_string(),
        }),

        [0xBE, 0xBA, 0xFE, 0xCA] => Ok(MachOInfo {
            format: "Universal".to_string(),
            architecture: None,
            endianness: "little".to_string(),
        }),

        // 64-bit Universal / Fat header
        [0xCA, 0xFE, 0xBA, 0xBF] => Ok(MachOInfo {
            format: "Universal64".to_string(),
            architecture: None,
            endianness: "big".to_string(),
        }),

        [0xBF, 0xBA, 0xFE, 0xCA] => Ok(MachOInfo {
            format: "Universal64".to_string(),
            architecture: None,
            endianness: "little".to_string(),
        }),

        _ => Err("Not a recognized Mach-O header".to_string()),
    }
}

fn inspect_thin_macho(
    bytes: &[u8],
    is_64_bit: bool,
    little_endian: bool,
) -> Result<MachOInfo, String> {
    if bytes.len() < 8 {
        return Err("Mach-O header is incomplete".to_string());
    }

    let cpu_bytes = [bytes[4], bytes[5], bytes[6], bytes[7]];

    let cpu_type = if little_endian {
        u32::from_le_bytes(cpu_bytes)
    } else {
        u32::from_be_bytes(cpu_bytes)
    };

    let architecture = architecture_name(cpu_type);

    Ok(MachOInfo {
        format: if is_64_bit {
            "64-bit".to_string()
        } else {
            "32-bit".to_string()
        },
        architecture: Some(architecture),
        endianness: if little_endian {
            "little".to_string()
        } else {
            "big".to_string()
        },
    })
}

fn architecture_name(cpu_type: u32) -> String {
    match cpu_type {
        0x00000007 => "x86".to_string(),
        0x01000007 => "x86_64".to_string(),

        0x0000000C => "arm".to_string(),
        0x0100000C => "arm64".to_string(),

        0x00000012 => "powerpc".to_string(),
        0x01000012 => "powerpc64".to_string(),

        _ => format!("unknown (0x{cpu_type:08x})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_arm64_macho() {
        let bytes = [0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01];

        let info = inspect_macho_bytes(&bytes).unwrap();

        assert_eq!(info.format, "64-bit");
        assert_eq!(info.architecture.as_deref(), Some("arm64"));
        assert_eq!(info.endianness, "little");
    }

    #[test]
    fn detects_x86_64_macho() {
        let bytes = [0xCF, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x01];

        let info = inspect_macho_bytes(&bytes).unwrap();

        assert_eq!(info.format, "64-bit");
        assert_eq!(info.architecture.as_deref(), Some("x86_64"));
    }

    #[test]
    fn detects_universal_binary() {
        let bytes = [0xCA, 0xFE, 0xBA, 0xBE];

        let info = inspect_macho_bytes(&bytes).unwrap();

        assert_eq!(info.format, "Universal");
        assert!(info.architecture.is_none());
    }
}
