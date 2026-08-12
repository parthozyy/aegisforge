use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

pub fn calculate_sha256_and_snapshot(
    reader: &mut impl Read,
    path: &Path,
) -> Result<(String, Vec<u8>), String> {
    let mut hasher = Sha256::new();
    let mut snapshot = Vec::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|error| format!("Failed to read {}: {}", path.display(), error))?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
        snapshot.extend_from_slice(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();

    Ok((hex::encode(result), snapshot))
}
