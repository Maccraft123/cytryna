use sha2::{Sha256, Digest};

/// Computes sha hash of a given byte slice
pub fn sha256(data: &[u8]) -> [u8; 0x20] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
