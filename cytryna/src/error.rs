use core::fmt;

use crate::crypto;

/// Low-effort catch-all error type for cytryna library
#[non_exhaustive]
#[derive(Debug)]
pub enum CytrynaError {
    InvalidMagic,
    MissingRegion,
    InvalidHeaderSize,
    InvalidHash,
    SignatureCorrupted,
    InvalidRegionPosition,
    UnsupportedHeaderVersion,
    #[cfg(feature = "crypto")]
    MissingKey(crypto::KeyIndex),
    #[cfg(feature = "crypto")]
    NoKeyBag,
    EnumValueOutOfRange(&'static str),
    SliceTooSmall,
    InvalidLength{
        what: &'static str,
        actual: usize,
        expected: usize,
    },
    #[cfg(feature = "crypto")]
    KeyIndexFail(crypto::KeyIndexParseError),
    #[cfg(feature = "crypto")]
    StreamCrypt(ctr::cipher::StreamCipherError),
    HexError(hex::FromHexError),
    BadAlign,
}

impl fmt::Display for CytrynaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => f.write_str("Invalid magic bytes"),
            Self::MissingRegion => f.write_str("Missing region"),
            Self::InvalidHeaderSize => f.write_str("Invalid header size"),
            Self::InvalidHash => f.write_str("Invalid hash"),
            Self::SignatureCorrupted => f.write_str("Signature corrupted"),
            Self::InvalidRegionPosition => f.write_str("Invalid region position"),
            Self::UnsupportedHeaderVersion => f.write_str("Unsupported header version"),
            #[cfg(feature = "crypto")]
            Self::MissingKey(idx) => f.write_str(&format!("Missing {idx} key")),
            #[cfg(feature = "crypto")]
            Self::NoKeyBag => f.write_str("Unitialized keybag"),
            Self::EnumValueOutOfRange(name) => f.write_str(&format!("Value of out range for {name} enum")),
            Self::SliceTooSmall => f.write_str("Byte slice passed is too small"),
            Self::InvalidLength {what, actual, expected} => f.write_str(&format!("Invalid length of {what}: {actual} (expected {expected})")),
            #[cfg(feature = "crypto")]
            Self::KeyIndexFail(_) => f.write_str("Key index parse error"),
            #[cfg(feature = "crypto")]
            Self::StreamCrypt(_) => f.write_str("Encryption/Decryption error"),
            Self::HexError(_) => f.write_str("Failed to decode hex string"),
            Self::BadAlign => f.write_str("Incorrect alignment"),
        }
    }
}

impl From<ctr::cipher::StreamCipherError> for CytrynaError {
    fn from(err: ctr::cipher::StreamCipherError) -> Self {
        CytrynaError::StreamCrypt(err)
    }
}

impl From<crypto::KeyIndexParseError> for CytrynaError {
    fn from(err: crypto::KeyIndexParseError) -> Self {
        Self::KeyIndexFail(err)
    }
}

impl From<hex::FromHexError> for CytrynaError {
    fn from(err: hex::FromHexError) -> Self {
        Self::HexError(err)
    }
}
