pub mod ncch;
pub mod cia;
pub mod titleid;
pub mod tmd;
pub mod smdh;
pub mod string;
pub mod crypto;
pub mod ticket;

use thiserror::Error;
#[derive(Error, Debug)]
pub enum CytrynaError {
    #[error("Invalid magic bytes")]
    InvalidMagic,
    #[error("Missing region")]
    MissingRegion,
    #[error("Invalid size of header")]
    InvalidHeaderSize,
    #[error("Invalid hash for {0}")]
    InvalidHash(&'static str),
    #[error("Signature corrupted/forged")]
    SignatureCorrupted,
    #[error("Invalid region position")]
    InvalidRegionPosition,
    #[error("Unsupported version of header")]
    UnsupportedHeaderVersion,
    #[error("Missing {0} key")]
    MissingKey(crypto::KeyIndex),
    #[error("Uninitialized keybag")]
    NoKeyBag,
    #[error("Value out of range for {0} enum")]
    EnumValueOutOfRange(&'static str),
    #[error("Byte slice passed is too small")]
    SliceTooSmall,
}

pub type Result<T> = std::result::Result<T, CytrynaError>;
