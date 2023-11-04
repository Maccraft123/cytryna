pub mod cia;
pub mod crypto;
pub mod ncch;
pub mod smdh;
pub mod string;
pub mod ticket;
pub mod titleid;
pub mod tmd;

use std::ops::Deref;

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
    #[error("Invalid length of {what}: {actual} (expected {expected})")]
    InvalidLength{
        what: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("Failed to parse keyindex")]
    KeyIndexFail(#[from] crypto::KeyIndexParseError),
    #[error("Failed to stream-encrypt/decrypt data")]
    StreamCrypt(#[from] ctr::cipher::StreamCipherError),
    #[error("Failed to decode hex string")]
    HexError(#[from] hex::FromHexError)
}

pub type CytrynaResult<T> = std::result::Result<T, CytrynaError>;

pub mod prelude {
    pub use crate::cia::Cia;
    pub use crate::ncch::Ncch;
    pub use crate::smdh::Smdh;
    pub use crate::ticket::Ticket;
}

#[derive(Debug, Clone)]
pub enum OwnedOrBorrowed<'a, T> {
    Owned(Box<T>),
    Borrowed(&'a T),
}

impl<T> Deref for OwnedOrBorrowed<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        match self {
            Self::Owned(data) => &(data.as_ref()),
            Self::Borrowed(data) => data,
        }
    }
}

#[derive(Debug, Clone)]
pub enum VecOrSlice<'a, T> {
    V(Vec<T>),
    S(&'a [T]),
}

impl<T> VecOrSlice<'_, T> {
    fn as_slice(&self) -> &[T] {
        match self {
            Self::V(vec) => &vec,
            Self::S(slice) => slice,
        }
    }
}

impl<T> Deref for VecOrSlice<'_, T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}
