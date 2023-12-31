#![allow(clippy::transmute_ptr_to_ref)]
#![allow(clippy::identity_op)]

extern crate alloc;

#[cfg(feature = "3dsx")]
pub mod hb3dsx;
#[cfg(feature = "cia")]
pub mod cia;
#[cfg(feature = "crypto")]
pub mod crypto;
#[cfg(feature = "firm")]
pub mod firm;
#[cfg(feature = "hash")]
pub mod hash;
#[cfg(feature = "ncch")]
pub mod ncch;
#[cfg(feature = "smdh")]
pub mod smdh;
pub mod string;
#[cfg(feature = "cia")]
pub mod ticket;
pub mod titleid;
#[cfg(feature = "cia")]
pub mod tmd;

use core::ops::Deref;

use derive_more::{Display, Error, From};

/// Low-effort catch-all error type for cytryna library
#[non_exhaustive]
#[derive(Display, Debug, Error, From)]
pub enum CytrynaError {
    #[display(fmt = "Invalid magic bytes")]
    InvalidMagic,
    #[display(fmt = "Missing region")]
    MissingRegion,
    #[display(fmt = "Invalid size of header")]
    InvalidHeaderSize,
    #[display(fmt = "Invalid hash")]
    InvalidHash,
    #[display(fmt = "Signature corrupted/forged")]
    SignatureCorrupted,
    #[display(fmt = "Invalid region position")]
    InvalidRegionPosition,
    #[display(fmt = "Unsupported version of header")]
    UnsupportedHeaderVersion,
    #[cfg(feature = "crypto")]
    #[error(ignore)]
    #[display(fmt = "Missing {_0} key")]
    MissingKey(crypto::KeyIndex),
    #[cfg(feature = "crypto")]
    #[display(fmt = "Uninitialized keybag")]
    NoKeyBag,
    #[error(ignore)]
    #[from(ignore)]
    #[display(fmt = "Value out of range for {_0} enum")]
    EnumValueOutOfRange(&'static str),
    #[display(fmt = "Byte slice passed is too small")]
    SliceTooSmall,
    #[from(ignore)]
    #[display(fmt = "Invalid length of {what}: {actual} (expected {expected})")]
    InvalidLength{
        what: &'static str,
        actual: usize,
        expected: usize,
    },
    #[cfg(feature = "crypto")]
    #[display(fmt = "Failed to parse keyindex")]
    KeyIndexFail(crypto::KeyIndexParseError),
    #[cfg(feature = "crypto")]
    #[display(fmt = "Failed to stream-encrypt/decrypt data")]
    StreamCrypt(ctr::cipher::StreamCipherError),
    #[display(fmt = "Failed to decode hex string")]
    HexError(hex::FromHexError),
    #[display(fmt = "Incorrect alignment")]
    BadAlign,
}

pub type CytrynaResult<T> = core::result::Result<T, CytrynaError>;

/// Simple trait to implement safe conversions from bytes
pub trait FromBytes {
    /// Minimum size of byte slice for a type to be valid, it's struct size for non-DST structs and
    /// header size for DST structs
    fn min_size() -> usize;

    /// Ensures that a byte slice is valid, checking everything that needs to be chcked in order
    /// for struct to not contain invalid values for its type
    fn bytes_ok(_: &[u8]) -> CytrynaResult<()>;

    /// Casts a byte slice to Self, it's a required method because DST and non-DST references have
    /// different sizes and I wasn't able to figure out a way to not do it this way
    fn cast(_: &[u8]) -> &Self;

    /// Ensures that in-struct hash value is valid. Not required because not all structs have a
    /// field for hash value
    fn hash_ok(&self) -> bool { true }

    /// A function that brings it all together
    fn from_bytes(bytes: &[u8]) -> CytrynaResult<&Self> {
        Self::bytes_ok(bytes)?;
        let ret = Self::cast(bytes);
        if ret.hash_ok() {
            Ok(ret)
        } else {
            Err(CytrynaError::InvalidHash)
        }
    }
}

pub mod prelude {
    pub use crate::FromBytes;
    #[cfg(feature = "3dsx")]
    pub use crate::hb3dsx::Hb3dsx;
    #[cfg(feature = "cia")]
    pub use crate::cia::Cia;
    #[cfg(feature = "firm")]
    pub use crate::firm::Firm;
    #[cfg(feature = "ncch")]
    pub use crate::ncch::Ncch;
    #[cfg(feature = "smdh")]
    pub use crate::smdh::Smdh;
    #[cfg(feature = "cia")]
    pub use crate::ticket::Ticket;
}

/// Aligns a value up, used internally
///
/// # Examples
/// ```ignore
/// use cytryna::align_up;
///
/// let alignment = 0x10;
/// let val_unaligned = 0x37;
/// let val_aligned = 0x40;
///
/// assert_eq!(align_up(val_unaligned, alignment), 0x40);
/// assert_eq!(align_up(val_aligned, alignment), 0x40);
/// ```
///
pub(crate) const fn align_up(val: u32, alignment: u32) -> u32 {
    if val % alignment != 0 {
        val + (alignment - (val % alignment))
    } else {
        val
    }
}

/// Contains either a box pointer to a type, or a reference to it, used as a return type for
/// functions that may or may not decompress/decrypt data
#[derive(Debug, Clone)]
pub enum OwnedOrBorrowed<'a, T> {
    Owned(Box<T>),
    Borrowed(&'a T),
}

impl<T> Deref for OwnedOrBorrowed<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        match self {
            Self::Owned(data) => data.as_ref(),
            Self::Borrowed(data) => data,
        }
    }
}

/// Contains either a (borrowed) byte slice or an (owned) Vec, used in the the same ways
/// OwnedOrBorrowed is used, but limited to arrays
#[derive(Debug, Clone)]
pub enum VecOrSlice<'a, T> {
    V(Vec<T>),
    S(&'a [T]),
}

impl<T> VecOrSlice<'_, T> {
    /// Borrows internal value and returns a slice
    fn as_slice(&self) -> &[T] {
        match self {
            Self::V(vec) => vec,
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

#[cfg(test)]
mod tests {
    #[test]
    fn check_align_up() {
        use super::align_up;

        let alignment = 0x10;
        let val_unaligned = 0x37;
        let val_aligned = 0x40;

        assert_eq!(align_up(val_unaligned, alignment), 0x40);
        assert_eq!(align_up(val_aligned, alignment), 0x40);
    }
}
