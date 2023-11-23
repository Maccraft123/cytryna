use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::mem;
use std::num;
use std::str::FromStr;
use std::sync::OnceLock;

use crate::string::SizedCString;
use crate::{CytrynaError, CytrynaResult, FromBytes};

use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod aes128_ctr {
    pub use aes::cipher::block_padding::NoPadding;
    pub use aes::cipher::BlockDecryptMut;
    pub use aes::cipher::KeyIvInit;
    pub use aes::cipher::StreamCipher;
    pub type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    pub type Aes128CtrDec = ctr::Ctr128BE<aes::Aes128>;
}

static KEY_BAG: OnceLock<KeyBag> = OnceLock::new();

/// Contains keys used for encrypting/decrypting data
#[derive(Clone, Debug)]
pub struct KeyBag {
    keys: HashMap<KeyIndex, [u8; 0x10]>,
}

impl KeyBag {
    /// Makes an instance of KeyBag
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
    /// Makes an instance of KeyBag from a string in format compatible with
    /// keys returned by <https://github.com/citra-emu/citra/raw/master/dist/dumpkeys/DumpKeys.gm9>
    ///
    /// Note that this script won't dump all keys used in this library
    #[must_use]
    pub fn from_string(string: &str) -> CytrynaResult<Self> {
        let mut this = Self::new();
        for line in string.lines() {
            if line.starts_with('#') {
                continue;
            }
            let line = line.to_lowercase();
            let Some((left, right)) = line.split_once('=') else {
                continue;
            };
            let idx: KeyIndex = left.parse()?;
            let keyvec = hex::decode(right)?;
            if keyvec.len() != 0x10 {
                return Err(CytrynaError::InvalidLength {
                    what: "key",
                    actual: keyvec.len(),
                    expected: 0x10,
                });
            }
            let key: [u8; 0x10] = keyvec.try_into().unwrap();

            this.set_key(idx, key);
        }
        Ok(this)
    }
    /// Adds a key to KeyBag, overwriting previous data if there was any
    pub fn set_key(&mut self, idx: KeyIndex, key: [u8; 0x10]) {
        self.keys.insert(idx, key);
    }
    /// Sets the KeyBag to be used for all crypto functions of this crate
    pub fn finalize(self) {
        let _ = KEY_BAG.set(self);
    }
    /// Returns a key if it is contained in global KeyBag instance
    pub fn get_key(&self, idx: KeyIndex) -> CytrynaResult<&[u8; 0x10]> {
        self.keys.get(&idx).ok_or(CytrynaError::MissingKey(idx))
    }
    /// Returns reference to the global KeyBag instance
    pub fn global() -> CytrynaResult<&'static Self> {
        KEY_BAG.get().ok_or(CytrynaError::NoKeyBag)
    }
}

/// Generates a normal-key from X and Y keys and a keygen constant
#[must_use]
pub fn keygen(x: [u8; 0x10], y: [u8; 0x10]) -> CytrynaResult<[u8; 0x10]> {
    let x = u128::from_be_bytes(x);
    let y = u128::from_be_bytes(y);
    let gen = u128::from_be_bytes(*KeyBag::global()?.get_key(KeyIndex::Generator)?);

    Ok(((x.rotate_left(2) ^ y).wrapping_add(gen))
        .rotate_right(41)
        .to_be_bytes())
}

/// Is this self-documenting? I think it is
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum KeyIndex {
    /// The generator key
    Generator,
    /// Key contained in 3DS's AES slot
    Slot(u8, KeyType),
    /// Index for common keyY used in Title Key decryption
    Common(u8),
    /// Index for common normal-key used in Title Key decryption
    CommonN(u8),
}

impl fmt::Display for KeyIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string = match self {
            Self::Generator => "generator".to_string(),
            Self::Slot(num, ty) => format!("slot0x{num:X}Key{ty}"),
            Self::Common(num) => format!("common{num}"),
            Self::CommonN(num) => format!("common{num}N"),
        };
        f.write_str(&string)
    }
}

/// An error type for KeyIndex parsing
#[derive(Error, Debug)]
pub enum KeyIndexParseError {
    #[error("Failed to parse a hex number")]
    NumberParseError(#[from] num::ParseIntError),
    #[error("Invalid key type \"{0}\"")]
    InvalidKeyType(String),
    #[error("Invalid X/Y/Z key type \"{0}\"")]
    InvalidKeyXYNType(String),
}

impl FromStr for KeyIndex {
    type Err = KeyIndexParseError;

    fn from_str(from: &str) -> Result<Self, KeyIndexParseError> {
        if from == "generator" {
            Ok(Self::Generator)
        } else if from.starts_with("slot") {
            let from = from.trim_start_matches("slot").trim_start_matches("0x");
            let num = u8::from_str_radix(&from[..2], 16)?;
            let keytype = match &from[2..] {
                "keyx" => KeyType::X,
                "keyy" => KeyType::Y,
                "keyn" => KeyType::N,
                _ => return Err(KeyIndexParseError::InvalidKeyXYNType(from[2..].to_string())),
            };
            Ok(Self::Slot(num, keytype))
        } else if from.starts_with("common") {
            let from = from.trim_start_matches("common");
            let num = u8::from_str_radix(from.get(0..1).unwrap(), 16)?;
            let has_n = from.ends_with('n');
            if has_n {
                Ok(Self::Common(num))
            } else {
                Ok(Self::CommonN(num))
            }
        } else {
            Err(KeyIndexParseError::InvalidKeyType(from.to_string()))
        }
    }
}

/// Type of a 3DS key
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum KeyType {
    /// KeyX
    X,
    /// KeyY
    Y,
    /// Normal-key
    N,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string = match self {
            Self::X => "X",
            Self::Y => "Y",
            Self::N => "N",
        };
        f.write_str(string)
    }
}

/// Computes sha data of a byte slice
pub fn sha256(data: &[u8]) -> [u8; 0x20] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Contains signed data in a way that is generic over signed data type and signature type
#[repr(C)]
pub struct SignedDataInner<T: ?Sized + FromBytes + fmt::Debug, S: Signature> {
    _unused: PhantomData<T>,
    sig_type: SignatureType,
    signature: S,
    sig_issuer: SizedCString<0x40>,
    data: [u8],
}

impl<T: ?Sized + FromBytes + fmt::Debug, S: Signature> SignedDataInner<T, S> {
    /// Returns stored data
    #[must_use]
    pub fn data(&self) -> &T {
        T::cast(&self.data)
    }
}

impl<T, S> fmt::Debug for SignedDataInner<T, S>
where
    T: ?Sized + FromBytes + fmt::Debug,
    S: Signature,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SignedDataInner")
            .field("sig_type", &self.sig_type)
            .field("signature", &"skipped")
            .field("sig_issuer", &self.sig_issuer)
            .field("data", &T::cast(&self.data))
            .finish()
    }
}

/// Stores SignedDataInner in a way that makes it possible to use as a return type of a function
pub enum SignedData<'a, T: ?Sized + FromBytes + fmt::Debug> {
    Rsa4096Sha256(&'a SignedDataInner<T, Rsa4096Sha256>),
    Rsa2048Sha256(&'a SignedDataInner<T, Rsa2048Sha256>),
    EcdsaSha256(&'a SignedDataInner<T, EcdsaSha256>),
}

impl<T> fmt::Debug for SignedData<'_, T>
where
    T: ?Sized + FromBytes + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Rsa4096Sha256(inner) => f.debug_tuple("Rsa4096Sha256").field(inner).finish(),
            Self::Rsa2048Sha256(inner) => f.debug_tuple("Rsa2048Sha256").field(inner).finish(),
            Self::EcdsaSha256(inner) => f.debug_tuple("EcdsaSha256").field(inner).finish(),
        }
    }
}

impl<T: ?Sized + FromBytes + fmt::Debug> SignedData<'_, T> {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> CytrynaResult<SignedData<T>> {
        unsafe {
            if bytes[0] != 0x0
                || bytes[1] != 0x1
                || bytes[2] != 0x0
                || bytes[3] >= 0x06
                || bytes[3] <= 0x02
            {
                return Err(CytrynaError::InvalidMagic);
            }

            let sig_size = match bytes[3] {
                0x03 => mem::size_of::<Rsa4096Sha256>(),
                0x04 => mem::size_of::<Rsa2048Sha256>(),
                0x05 => mem::size_of::<EcdsaSha256>(),
                _ => unreachable!("Already checked if it's in range"),
            };
            let offset = sig_size + mem::size_of::<SignatureType>() + 0x40;

            T::bytes_ok(&bytes[offset..])?;

            match bytes[3] {
                0x03 => Ok(SignedData::Rsa4096Sha256(mem::transmute(bytes))),
                0x04 => Ok(SignedData::Rsa2048Sha256(mem::transmute(bytes))),
                0x05 => Ok(SignedData::EcdsaSha256(mem::transmute(bytes))),
                _ => unreachable!("Already checked if it's in range"),
            }
        }
    }
    /// Returns a reference to data stored inside
    #[must_use]
    pub fn data(&self) -> &T {
        match self {
            Self::Rsa4096Sha256(inner) => T::cast(&inner.data),
            Self::Rsa2048Sha256(inner) => T::cast(&inner.data),
            Self::EcdsaSha256(inner) => T::cast(&inner.data),
        }
    }
}

/// Stores signature type of TMD and Ticket structs in a little-endian way
#[derive(Copy, Clone, Debug)]
#[repr(u32)]
pub enum SignatureType {
    Rsa4096Sha256 = 0x03000100,
    Rsa2048Sha256 = 0x04000100,
    EcdsaSha256 = 0x05000100,
}

pub trait Signature: sealed_impl::Sealed {}

/// RSA_4096 SHA256 signature data, including padding
#[repr(C, packed)]
pub struct Rsa4096Sha256 {
    sig: [u8; 0x200],
    pad: [u8; 0x3c],
}
impl Signature for Rsa4096Sha256 {}

/// RSA_2048 SHA256 signature data, including padding
#[repr(C, packed)]
pub struct Rsa2048Sha256 {
    sig: [u8; 0x100],
    pad: [u8; 0x3c],
}
impl Signature for Rsa2048Sha256 {}

/// ECDSA with SHA256 signature data, including padding
#[repr(C, packed)]
pub struct EcdsaSha256 {
    sig: [u8; 0x3c],
    pad: [u8; 0x40],
}
impl Signature for EcdsaSha256 {}

mod sealed_impl {
    pub trait Sealed {}
    impl Sealed for super::Rsa4096Sha256 {}
    impl Sealed for super::Rsa2048Sha256 {}
    impl Sealed for super::EcdsaSha256 {}
}

#[cfg(test)]
mod tests {
    use super::{KeyBag, KeyIndex};
    #[test]
    fn test_keygen() {
        // https://www.random.org/cgi-bin/randbyte?nbytes=16&format=h
        const RANDOM_GENERATOR: [u8; 0x10] = [
            0x12, 0x59, 0x9a, 0x14, 0xff, 0x66, 0xda, 0x9f, 0x65, 0xc1, 0x3e, 0xad, 0x30, 0x50,
            0x15, 0xc7,
        ];
        const RANDOM_X: [u8; 0x10] = [
            0xfa, 0xfe, 0x20, 0x7b, 0xb2, 0x3c, 0xa4, 0x30, 0x16, 0x2a, 0x65, 0xf6, 0xd3, 0xff,
            0x50, 0x40,
        ];
        const RANDOM_Y: [u8; 0x10] = [
            0x82, 0x48, 0x62, 0xde, 0xd5, 0xc6, 0xd5, 0x99, 0x23, 0x05, 0x19, 0xf5, 0x2d, 0x27,
            0x56, 0xa8,
        ];
        const REFERENCE_KEY: [u8; 0x10] = [
            0x6d, 0xc9, 0x95, 0x16, 0xb9, 0x3e, 0x05, 0x3e, 0xa2, 0x8e, 0x4d, 0x8f, 0xfc, 0x70,
            0xb6, 0xe6,
        ];

        let mut bag = KeyBag::new();
        bag.set_key(KeyIndex::Generator, RANDOM_GENERATOR);
        bag.finalize();

        assert_eq!(super::keygen(RANDOM_X, RANDOM_Y).unwrap(), REFERENCE_KEY);
    }
}
