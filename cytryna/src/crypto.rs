use std::sync::OnceLock;
use std::collections::HashMap;
use std::mem;
use std::marker::PhantomData;
use std::fmt;

use crate::string::SizedCString;
use crate::{CytrynaError, Result};

pub mod aes128_ctr {
    pub use aes::cipher::block_padding::NoPadding;
    pub use aes::cipher::KeyIvInit;
    pub use aes::cipher::BlockDecryptMut;
    pub type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
}

static KEY_BAG: OnceLock<KeyBag> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct KeyBag {
    keys: HashMap<KeyIndex, [u8; 0x10]>,
}

impl KeyBag {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new()
        }
    }
    pub fn set_key(&mut self, idx: KeyIndex, key: [u8; 0x10]) {
        self.keys.insert(idx, key);
    }
    pub fn finalize(self) {
        let _ = KEY_BAG.set(self);
    }
    pub fn get_key(&self, idx: KeyIndex) -> Result<&[u8; 0x10]> {
        self.keys.get(&idx).ok_or(CytrynaError::MissingKey(idx))
    }
    pub fn global() -> Result<&'static Self> {
        KEY_BAG.get().ok_or(CytrynaError::NoKeyBag)
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum KeyIndex {
    Generator,
    Slot(u8, KeyType),
    Common(u8),
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

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum KeyType {
    X,
    Y,
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

pub trait FromBytes {
    fn bytes_ok(_: &[u8]) -> Result<()>;
    fn cast(_: &[u8]) -> &Self;
}

#[repr(C)]
pub struct SignedDataInner<T: ?Sized + FromBytes + fmt::Debug, S: Signature> {
    _unused: PhantomData<T>,
    sig_type: SignatureType,
    signature: S,
    sig_issuer: SizedCString<0x40>,
    data: [u8],
}

impl<T: ?Sized + FromBytes + fmt::Debug, S: Signature> SignedDataInner<T, S> {
    pub fn data(&self) -> &T { T::cast(&self.data) }
}

impl<T, S> fmt::Debug for SignedDataInner<T, S>
where
    T: ?Sized + FromBytes + fmt::Debug, S: Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SignedDataInner")
            .field("sig_type", &self.sig_type)
            .field("signature", &"skipped")
            .field("sig_issuer", &self.sig_issuer)
            .field("data", &T::cast(&self.data))
            .finish()
    }
}

pub enum SignedData<'a, T: ?Sized + FromBytes + fmt::Debug> {
    Rsa4096Sha256(&'a SignedDataInner<T, Rsa4096Sha256>),
    Rsa2048Sha256(&'a SignedDataInner<T, Rsa2048Sha256>),
    EcdsaSha256(&'a SignedDataInner<T, EcdsaSha256>),
}

impl<T> fmt::Debug for SignedData<'_, T>
    where T: ?Sized + FromBytes + fmt::Debug
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Rsa4096Sha256(inner) => {
                f.debug_tuple("Rsa4096Sha256")
                    .field(inner)
                    .finish()
            },
            Self::Rsa2048Sha256(inner) => {
                f.debug_tuple("Rsa2048Sha256")
                    .field(inner)
                    .finish()
            },
            Self::EcdsaSha256(inner) => {
                f.debug_tuple("EcdsaSha256")
                    .field(inner)
                    .finish()
            },
        }
    }
}

impl<T: ?Sized + FromBytes + fmt::Debug> SignedData<'_, T> {
    pub fn from_bytes(bytes: &[u8]) -> Result<SignedData<T>> {
        unsafe {
            if bytes[0] != 0x0 || bytes[1] != 0x1 || bytes[2] != 0x0 || bytes[3] >= 0x06 || bytes[3] <= 0x02 {
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
    pub fn data(&self) -> &T {
        match self {
            Self::Rsa4096Sha256(inner) => T::cast(&inner.data),
            Self::Rsa2048Sha256(inner) => T::cast(&inner.data),
            Self::EcdsaSha256(inner) => T::cast(&inner.data),
        }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(u32)]
pub enum SignatureType {
    Rsa4096Sha256 = 0x03000100,
    Rsa2048Sha256 = 0x04000100,
    EcdsaSha256 = 0x05000100,
}

#[allow(private_bounds)]
pub trait Signature: Sealed {}

trait Sealed {}

#[repr(C, packed)]
pub struct Rsa4096Sha256 {
    sig: [u8; 0x200],
    pad: [u8; 0x3c],
}
impl Sealed for Rsa4096Sha256 {}
impl Signature for Rsa4096Sha256 {}

#[repr(C, packed)]
pub struct Rsa2048Sha256 {
    sig: [u8; 0x100],
    pad: [u8; 0x3c],
}
impl Sealed for Rsa2048Sha256 {}
impl Signature for Rsa2048Sha256 {}

#[repr(C, packed)]
pub struct EcdsaSha256 {
    sig: [u8; 0x3c],
    pad: [u8; 0x40],
}
impl Sealed for EcdsaSha256 {}
impl Signature for EcdsaSha256 {}
