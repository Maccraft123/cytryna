use std::mem;

use crate::titleid::MaybeTitleIdBe;
use crate::string::SizedCString;
use crate::crypto::{KeyIndex, KeyBag, Aes128CbcDec};
use aes::cipher::block_padding::NoPadding;
use cbc::cipher::{KeyIvInit, BlockDecryptMut};

use derivative::Derivative;
use redox_simple_endian::*;
use static_assertions::assert_eq_size;

#[repr(C, packed)]
pub struct TicketInner<S: Signature> {
    sig_type: u32be,
    sig: S,
    data: TicketData,
    content_index: [u8],
}

#[derive(Derivative)]
#[derivative(Debug)]
#[repr(C, packed)]
pub struct TicketData {
    #[derivative(Debug="ignore")] issuer: SizedCString<0x40>,
    ecc_pubkey: [u8; 0x3c],
    version: u8,
    ca_crl_version: u8,
    signer_crl_version: u8,
    title_key: [u8; 0x10],
    #[derivative(Debug="ignore")] _reserved0: u8,
    ticket_id: u64be,
    console_id: u32be,
    title_id: MaybeTitleIdBe,
    #[derivative(Debug="ignore")] _reserved1: [u8; 0x2],
    ticket_title_version: u16be,
    #[derivative(Debug="ignore")] _reserved2: [u8; 0x8],
    license_type: u8,
    key_index: u8,
    #[derivative(Debug="ignore")] _reserved3: [u8; 0x2a],
    maybe_eshop_account_id: u32be,
    #[derivative(Debug="ignore")] _reserved4: u8,
    audit: u8,
    #[derivative(Debug="ignore")] _reserved5: [u8; 0x42],
    limits: [u8; 0x40],
}
assert_eq_size!([u8; 0x164], TicketData);

pub enum Ticket<'t> {
    Rsa4096Sha256(&'t TicketInner<Rsa4096Sha256>),
    Rsa2048Sha256(&'t TicketInner<Rsa2048Sha256>),
    EcdsaSha256(&'t TicketInner<EcdsaSha256>),
}

impl Ticket<'_> {
    pub fn from_bytes(bytes: &[u8]) -> Option<Ticket> {
        // NOTE: alignment of TicketInner HAS TO BE 1
        unsafe {
            let sig_ty = (bytes[0], bytes[1], bytes[2], bytes[3]);
            match sig_ty {
                (0x00, 0x01, 0x00, 0x03) => Some(Ticket::Rsa4096Sha256(mem::transmute(bytes))),
                (0x00, 0x01, 0x00, 0x04) => Some(Ticket::Rsa2048Sha256(mem::transmute(bytes))),
                (0x00, 0x01, 0x00, 0x05) => Some(Ticket::EcdsaSha256(mem::transmute(bytes))),
                _ => None,
            }
        }
    }
    pub fn data(&self) -> &TicketData {
        match self {
            Self::Rsa4096Sha256(t) => &t.data,
            Self::Rsa2048Sha256(t) => &t.data,
            Self::EcdsaSha256(t) => &t.data,
        }
    }
    pub fn title_key(&self) -> Option<[u8; 0x10]> {
        let mut iv = [0u8; 0x10];
        iv[..0x8].copy_from_slice(&self.data().title_id.to_bytes());

        let mut title_key = self.data().title_key;
        let idx = self.data().key_index;
        let key = KeyBag::global()?.get_key(KeyIndex::CommonN(idx))?;

        Aes128CbcDec::new(key.into(), &iv.into())
            .decrypt_padded_mut::<NoPadding>(&mut title_key).ok()?;
        Some(title_key)
    }
    pub fn issuer(&self) -> &SizedCString<0x40> { &self.data().issuer }
    pub fn title_key_raw(&self) -> &[u8; 0x10] { &self.data().title_key }
    pub fn key_index(&self) -> u8 { self.data().key_index }
}

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
