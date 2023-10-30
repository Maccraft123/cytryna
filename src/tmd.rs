use std::mem;

use crate::titleid::MaybeTitleIdBe;

use derivative::Derivative;
use redox_simple_endian::*;

#[derive(Derivative)]
#[derivative(Debug)]
#[repr(C, packed)]
pub struct TmdInner<S: Signature> {
    sig_type: u32be,
    #[derivative(Debug="ignore")] sig: S, // includes padding
    sig_issuer: [u8; 0x40],
    version: u8,
    ca_crl_version: u8,
    signer_crl_version: u8,
    #[derivative(Debug="ignore")] _reserved0: u8,
    system_vresion: u64,
    title_id: MaybeTitleIdBe,
    group_id: u16be,
    save_data_size: u32,
    srl_private_save_size: u32,
    #[derivative(Debug="ignore")] _reserved1: u32,
    srl_flag: u8,
    #[derivative(Debug="ignore")] _reserved2: [u8; 0x31],
    access_rights: u32be,
    title_version: u16be,
    content_count: u16be,
    boot_content: u16be,
    #[derivative(Debug="ignore")] _padding: u16,
    hash: [u8; 0x20],
    #[derivative(Debug="ignore")] content_info_records: [u8; 0x24*60],
    #[derivative(Debug="ignore")] content_chunk_records: [u8],
}

#[derive(Debug, Clone)]
pub enum Tmd<'t> {
    Rsa4096Sha256(&'t TmdInner<Rsa4096Sha256>),
    Rsa2048Sha256(&'t TmdInner<Rsa2048Sha256>),
    EcdsaSha256(&'t TmdInner<EcdsaSha256>),
}

impl Tmd<'_> {
    pub fn from_bytes(bytes: &[u8]) -> Option<Tmd> {
        // NOTE: alignment of TmdInner HAS TO BE 1
        unsafe {
            let sig_ty = (bytes[0], bytes[1], bytes[2], bytes[3]);
            match sig_ty {
                (0x00, 0x01, 0x00, 0x03) => Some(Tmd::Rsa4096Sha256(mem::transmute(bytes))),
                (0x00, 0x01, 0x00, 0x04) => Some(Tmd::Rsa2048Sha256(mem::transmute(bytes))),
                (0x00, 0x01, 0x00, 0x05) => Some(Tmd::EcdsaSha256(mem::transmute(bytes))),
                _ => None,
            }
        }
    }
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

