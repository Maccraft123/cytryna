use std::{fmt, mem};

use crate::crypto::{FromBytes, SignedData};
use crate::ticket::{EcdsaSha256, Rsa2048Sha256, Rsa4096Sha256, Signature};
use crate::titleid::MaybeTitleIdBe;

use bitflags::bitflags;
use derivative::Derivative;
use redox_simple_endian::*;
use static_assertions::assert_eq_size;

#[derive(Derivative)]
#[derivative(Debug)]
#[repr(C, packed)] // TODO: remove packing and copy from fields
pub struct TmdInner {
    version: u8,
    ca_crl_version: u8,
    signer_crl_version: u8,
    #[derivative(Debug = "ignore")]
    _reserved0: u8,
    system_version: u64be,
    title_id: MaybeTitleIdBe,
    title_type: u32be,
    group_id: u16be,
    save_data_size: u32be,
    srl_private_save_size: u32be,
    #[derivative(Debug = "ignore")]
    _reserved1: u32,
    srl_flag: u8,
    #[derivative(Debug = "ignore")]
    _reserved2: [u8; 0x31],
    access_rights: u32be,
    title_version: u16be,
    content_count: u16be,
    boot_content: u16be,
    #[derivative(Debug = "ignore")]
    _padding: u16,
    hash: [u8; 0x20],
    content_info_records: [ContentInfo; 64],
    #[derivative(Debug = "ignore")]
    content_chunk_records: [ContentChunk],
}

impl FromBytes for TmdInner {
    fn bytes_ok(_: &[u8]) -> bool {
        true
    }
    fn cast(bytes: &[u8]) -> &Self {
        unsafe { mem::transmute(bytes) }
    }
}

pub type Tmd<'a> = SignedData<'a, TmdInner>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ContentChunk {
    id: u32be,
    idx: u16be,
    ty: u16be,
    size: u64be,
    hash: [u8; 0x20]
}
assert_eq_size!([u8; 0x30], ContentChunk);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ContentInfo {
    idx: ContentIndex,
    cmd_count: u16be,
    hash: [u8; 0x20],
}
assert_eq_size!([u8; 0x24], ContentInfo);

impl fmt::Debug for ContentInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.cmd_count.to_native() != 0
            || self.hash.iter().any(|v| *v != 0)
        {
            f.debug_struct("ContentInfo")
                .field("idx", &self.idx)
                .field("cmd_count", &self.cmd_count)
                .field("hash", &self.hash)
                .finish()
        } else {
            f.debug_tuple("ContentInfo")
                .field(&None::<()>)
                .finish()
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct ContentTypeFlag: u16 {
        const ENCRYPTED = 0x1;
        const DISC = 0x2;
        const CFM = 0x4;
        const OPTIONAL = 0x4000;
        const SHARED = 0x8000;
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum ContentIndex {
    Main = 0,
    Manual = 1,
    Dlp = 2,
}
