use core::{fmt, mem, ptr, slice};

use crate::crypto::SignedData;
use crate::titleid::{MaybeTitleIdBe, TitleId};
use crate::{CytrynaResult, FromBytes};

use bitflags::bitflags;
use derivative::Derivative;
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
    system_version: [u8; 0x8],
    title_id: MaybeTitleIdBe,
    title_type: [u8; 0x4],
    group_id: [u8; 0x2],
    save_data_size: [u8; 0x4],
    srl_private_save_size: [u8; 0x4],
    #[derivative(Debug = "ignore")]
    _reserved1: u32,
    srl_flag: u8,
    #[derivative(Debug = "ignore")]
    _reserved2: [u8; 0x31],
    access_rights: [u8; 0x4],
    title_version: [u8; 0x2],
    content_count: [u8; 0x2],
    boot_content: [u8; 0x2],
    #[derivative(Debug = "ignore")]
    _padding: u16,
    hash: [u8; 0x20],
    content_info_records: [ContentInfo; 64],
    #[derivative(Debug = "ignore")]
    content_chunk_records: [ContentChunk],
}

impl FromBytes for TmdInner {
    fn min_size() -> usize {
        // https://www.3dbrew.org/wiki/Title_metadata#Header
        0x64
    }
    // TODO: check validity of content indexes
    fn bytes_ok(_: &[u8]) -> CytrynaResult<()> {
        Ok(())
    }
    fn cast(bytes: &[u8]) -> &Self {
        unsafe { mem::transmute(bytes) }
    }
}

pub type Tmd<'a> = SignedData<'a, TmdInner>;

impl<'a> Tmd<'a> {
    #[must_use]
    pub fn title_id(&self) -> CytrynaResult<TitleId> {
        self.data().title_id.to_titleid()
    }
    #[must_use]
    pub fn content_count(&self) -> u16 {
        u16::from_be_bytes(self.data().content_count)
    }
    #[must_use]
    pub fn content_chunks(&self) -> &[ContentChunk] {
        let ptr = ptr::addr_of!(self.data().content_chunk_records);
        let amount = self.content_count();
        assert_eq!(
            ptr as *const u8 as usize % mem::align_of::<ContentChunk>(),
            0
        );

        unsafe { slice::from_raw_parts(ptr as *const ContentChunk, amount as usize) }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ContentIndex {
    Main = 0,
    Manual = 1,
    Dlp = 2,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ContentChunk {
    id: [u8; 0x4],
    _pad: u8,
    idx: ContentIndex,
    ty: [u8; 0x2],
    size: [u8; 8], // actually u64be
    hash: [u8; 0x20],
}
assert_eq_size!([u8; 0x30], ContentChunk);

impl ContentChunk {
    #[must_use]
    pub fn id(&self) -> u32 {
        u32::from_be_bytes(self.id)
    }
    #[must_use]
    pub fn idx(&self) -> ContentIndex {
        self.idx
    }
    #[must_use]
    pub fn ty(&self) -> ContentType {
        ContentType::from_bits_retain(u16::from_be_bytes(self.ty))
    }
    #[must_use]
    pub fn size(&self) -> u64 {
        u64::from_be_bytes(self.size)
    }
    #[must_use]
    pub fn hash(&self) -> &[u8; 0x20] {
        &self.hash
    }
    #[must_use]
    pub fn is_nil(&self) -> bool {
        self.ty == [0, 0] && self.size == [0; 8] && self.hash.iter().all(|v| *v == 0)
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ContentInfo {
    _pad: u8,
    idx: ContentIndex,
    cmd_count: [u8; 0x2],
    hash: [u8; 0x20],
}
assert_eq_size!([u8; 0x24], ContentInfo);

impl fmt::Debug for ContentInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.cmd_count != [0, 0] || self.hash.iter().any(|v| *v != 0) {
            f.debug_struct("ContentInfo")
                .field("idx", &self.idx)
                .field("cmd_count", &self.cmd_count)
                .field("hash", &self.hash)
                .finish()
        } else {
            f.debug_tuple("ContentInfo").field(&None::<()>).finish()
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct ContentType: u16 {
        const ENCRYPTED = 0x1;
        const DISC = 0x2;
        const CFM = 0x4;
        const OPTIONAL = 0x4000;
        const SHARED = 0x8000;
    }
}
