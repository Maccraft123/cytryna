use std::mem;

use derivative::Derivative;
use static_assertions::assert_eq_size;

use crate::crypto::aes128_ctr::*;
use crate::titleid::{TitleId, MaybeTitleId};
use crate::ticket::Ticket;
use crate::tmd::{self, ContentIndex, Tmd};
use crate::smdh::Smdh;
use crate::{CytrynaError, Result};

fn align(what: u32) -> usize {
    if what % 0x40 != 0 {
        (what + (0x40 - (what % 0x40))) as usize
    } else {
        what as usize
    }
}

#[derive(Derivative, Clone)]
#[derivative(Debug)]
#[repr(C)]
pub struct CiaHeader {
    hdr_size: u32,
    ty: u16,
    version: u16,
    cert_size: u32,
    ticket_size: u32,
    tmd_size: u32,
    meta_size: u32,
    content_size: u64,
    #[derivative(Debug = "ignore")] content_index: [u8; 0x2000],
}
assert_eq_size!([u8; 0x2020], CiaHeader);

#[repr(C)]
pub struct Cia {
    header: CiaHeader,
    data: [u8],
}

impl Cia {
    fn looks_ok(&self) -> Result<()> {
        if self.header.hdr_size != mem::size_of::<CiaHeader>() as u32 {
            Err(CytrynaError::InvalidHeaderSize)
        } else {
            Ok(())
        }
    }
    pub fn header(&self) -> &CiaHeader {
        &self.header
    }
    fn hdr_offset() -> usize {
        // including alignment, however, self.data doesn't include header
        // so we have to subtract unaligned header size
        align(mem::size_of::<CiaHeader>() as u32) - mem::size_of::<CiaHeader>()
    }
    pub fn from_slice(what: &[u8]) -> Result<&Self> {
        let alignment = mem::align_of::<CiaHeader>();
        assert_eq!(0, what.as_ptr().align_offset(alignment));

        let me: &Cia = unsafe { mem::transmute(what) };
        me.looks_ok()?;
        Ok(me)
    }

    pub fn cert_chain_region(&self) -> &[u8] {
        &self.data[Self::hdr_offset()..][..align(self.header.cert_size)]
    }
    pub fn ticket_region(&self) -> Result<Ticket> {
        let offset = Self::hdr_offset() + align(self.header.cert_size);
        Ticket::from_bytes(&self.data[offset..][..align(self.header.ticket_size)])
    }
    pub fn tmd_region(&self) -> Result<Tmd> {
        let offset =
            Self::hdr_offset() + align(self.header.cert_size) + align(self.header.ticket_size);
        //Some(unsafe { mem::transmute(&self.data[offset..][..align(self.header.tmd_size)]) })
        Tmd::from_bytes(&self.data[offset..][..align(self.header.tmd_size)])
    }
    pub fn content_region(&self) -> Result<ContentRegionIter> {
        let offset = Self::hdr_offset()
            + align(self.header.cert_size)
            + align(self.header.ticket_size)
            + align(self.header.tmd_size);
        let title_key = self.ticket_region()?.title_key()?;
        let tmd = self.tmd_region()?;
        Ok(ContentRegionIter {
            tmd,
            title_key,
            buf: &self.data[offset..][..align(self.header.content_size as u32)],
            offset: 0,
            chunk_idx: 0,
        })
    }
    pub fn meta_region(&self) -> Option<&MetaRegion> {
        if self.header.meta_size != 0 {
            let offset = Self::hdr_offset()
                + align(self.header.cert_size)
                + align(self.header.ticket_size)
                + align(self.header.tmd_size)
                + align(self.header.content_size as u32);
            assert_eq!(self.header.meta_size as usize, mem::size_of::<MetaRegion>());
            unsafe {
                let ptr = self.data[offset..][..align(self.header.meta_size)].as_ptr();
                Some((ptr as *const MetaRegion).as_ref().unwrap())
            }
        } else {
            None
        }
    }
}

pub struct ContentRegion<'a> {
    data: ContentData<'a>,
    idx: ContentIndex
}

impl ContentRegion<'_> {
    pub fn data(&self) -> &[u8] {
        match &self.data {
            ContentData::Decrypted(vec) => vec.as_slice(),
            ContentData::Unencrypted(slice) => slice,
        }
    }
    pub fn idx(&self) -> ContentIndex { self.idx }
}

pub enum ContentData<'a> {
    Decrypted(Vec<u8>),
    Unencrypted(&'a [u8]),
}

pub struct ContentRegionIter<'a> {
    tmd: Tmd<'a>,
    title_key: [u8; 0x10],
    buf: &'a [u8],
    offset: usize,
    chunk_idx: u16,
}

impl<'a> Iterator for ContentRegionIter<'a> {
    type Item = ContentRegion<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let chunks = self.tmd.content_chunks();
        let chunk = chunks[self.chunk_idx as usize];
        let idx = chunk.idx();
        let data;

        if chunk.ty().contains(tmd::ContentType::ENCRYPTED) {
            let mut iv = [0u8; 0x10];
            iv[0] = idx as u8;
            data = ContentData::Decrypted(Aes128CbcDec::new(&self.title_key.into(), &iv.into())
                .decrypt_padded_vec_mut::<NoPadding>(&self.buf[self.offset..chunk.size() as usize]).ok()?);
        } else {
            data = ContentData::Unencrypted(&self.buf[self.offset..chunk.size() as usize])
        }
        
        self.chunk_idx += 1;
        Some(ContentRegion { data, idx})
    }
}

#[repr(C)]
pub struct MetaRegion {
    dependencies: [MaybeTitleId; 0x30],
    _reserved0: [u8; 0x180],
    core_version: u32,
    _reserved1: [u8; 0xfc],
    icon: [u8; mem::size_of::<Smdh>()],
}
assert_eq_size!([u8; 0x3ac0], MetaRegion);

impl MetaRegion {
    pub fn dependencies(&self) -> [MaybeTitleId; 0x30] { self.dependencies }
    pub fn dependencies_iter(&self) -> impl Iterator<Item = TitleId> {
        let copy = self.dependencies;
        copy.into_iter()
            .filter_map(|v| v.to_titleid().ok())
    }
    pub fn icon(&self) -> Result<&Smdh> {
        Smdh::from_slice(&self.icon)
    }
}
