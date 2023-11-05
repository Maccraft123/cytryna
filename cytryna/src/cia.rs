use std::mem;

use crate::crypto::aes128_ctr::*;
use crate::smdh::Smdh;
use crate::ticket::Ticket;
use crate::titleid::{MaybeTitleId, TitleId};
use crate::tmd::{self, ContentIndex, Tmd};
use crate::{CytrynaError, CytrynaResult, VecOrSlice, FromBytes};

use derivative::Derivative;
use memoffset::span_of;
use static_assertions::assert_eq_size;

const fn align(what: u32) -> usize {
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
    #[derivative(Debug = "ignore")]
    content_index: [u8; 0x2000],
}
assert_eq_size!([u8; 0x2020], CiaHeader);

const HDR_PAD: usize = align(mem::size_of::<CiaHeader>() as u32) - mem::size_of::<CiaHeader>();

#[repr(C)]
pub struct Cia {
    header: CiaHeader,
    pad: [u8; HDR_PAD],
    data: [u8],
}

impl FromBytes for Cia {
    fn min_size() -> usize {
        mem::size_of::<CiaHeader>()
    }
    fn cast(bytes: &[u8]) -> &Cia {
        unsafe { mem::transmute(bytes) }
    }
    fn bytes_ok(bytes: &[u8]) -> CytrynaResult<()> {
        let hdr_size_span = span_of!(CiaHeader, hdr_size);
        let hdr_size = u32::from_le_bytes(bytes[hdr_size_span].try_into().unwrap());
        if hdr_size != mem::size_of::<CiaHeader>() as u32 {
            return Err(CytrynaError::InvalidHeaderSize);
        }

        Ok(())
    }
}

impl Cia {
    pub fn header(&self) -> &CiaHeader {
        &self.header
    }
    pub fn cert_chain_region(&self) -> &[u8] {
        &self.data[..align(self.header.cert_size)]
    }
    pub fn ticket_region(&self) -> CytrynaResult<Ticket> {
        let offset = align(self.header.cert_size);
        Ticket::from_bytes(&self.data[offset..][..align(self.header.ticket_size)])
    }
    pub fn tmd_region(&self) -> CytrynaResult<Tmd> {
        let offset =
            align(self.header.cert_size) + align(self.header.ticket_size);
        //Some(unsafe { mem::transmute(&self.data[offset..][..align(self.header.tmd_size)]) })
        Tmd::from_bytes(&self.data[offset..][..align(self.header.tmd_size)])
    }
    pub fn content_region(&self) -> CytrynaResult<ContentRegionIter> {
        let offset = align(self.header.cert_size)
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
            let offset = align(self.header.cert_size)
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
    data: VecOrSlice<'a, u8>,
    idx: ContentIndex,
}

impl ContentRegion<'_> {
    pub fn data(&self) -> &[u8] { &self.data.as_slice() }
    pub fn idx(&self) -> ContentIndex {
        self.idx
    }
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
            data = VecOrSlice::V(
                Aes128CbcDec::new(&self.title_key.into(), &iv.into())
                    .decrypt_padded_vec_mut::<NoPadding>(
                        &self.buf[self.offset..chunk.size() as usize],
                    )
                    .ok()?,
            );
        } else {
            data = VecOrSlice::S(&self.buf[self.offset..chunk.size() as usize])
        }

        self.chunk_idx += 1;
        Some(ContentRegion { data, idx })
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
    pub fn dependencies(&self) -> [MaybeTitleId; 0x30] {
        self.dependencies
    }
    pub fn dependencies_iter(&self) -> impl Iterator<Item = TitleId> {
        let copy = self.dependencies;
        copy.into_iter().filter_map(|v| v.to_titleid().ok())
    }
    pub fn icon(&self) -> CytrynaResult<&Smdh> {
        Smdh::from_bytes(&self.icon)
    }
}
