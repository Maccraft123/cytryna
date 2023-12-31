use core::mem;

use crate::crypto::aes128_ctr::*;
#[cfg(feature = "smdh")]
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

/// CIA Header data
/// <https://www.3dbrew.org/wiki/CIA#CIA_Header>
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

/// CIA data
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
    /// Returns a reference to CIA header
    #[must_use]
    pub fn header(&self) -> &CiaHeader {
        &self.header
    }
    /// Returns a referene to certificate chain region as a slice.
    /// Return type of this function will be changed when CertificateChain struct is added.
    ///
    /// <https://www.3dbrew.org/wiki/CIA#Certificate_Chain>
    #[must_use]
    pub fn cert_chain_region(&self) -> &[u8] {
        &self.data[..align(self.header.cert_size)]
    }
    /// Returns a reference to Ticket region
    pub fn ticket_region(&self) -> CytrynaResult<Ticket> {
        let offset = align(self.header.cert_size);
        Ticket::from_bytes(&self.data[offset..][..align(self.header.ticket_size)])
    }
    /// Returns a reference to Title metadata region
    pub fn tmd_region(&self) -> CytrynaResult<Tmd> {
        let offset =
            align(self.header.cert_size) + align(self.header.ticket_size);
        //Some(unsafe { mem::transmute(&self.data[offset..][..align(self.header.tmd_size)]) })
        Tmd::from_bytes(&self.data[offset..][..align(self.header.tmd_size)])
    }
    /// Returns an iterator over contents
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
    /// If CIA has a Meta region, returns a reference to it, otherwise None is returned
    #[must_use]
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

/// Content region data
pub struct ContentRegion<'a> {
    data: VecOrSlice<'a, u8>,
    idx: ContentIndex,
}

impl ContentRegion<'_> {
    /// Returns a reference to data contained within
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }
    /// Returns the content index of this region
    #[must_use]
    pub fn idx(&self) -> ContentIndex {
        self.idx
    }
}

/// An iterator over content data, possibly decrypting them
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

/// CIA Meta region
///
/// <https://www.3dbrew.org/wiki/CIA#Meta>
#[repr(C)]
pub struct MetaRegion {
    dependencies: [MaybeTitleId; 0x30],
    _reserved0: [u8; 0x180],
    core_version: u32,
    _reserved1: [u8; 0xfc],
    icon: [u8; 0x36c0], // mem::size_of::<Smdh>(),
}
assert_eq_size!([u8; 0x3ac0], MetaRegion);

impl MetaRegion {
    /// Returns dependencies as an array of MaybeTitleId
    #[must_use]
    pub fn dependencies(&self) -> [MaybeTitleId; 0x30] {
        self.dependencies
    }
    /// Returns an iterator over TitleId structs, skipping dependency fields that aren't used
    pub fn dependencies_iter(&self) -> impl Iterator<Item = TitleId> {
        let copy = self.dependencies;
        copy.into_iter().filter_map(|v| v.to_titleid().ok())
    }
    /// Returns SMDH data contained in this region
    #[cfg(feature = "smdh")]
    pub fn icon(&self) -> CytrynaResult<&Smdh> {
        Smdh::from_bytes(&self.icon)
    }
}
