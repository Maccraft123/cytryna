use std::mem;

use derivative::Derivative;
use static_assertions::assert_eq_size;

use crate::titleid::{TitleId, MaybeTitleId};
use crate::tmd::Tmd;
use crate::smdh::Smdh;

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
    #[derivative(Debug="ignore")] content_index: [u8; 0x2000],
}
assert_eq_size!([u8; 0x2020], CiaHeader);

#[repr(C)]
pub struct Cia {
    header: CiaHeader,
    data: [u8],
}

impl Cia {
    pub fn looks_ok(&self) -> bool {
        self.header.hdr_size == mem::size_of::<CiaHeader>() as u32
    }
    pub fn header(&self) -> &CiaHeader {
        &self.header
    }
    fn hdr_offset() -> usize {
        // including alignment, however, self.data doesn't include header
        // so we have to subtract unaligned header size
        align(mem::size_of::<CiaHeader>() as u32) - mem::size_of::<CiaHeader>()
    }
    pub fn from_slice(what: &[u8]) -> &Self {
        let alignment = mem::align_of::<CiaHeader>();
        assert_eq!(0, what.as_ptr().align_offset(alignment));

        let me: &Cia = unsafe { mem::transmute(what) };
        assert!(me.looks_ok());
        me
    }

    pub fn cert_chain_region(&self) -> &[u8] {
        &self.data[Self::hdr_offset()..][..align(self.header.cert_size)]
    }
    pub fn ticket_region(&self) -> &[u8] {
        let offset = Self::hdr_offset() + align(self.header.cert_size);
        &self.data[offset..][..align(self.header.ticket_size)]
    }
    pub fn tmd_region(&self) -> Option<Tmd> {
        let offset =
            Self::hdr_offset() + align(self.header.cert_size) + align(self.header.ticket_size);
        //Some(unsafe { mem::transmute(&self.data[offset..][..align(self.header.tmd_size)]) })
        Tmd::from_bytes(&self.data[offset..][..align(self.header.tmd_size)])
    }
    pub fn content_region(&self) -> &[u8] {
        let offset = Self::hdr_offset()
            + align(self.header.cert_size)
            + align(self.header.ticket_size)
            + align(self.header.tmd_size);
        &self.data[offset..][..align(self.header.content_size as u32)]
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
            .filter_map(|v| v.to_titleid())
    }
    pub fn icon(&self) -> Option<&Smdh> {
        Smdh::from_slice(&self.icon)
    }
}
