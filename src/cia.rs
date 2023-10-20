use std::mem;

use derivative::Derivative;
use static_assertions::assert_eq_size;

use crate::titleid::TitleId;
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
    pub fn header(&self) -> &CiaHeader { &self.header }
    fn hdr_offset() -> usize {
        align(mem::size_of::<CiaHeader>() as u32) - mem::size_of::<CiaHeader>()
    }
    pub fn from_slice(what: &[u8]) -> &Self {
        let me: &Cia = unsafe { mem::transmute(what) };
        me
    }
    pub fn cert_chain_region(&self) -> &[u8] {
        &self.data[Self::hdr_offset()..][..align(self.header.cert_size)]
    }
    pub fn ticket_region(&self) -> &[u8] {
        let offset = Self::hdr_offset() + align(self.header.cert_size);
        &self.data[offset..][..align(self.header.ticket_size)]
    }
    pub fn tmd_region(&self) -> &[u8] {
        let offset =
            Self::hdr_offset() + align(self.header.cert_size) + align(self.header.ticket_size);
        &self.data[offset..][..align(self.header.tmd_size)]
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
    dependencies: [TitleId; 0x30],
    _reserved0: [u8; 0x180],
    core_version: u32,
    _reserved1: [u8; 0xfc],
    icon: [u8; 0x36c0], // should this be Smdh????
}
assert_eq_size!([u8; 0x3ac0], MetaRegion);

impl MetaRegion {
    pub fn dependencies(&self) -> [TitleId; 0x30] { self.dependencies }
    pub fn dependencies_iter(&self) -> impl Iterator<Item = TitleId> {
        let copy = self.dependencies;
        copy.into_iter()
            .filter(|v| !v.is_null())
    }
    pub fn icon(&self) -> &Smdh { Smdh::from_bytes(&self.icon) }
    pub fn smdh(&self) -> &Smdh { Smdh::from_bytes(&self.icon) }
}
