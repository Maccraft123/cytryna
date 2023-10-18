use std::mem;
use std::ops::{Add, Rem};

fn align(what: u32) -> u32 {
    what + (0x40 - (what % 0x40))
}

#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct CiaHeader {
    pub hdr_size: u32,
    ty: u16,
    version: u16,
    cert_size: u32,
    ticket_size: u32,
    tmd_size: u32,
    meta_size: u32,
    content_size: u64,
    content_index: [u8; 0x2000],
}

#[repr(C, packed)]
pub struct Cia {
    pub header: CiaHeader,
    data: [u8],
}

impl Cia {
    fn hdr_offset() -> usize {
        align(mem::size_of::<CiaHeader>() as u32) as usize - mem::size_of::<CiaHeader>()
    }
    pub fn from_slice(what: &[u8]) -> &Self {
        let me: &Cia = unsafe { mem::transmute(what) };
        me
    }
    pub fn cert_chain(&self) -> &[u8] {
        &self.data[Self::hdr_offset()..][..align(self.header.cert_size) as usize]
    }
}
