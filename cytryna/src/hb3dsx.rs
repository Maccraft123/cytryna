use core::mem;

use crate::{CytrynaResult, CytrynaError, FromBytes};
use crate::string::SizedCString;

use static_assertions::assert_eq_size;

#[repr(C)]
pub struct Hb3dsx {
    header: Hb3dsxHeader,
    data: [u8],
}

impl FromBytes for Hb3dsx {
    fn min_size() -> usize {
        mem::size_of::<Hb3dsxHeader>()
    }
    fn bytes_ok(bytes: &[u8]) -> CytrynaResult<()> {
        if [bytes[0], bytes[1], bytes[2], bytes[3]] != *b"3DSX" {
            Err(CytrynaError::InvalidMagic)
        } else {
            Ok(())
        }
    }
    fn cast(bytes: &[u8]) -> &Self {
        unsafe { mem::transmute(bytes) }
    }
}

impl Hb3dsx {
    pub fn header(&self) -> &Hb3dsxHeader {
        &self.header
    }
    pub fn exheader(&self) -> Option<&Hb3dsxExheader> {
        if self.header.header_size != 0x2c {
            None
        } else {
            unsafe {
                Some( mem::transmute(self.data[..mem::size_of::<Hb3dsxExheader>()].as_ptr()) )
            }
        }
    }
    unsafe fn reloc_header(&self, offset: usize) -> &RelocationHeader {
        &*self.data[offset..][..mem::size_of::<RelocationHeader>()].as_ptr().cast()
    }
    pub fn code_reloc_header(&self) -> &RelocationHeader {
        unsafe { self.reloc_header(self.header.code_reloc_header_offset()) }
    }
    pub fn rodata_reloc_header(&self) -> &RelocationHeader {
        unsafe { self.reloc_header(self.header.rodata_reloc_header_offset()) }
    }
    pub fn data_reloc_header(&self) -> &RelocationHeader {
        unsafe { self.reloc_header(self.header.data_reloc_header_offset()) }
    }
    pub fn code_reloc_iter(&self) -> impl Iterator<Item = (RelocationType, &Relocation)> {
        RelocationIter {
            hdr: self.code_reloc_header(),
            offset_bytes: 0,
            data: &self.data[self.header.code_reloc_table_offset()..][..self.code_reloc_header().table_size()],
        }
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Hb3dsxHeader {
    magic: SizedCString<4>,
    header_size: u16,
    relocation_header_size: u16,
    format_version: u32,
    flags: u32,
    code_segment_size: u32,
    rodata_segment_size: u32,
    data_bss_segment_size: u32,
    bss_segment_size: u32,
}
assert_eq_size!([u8; 0x20], Hb3dsxHeader);

impl Hb3dsxHeader {
    fn exheader_offset(&self) -> usize {
        0
    }
    fn code_reloc_header_offset(&self) -> usize {
        self.header_size as usize - mem::size_of::<Hb3dsxHeader>()
    }
    fn rodata_reloc_header_offset(&self) -> usize {
        self.code_reloc_header_offset() + mem::size_of::<RelocationHeader>()
    }
    fn data_reloc_header_offset(&self) -> usize {
        self.rodata_reloc_header_offset() + mem::size_of::<RelocationHeader>()
    }
    fn code_segment_offset(&self) -> usize {
        self.data_reloc_header_offset() + mem::size_of::<RelocationHeader>()
    }
    fn rodata_segment_offset(&self) -> usize {
        self.code_segment_offset() + self.code_segment_size as usize
    }
    fn data_segment_offset(&self) -> usize {
        self.rodata_segment_offset() + self.rodata_segment_size as usize
    }
    pub fn code_reloc_table_offset(&self) -> usize {
        self.data_segment_offset() + (self.data_bss_segment_size - self.bss_segment_size) as usize
    }
    /*fn rodata_reloc_table_offset(&self) -> usize {
        self.data_segment_offset + self.data_segment_offset
    }
    fn data_reloc_table_offset(&self) -> usize {
        self.data_segment_offset + self.data_segment_offset
    }*/
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Hb3dsxExheader {
    smdh_offset: u32,
    smdh_size: u32,
    romfs_offset: u32,
}
assert_eq_size!([u8; 0xc], Hb3dsxExheader);

#[derive(Clone, Debug)]
#[repr(C)]
pub struct RelocationHeader {
    abs_count: u32,
    rel_count: u32,
}
assert_eq_size!([u8; 0x8], RelocationHeader);

impl RelocationHeader {
    fn table_size(&self) -> usize {
        (self.abs_count + self.rel_count) as usize * mem::size_of::<Relocation>()
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Relocation {
    skip: u16,
    patch: u16,
}
assert_eq_size!([u8; 0x4], Relocation);

pub struct RelocationIter<'a> {
    hdr: &'a RelocationHeader,
    offset_bytes: usize,
    data: &'a [u8],
}

impl<'a> Iterator for RelocationIter<'a> {
    type Item = (RelocationType, &'a Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset_bytes >= self.data.len() {
            return None;
        }

        let relative_start = self.hdr.abs_count as usize * mem::size_of::<Relocation>();
        let relocation = unsafe { &*self.data[self.offset_bytes..][..mem::size_of::<Relocation>()].as_ptr().cast() };
        let rel_type;
        if self.offset_bytes >= relative_start as usize {
            rel_type = RelocationType::Relative;
        } else {
            rel_type = RelocationType::Absolute;
        }

        self.offset_bytes += mem::size_of::<Relocation>();
        Some((rel_type, relocation))
    }
}

#[derive(Clone, Debug)]
pub enum RelocationType {
    Absolute,
    Relative,
}
