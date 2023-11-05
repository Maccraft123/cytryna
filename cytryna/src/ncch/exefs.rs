use crate::string::SizedCString;
use crate::VecOrSlice;

use derivative::Derivative;
use static_assertions::assert_eq_size;

#[derive(Debug)]
#[repr(C)]
pub struct ExeFs<'a> {
    pub(super) compressed: bool,
    pub(super) encrypted: bool,
    pub(super) inner: &'a ExeFsInner,
}

impl ExeFs<'_> {
    #[must_use]
    pub fn file_by_name(&self, name: &[u8]) -> Option<VecOrSlice<u8>> {
        let header = self.inner.header.file_header_by_name(name)?;
        let file = self.inner.file_by_header(header);

        if self.compressed && name == b".code" {
            todo!("exefs decompression")
        } else {
            Some(VecOrSlice::S(file))
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
#[repr(C)]
pub struct ExeFsInner {
    header: ExeFsHeader,
    #[derivative(Debug = "ignore")]
    data: [u8],
}

impl ExeFsInner {
    #[must_use]
    pub fn file_by_header<'a>(&'a self, hdr: &'a FileHeader) -> &'a [u8] {
        &self.data[hdr.offset as usize..][..hdr.size as usize]
    }
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
#[repr(C)]
pub struct ExeFsHeader {
    file_headers: [FileHeader; 8],
    #[derivative(Debug = "ignore")]
    _reserved: [u8; 0x80],
    file_hashes: [[u8; 32]; 8],
}
assert_eq_size!([u8; 0x200], ExeFsHeader);

impl ExeFsHeader {
    #[must_use]
    pub fn file_headers_used(&self) -> impl Iterator<Item = &FileHeader> {
        self.file_headers.iter().filter(|hdr| !hdr.is_unused())
    }
    #[must_use]
    pub fn file_header_by_name<'a>(&'a self, name: &[u8]) -> Option<&'a FileHeader> {
        if name.len() > 0x8 {
            return None;
        }
        let mut name = name.to_vec();
        name.resize(0x8, b'\0');
        self.file_headers_used()
            .find(|&hdr| name == hdr.name.data())
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct FileHeader {
    name: SizedCString<0x8>,
    offset: u32,
    size: u32,
}
assert_eq_size!([u8; 16], FileHeader);

impl FileHeader {
    #[must_use]
    fn is_unused(&self) -> bool {
        !self.name.is_zero() && self.offset == 0 && self.size == 0
    }
}
