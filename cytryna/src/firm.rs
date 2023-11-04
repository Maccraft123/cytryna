use std::mem;

use crate::crypto::sha256;
use crate::string::SizedCString;
use crate::{CytrynaResult, CytrynaError};

use derivative::Derivative;
use static_assertions::assert_eq_size;

const SIGHAX: &[u8] = include_bytes!("sighax.bin");

#[derive(Derivative, Clone)]
#[derivative(Debug)]
#[repr(C)]
pub struct FirmHeader {
    magic: SizedCString<4>,
    boot_priority: u32,
    arm11_entrypoint: u32,
    arm9_entrypoint: u32,
    #[derivative(Debug = "ignore")]
    _reserved: [u8; 0x30],
    firmware_section_headers: [SectionHeader; 4],
    rsa2048_sig: [u8; 0x100],
}
assert_eq_size!([u8; 0x200], FirmHeader);

impl FirmHeader {
    pub fn boot_priority(&self) -> u32 { self.boot_priority }
    pub fn arm11_entrypoint(&self) -> u32 { self.arm11_entrypoint }
    pub fn arm9_entrypoint(&self) -> u32 { self.arm9_entrypoint }
    pub fn sections(&self) -> &[SectionHeader; 4] { &self.firmware_section_headers }
    pub fn section_iter(&self) -> impl Iterator<Item = &SectionHeader> {
        self.firmware_section_headers.iter()
            .filter(|section| section.size != 0)
    }
    pub fn is_sighaxed(&self) -> bool {
        self.rsa2048_sig == SIGHAX
    }
}

#[derive(Derivative, Clone)]
#[derivative(Debug)]
#[repr(C)]
pub struct SectionHeader {
    offset: u32,
    phys_addr: u32,
    size: u32,
    copy_method: CopyMethod,
    hash: [u8; 0x20],
}
assert_eq_size!([u8; 0x30], SectionHeader);

#[derive(Debug, Clone)]
#[repr(u32)]
pub enum CopyMethod {
    Ndma = 0,
    Xdma,
    CpuMemcpy,
}

#[repr(C)]
pub struct Firm {
    header: FirmHeader,
    data: [u8],
}

impl Firm {
    pub fn from_slice(bytes: &[u8]) -> CytrynaResult<&Self> {
        if bytes[0..4] != *b"FIRM" {
            return Err(CytrynaError::InvalidMagic);
        }

        unsafe { Ok(mem::transmute(bytes)) }
    }
    pub fn section_data(&self, section: &SectionHeader) -> &[u8] {
        let offset = section.offset as usize - mem::size_of::<FirmHeader>();
        &self.data[offset..][..section.size as usize]
    }
    pub fn header(&self) -> &FirmHeader {
        &self.header
    }
    pub fn hashes_ok(&self) -> bool {
        for section in self.header.section_iter() {
            let data = self.section_data(section);
            if sha256(data) != section.hash {
                return false;
            }
        }
        true
    }
}
