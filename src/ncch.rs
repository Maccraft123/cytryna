use std::os::raw::c_char;
use std::mem;
use bitflags::bitflags;
use static_assertions::assert_eq_size;

// TODO:
// - validate hashes
// - validate sizes and offsets
// - MediaSize<u32> if that shows up a lot
#[derive(Clone)]
#[repr(C)]
pub struct NcchHeader {
    sig: [u8; 0x100],
    magic: [u8; 4],
    content_size: u32,
    partition_id: u64,
    maker_code: [c_char; 2],
    version: u16,
    content_lock_seed_hash: u32,
    program_id: u64,
    _reserved0: [u8; 0x10],
    logo_region_hash: [u8; 0x20],
    product_code: [c_char; 0x10],
    exheader_hash: [u8; 0x20],
    exheader_size: u32,
    _reserved1: u32,
    flags: NcchFlags,
    plain_offset: u32,
    plain_size: u32,
    logo_offset: u32,
    logo_size: u32,
    exefs_offset: u32,
    exefs_size: u32,
    exefs_hash_size: u32,
    _reserved2: u32,
    romfs_offset: u32,
    romfs_size: u32,
    romfs_hash_size: u32,
    _reserved3: u32,
    exefs_super_hash: [u8; 0x20],
    romfs_super_hash: [u8; 0x20],
}
assert_eq_size!([u8; 0x200], NcchHeader);

#[derive(Clone, Debug)]
#[repr(C)]
pub struct NcchFlags {
    unk0: u8,
    unk1: u8,
    unk2: u8,
    two_keyslots: u8, // TODO: use bool if i can
    content_platform: u8,
    content_type: ContentType,
    content_unit_size: u8,
    options: NcchFlagsOptions
}
assert_eq_size!([u8; 0x8], NcchFlags);

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct ContentType: u8 {
        const DATA = 0x1;
        const EXECUTABLE = 0x2;
        const SYSTEMUPDATE = 0x4;
        const MANUAL = 0x8;
        const CHILD = 0x4 | 0x8;
        const TRIAL = 0x10;
        const _ = !0;
    }
    #[derive(Debug, Clone, Copy)]
    pub struct NcchFlagsOptions: u8 {
        const FIXED_CRYPTO_KEY = 0x1;
        const NO_MOUNT_ROM_FS = 0x2;
        const NO_CRYPTO = 0x4;
        const NEW_KEY_Y_GENERATOR = 0x20;
        const _ = !0;
    }
}

#[repr(C, packed)]
pub struct Ncch {
    header: NcchHeader,
    data: [u8],
}

// TODO: 
// - modification of data inside of it?
// - encryption and decryption
impl Ncch {
    // TODO: Result<Self, BikeshednameError>
   pub  fn from_slice(what: &[u8]) -> &Self {
        let me: &Ncch = unsafe { mem::transmute(what) };
        if &me.header.magic != b"NCCH" {
            panic!("wrong magic");
        }
        me
    }
    // TODO: when are regions absent?
    fn region(&self, offset: u32, size: u32) -> Option<&[u8]> {
        let offset = offset as usize * 0x200 - mem::size_of::<NcchHeader>();
        let size = size as usize * 0x200;
        Some(&self.data[offset..][..size])
    }
    pub fn plain_region(&self) -> Option<&[u8]> {
        self.region(self.header.plain_offset, self.header.plain_size)
    }
    pub fn logo_region(&self) -> Option<&[u8]> {
        self.region(self.header.logo_offset, self.header.logo_size)
    }
    pub fn exefs_region(&self) -> Option<&[u8]> {
        self.region(self.header.exefs_offset, self.header.exefs_size)
    }
    pub fn exefs(&self) -> Option<&ExeFs> {
        unsafe {
            self.exefs_region().map(|v| mem::transmute(v))
        }
    }
    pub fn romfs_region(&self) -> Option<&[u8]> {
        self.region(self.header.romfs_offset, self.header.romfs_size)
    }
    pub fn flags(&self) -> &NcchFlags { &self.header.flags }
}

#[repr(C, packed)]
pub struct ExeFs {
    header: ExeFsHeader,
    data: [u8],
}

impl ExeFs {
    pub fn file_by_header<'a>(&'a self, hdr: &'a FileHeader) -> &'a [u8] {
        &self.data[hdr.offset as usize..][..hdr.size as usize]
    }
    pub fn file_by_name<'a>(&'a self, name: &[u8]) -> Option<&'a [u8]> {
        let header = self.header.file_header_by_name(name)?;
        Some(self.file_by_header(header))
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct ExeFsHeader {
    file_headers: [FileHeader; 8],
    _reserved: [u8; 0x80],
    file_hashes: [[u8; 32]; 8],
}
assert_eq_size!([u8; 0x200], ExeFsHeader);

impl ExeFsHeader {
    pub fn file_headers_used(&self) -> impl Iterator<Item = &FileHeader> {
        self.file_headers.iter()
            .filter(|hdr| !hdr.is_unused())
    }
    pub fn file_header_by_name<'a>(&'a self, name: &[u8]) -> Option<&'a FileHeader> {
        if name.len() > 0x8 {
            return None;
        }
        let mut name = name.to_vec();
        name.resize(0x8, b'\0');
        for hdr in self.file_headers_used() {
            if name == hdr.name {
                return Some(hdr);
            }
        }

        None
    }
}

#[derive(Clone)]
#[repr(C, packed)]
pub struct FileHeader {
    name: [u8; 0x8],
    offset: u32,
    size: u32,
}
assert_eq_size!([u8; 16], FileHeader);

impl FileHeader {
    fn is_unused(&self) -> bool {
        self.name == [0; 0x8] && self.offset == 0 && self.size == 0
    }
}
