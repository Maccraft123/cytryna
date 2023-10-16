use std::os::raw::c_char;
use std::mem;
use std::ops::Mul;
use static_assertions::assert_eq_size;

// TODO:
// - split out into ncch.rs
// - validate hashes
// - validate sizes and offsets
// - MediaSize<u32> if that shows up a lot
// - bitflags! for flags
#[derive(Debug, Clone)]
#[repr(C, packed)]
struct NcchHeader {
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
    flags: u64,
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

#[repr(C, packed)]
struct Ncch {
    header: NcchHeader,
    data: [u8],
}

// TODO: modification of data inside of it?
impl Ncch {
    // TODO: Result<Self, BikeshednameError>
    fn from_slice(what: &[u8]) -> &Self {
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
        println!("{:x} {:x}", offset, size);
        Some(&self.data[offset..][..size])
    }
    fn plain_region(&self) -> Option<&[u8]> {
        self.region(self.header.plain_offset, self.header.plain_size)
    }
    fn logo_region(&self) -> Option<&[u8]> {
        self.region(self.header.logo_offset, self.header.logo_size)
    }
    fn exefs_region(&self) -> Option<&[u8]> {
        self.region(self.header.exefs_offset, self.header.exefs_size)
    }
    fn exefs(&self) -> Option<&ExeFs> {
        unsafe {
            self.exefs_region().map(|v| mem::transmute(v))
        }
    }
    fn romfs_region(&self) -> Option<&[u8]> {
        self.region(self.header.romfs_offset, self.header.romfs_size)
    }
}

#[repr(C, packed)]
struct ExeFs {
    header: ExeFsHeader,
    data: [u8],
}

impl ExeFs {
    fn file_by_header<'a>(&'a self, hdr: &'a FileHeader) -> &'a [u8] {
        &self.data[hdr.offset as usize..][..hdr.size as usize]
    }
    fn file_by_name<'a>(&'a self, name: &[u8]) -> Option<&'a [u8]> {
        let header = self.header.file_header_by_name(name)?;
        Some(self.file_by_header(header))
    }
}

#[repr(C, packed)]
struct ExeFsHeader {
    file_headers: [FileHeader; 10],
    _reserved: [u8; 0x20],
    file_hashes: [[u8; 32]; 10],
}
assert_eq_size!([u8; 0x200], ExeFsHeader);

impl ExeFsHeader {
    fn file_header_by_name<'a>(&'a self, name: &[u8]) -> Option<&'a FileHeader> {
        if name.len() > 0x8 {
            return None;
        }
        let mut name = name.to_vec();
        name.resize(0x8, b'\0');
        println!("{:x?}", name);
        for hdr in self.file_headers.iter() {
            if hdr.is_null() {
                continue;
            }
            println!("{:x?}", hdr);
            if name == hdr.name {
                return Some(hdr);
            }

            println!("{}", String::from_utf8_lossy(&hdr.name));
            let slice: &[u8; 16] = unsafe { mem::transmute(hdr) };
            println!("{:x?}", slice);
        }

        None
    }
}

#[derive(Debug)]
#[repr(C, packed)]
struct FileHeader {
    name: [u8; 0x8],
    offset: u32,
    size: u32,
}
assert_eq_size!([u8; 16], FileHeader);

impl FileHeader {
    fn is_null(&self) -> bool {
        self.name == [0; 0x8] && self.offset == 0 && self.size == 0
    }
}

fn main() {
    let file = std::env::args().nth(1).unwrap();
    let data = std::fs::read(file).unwrap();
    let ncch = Ncch::from_slice(&data);
    let exefs_region = ncch.exefs_region().unwrap();
    let exefs = ncch.exefs().unwrap();
    let icon = exefs.file_by_name(b"icon").unwrap();
    println!("{:x?}", icon);
}
