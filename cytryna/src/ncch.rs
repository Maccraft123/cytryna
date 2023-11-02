use std::mem;
use std::os::raw::c_char;

use crate::string::SizedCString;
use crate::titleid::MaybeTitleId;
use crate::{CytrynaError, Result};

use bitfield::bitfield;
use bitflags::bitflags;
use derivative::Derivative;
use static_assertions::assert_eq_size;

#[derive(Derivative, Clone)]
#[derivative(Debug)]
#[repr(C)]
pub struct NcchHeader {
    sig: [u8; 0x100],
    magic: [u8; 4],
    #[derivative(Debug = "ignore")]
    content_size: u32,
    partition_id: u64,
    maker_code: [c_char; 2],
    version: u16,
    content_lock_seed_hash: u32,
    program_id: u64,
    #[derivative(Debug = "ignore")]
    _reserved0: [u8; 0x10],
    logo_region_hash: [u8; 0x20],
    product_code: SizedCString<0x10>,
    exheader_hash: [u8; 0x20],
    exheader_size: u32,
    #[derivative(Debug = "ignore")]
    _reserved1: u32,
    flags: NcchFlags,
    plain_offset: u32,
    plain_size: u32,
    logo_offset: u32,
    logo_size: u32,
    exefs_offset: u32,
    exefs_size: u32,
    exefs_hash_size: u32,
    #[derivative(Debug = "ignore")]
    _reserved2: u32,
    romfs_offset: u32,
    romfs_size: u32,
    romfs_hash_size: u32,
    #[derivative(Debug = "ignore")]
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
    options: NcchFlagsOptions,
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

#[repr(C)]
pub struct Ncch {
    header: NcchHeader,
    data: [u8],
}

impl Ncch {
    pub fn header(&self) -> &NcchHeader {
        &self.header
    }
    pub fn from_slice(what: &[u8]) -> Result<&Self> {
        let alignment = mem::align_of::<NcchHeader>();
        assert_eq!(0, what.as_ptr().align_offset(alignment));

        let me: &Ncch = unsafe { mem::transmute(what) };
        if &me.header.magic != b"NCCH" {
            Err(CytrynaError::InvalidMagic)?;
        }
        Ok(me)
    }
    // TODO: when are regions absent?
    fn region(&self, offset: u32, size: u32) -> Result<&[u8]> {
        if offset == 0 || size == 0 {
            return Err(CytrynaError::MissingRegion);
        }

        let offset = offset as usize * 0x200 - mem::size_of::<NcchHeader>();
        let size = size as usize * 0x200;
        Ok(&self.data[offset..][..size])
    }
    pub fn plain_region(&self) -> Result<&[u8]> {
        self.region(self.header.plain_offset, self.header.plain_size)
    }
    pub fn logo_region(&self) -> Result<&[u8]> {
        self.region(self.header.logo_offset, self.header.logo_size)
    }
    pub fn exefs_region(&self) -> Result<&[u8]> {
        self.region(self.header.exefs_offset, self.header.exefs_size)
    }
    pub fn exefs(&self) -> Result<&ExeFs> {
        unsafe {
            let reg = self.exefs_region()?;
            let alignment = mem::align_of::<ExeFsHeader>();
            assert_eq!(0, reg.as_ptr().align_offset(alignment));

            Ok(mem::transmute(reg))
        }
    }
    pub fn exheader(&self) -> Result<&Exheader> {
        if self.header.exheader_size == 0 {
            return Err(CytrynaError::MissingRegion);
        }

        unsafe {
            Ok(mem::transmute(self.data[..self.header.exheader_size as usize].as_ptr()))
        }
    }
    pub fn romfs_region(&self) -> Result<&[u8]> {
        self.region(self.header.romfs_offset, self.header.romfs_size)
    }
    pub fn flags(&self) -> &NcchFlags {
        &self.header.flags
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Exheader {
    sci: SystemControlInfo,
    aci: AccessControlInfo,
    access_desc_sig: [u8; 0x100],
    ncch_hdr_pubkey: [u8; 0x100],
    aci_second: AccessControlInfo,
}
assert_eq_size!([u8; 0x800], Exheader);

#[derive(Debug, Clone)]
#[repr(C)]
pub struct SystemControlInfo {
    app_title: SizedCString<0x8>,
    _reserved0: [u8; 0x5],
    exheader_flags: ExheaderFlags,
    remaster_version: u16,
    text_code_set_info: CodeSetInfo,
    stack_size: u32,
    read_only_code_set_info: CodeSetInfo,
    _reserved1: [u8; 0x4],
    data_code_set_info: CodeSetInfo,
    bss_size: u32,
    dep_list: [MaybeTitleId; 0x30],
    savedata_size: u64,
    jump_id: u64,
    _reserved2: [u8; 0x30],
}
assert_eq_size!([u8; 0x200], SystemControlInfo);

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct ExheaderFlags: u8 {
        const COMPRESS_EXEFS_CODE = 0x1;
        const SD_APPLICATION = 0x2;
        const _ = !0;
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct CodeSetInfo {
    addr: u32,
    phys_region_size_pages: u32,
    size_bytes: u32,
}
assert_eq_size!([u8; 0xc], CodeSetInfo);

#[derive(Debug, Clone)]
#[repr(C)]
pub struct AccessControlInfo {
    arm11_syscaps: Arm11LocalSystemCaps,
    arm11_kerncaps: Arm11KernelCaps,
    arm9: Arm9AccessControl,
}
assert_eq_size!([u8; 0x200], AccessControlInfo);

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Arm11LocalSystemCaps {
    program_id: MaybeTitleId,
    core_version: u32,
    n3ds_sysmode: New3dsSystemMode,
    flag1: Flag1,
    flag0: Flag0,
    priority: u8,
    resource_limit_desc: [u8; 0x20],
    storage_info: StorageInfo,
    service_access_control: [SizedCString<0x8>; 0x22],
    _reserved0: [u8; 0xf],
    resource_limit_category: ResourceLimitCategory,
}
assert_eq_size!([u8; 0x170], Arm11LocalSystemCaps);

bitfield! {
    #[derive(Clone, Copy)]
    pub struct Flag0(u8);
    impl Debug;

    ideal_processor, _: 1, 0;
    affinity_mask, _: 3, 2;
    old3ds_system_mode, _: 7, 4;
}

bitfield! {
    #[derive(Clone, Copy)]
    pub struct Flag1(u8);
    impl Debug;

    enable_l2_cache, _: 0;
    cpuspeed_804mhz, _: 1;
}

#[derive(Debug, Clone)]
#[repr(u8)]
pub enum New3dsSystemMode {
    Legacy = 0,
    Prod124Mb,
    Dev1178Mb,
    Dev2124Mb,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct StorageInfo {
    extdata_id: u64,
    system_savedata_id: u64,
    storage_access_unique_id: u64,
    access_info: FsAccessInfo,
}
assert_eq_size!([u8; 0x20], StorageInfo);

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct FsAccessInfo: u64 {
        const CAT_SYSTEM_APPLICATION = 0x1;
        const CAT_HARDWARE_CHECK = 0x2;
        const CAT_FILESYSTEM_TOOL = 0x4;
        const DEBUG = 0x8;
        const TWL_CARD_BACKUP = 0x10;
        const TWL_NAND_DATA = 0x20;
        const BOSS = 0x40;
        const SDMC = 0x80;
        const CORE = 0x100;
        const NANDRO_READONLY = 0x200;
        const NANDRW = 0x400;
        const NANDRO_WRITE_ACCESS = 0x800;
        const CAT_SYSTEM_SETTINGS = 0x1000;
        const CARDBOARD = 0x2000;
        const EXPORT_IMPORT_IVS = 0x4000;
        const SDMC_WRITEONLY = 0x8000;
        const SWITCH_CLEANUP = 0x1_0000;
        const SAVEDATA_MOVE = 0x2_0000;
        const SHOP = 0x4_0000;
        const SHELL = 0x8_0000;
        const CAT_HOME_MENU = 0x10_0000;
        const SEED_DB = 0x20_0000;
        const _ = !0;
    }
}

#[derive(Debug, Clone)]
#[repr(u8)]
pub enum ResourceLimitCategory {
    Application = 0,
    SysApplet = 1,
    LibApplet = 2,
    Other = 3,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Arm11KernelCaps {
    descriptors: [u32; 0x1c],
    _reserved0: [u8; 0x10],
}
assert_eq_size!([u8; 0x80], Arm11KernelCaps);

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Arm9AccessControl {
    descriptors: Arm9Descriptors,
    _pad: [u8; 0xd],
    version: u8,
}
assert_eq_size!([u8; 0x10], Arm9AccessControl);

bitflags! {
    #[derive(Debug, Clone, Copy)]
    // TODO: make sure this is correct
    pub struct Arm9Descriptors: u16 {
        const MOUNT_NAND = 0x1;
        const MOUNT_NANRO_WRITE = 0x2;
        const MOUNT_TWLN = 0x4;
        const MOUNT_WNAND = 0x8;
        const MOUNT_CARD_SPI = 0x10;
        const USE_SDIF3 = 0x20;
        const CREATE_SEED = 0x40;
        const USE_CARD_SPI = 0x80;
        const SD_APPLICATION = 0x100;
        const MOUNT_SDMC_WRITE = 0x200;
    }
}

#[repr(C)]
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
        self.file_headers.iter().filter(|hdr| !hdr.is_unused())
    }
    pub fn file_header_by_name<'a>(&'a self, name: &[u8]) -> Option<&'a FileHeader> {
        if name.len() > 0x8 {
            return None;
        }
        let mut name = name.to_vec();
        name.resize(0x8, b'\0');
        for hdr in self.file_headers_used() {
            if name == hdr.name.data() {
                return Some(hdr);
            }
        }

        None
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct FileHeader {
    name: SizedCString<0x8>,
    offset: u32,
    size: u32,
}
assert_eq_size!([u8; 16], FileHeader);

impl FileHeader {
    fn is_unused(&self) -> bool {
        !self.name.is_zero() && self.offset == 0 && self.size == 0
    }
}
