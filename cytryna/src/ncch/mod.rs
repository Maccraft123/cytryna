pub mod exefs;
pub mod romfs;

use core::fmt;
use core::mem;

use crate::crypto::{self, aes128_ctr::*, KeyBag, KeyIndex, KeyType};
use crate::string::SizedCString;
use crate::titleid::MaybeTitleId;
use crate::{CytrynaError, CytrynaResult, OwnedOrBorrowed};

use bitflags::bitflags;
use bitfield_struct::bitfield;
use derivative::Derivative;
use static_assertions::assert_eq_size;

/// NCCH Header data
/// <https://www.3dbrew.org/wiki/NCCH#NCCH_Header>
#[derive(Derivative, Clone)]
#[derivative(Debug)]
#[repr(C)]
pub struct NcchHeader {
    sig: [u8; 0x100],
    magic: [u8; 4],
    #[derivative(Debug = "ignore")]
    content_size: u32,
    partition_id: u64,
    maker_code: SizedCString<2>,
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

/// NCCH flags data, <https://www.3dbrew.org/wiki/NCCH#NCCH_Flags>
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
    /// NCCH Content Type
    /// https://www.3dbrew.org/wiki/NCCH#NCCH_Flags
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
    /// NCCH option bit-masks
    /// https://www.3dbrew.org/wiki/NCCH#NCCH_Flags
    #[derive(Debug, Clone, Copy)]
    pub struct NcchFlagsOptions: u8 {
        const FIXED_CRYPTO_KEY = 0x1;
        const NO_MOUNT_ROM_FS = 0x2;
        const NO_CRYPTO = 0x4;
        const NEW_KEY_Y_GENERATOR = 0x20;
        const _ = !0;
    }
}

/// NCCH File
#[repr(C)]
pub struct Ncch {
    header: NcchHeader,
    data: [u8],
}

impl Ncch {
    /// Returns a reference to NCCH Header
    #[must_use]
    pub fn header(&self) -> &NcchHeader {
        &self.header
    }
    pub fn from_slice(what: &[u8]) -> CytrynaResult<&Self> {
        let alignment = mem::align_of::<NcchHeader>();
        assert_eq!(0, what.as_ptr().align_offset(alignment));

        let me: &Ncch = unsafe { mem::transmute(what) };
        if &me.header.magic != b"NCCH" {
            Err(CytrynaError::InvalidMagic)?;
        }
        Ok(me)
    }
    /// Check if data is encrypted
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        !self
            .header
            .flags
            .options
            .contains(NcchFlagsOptions::NO_CRYPTO)
    }
    /// Returns a region as a byte slice
    fn region(&self, offset: u32, size: u32) -> CytrynaResult<&[u8]> {
        if offset == 0 || size == 0 {
            return Err(CytrynaError::MissingRegion);
        }

        let offset = offset as usize * 0x200 - mem::size_of::<NcchHeader>();
        let size = size as usize * 0x200;
        Ok(&self.data[offset..][..size])
    }
    /// Returns a reference to "plain region"
    pub fn plain_region(&self) -> CytrynaResult<&[u8]> {
        self.region(self.header.plain_offset, self.header.plain_size)
    }
    /// Returns icon/SMDH region data as a byte slice
    pub fn logo_region(&self) -> CytrynaResult<&[u8]> {
        self.region(self.header.logo_offset, self.header.logo_size)
    }
    /// Returns ExeFS region data as a byte slice
    pub fn exefs_region(&self) -> CytrynaResult<&[u8]> {
        self.region(self.header.exefs_offset, self.header.exefs_size)
    }
    /// Returns ExeFS region data
    pub fn exefs(&self) -> CytrynaResult<exefs::ExeFs> {
        let data = self.exefs_region()?;
        let alignment = mem::align_of::<exefs::ExeFsHeader>();
        assert_eq!(0, data.as_ptr().align_offset(alignment));

        let inner = unsafe { mem::transmute(data) };

        Ok(exefs::ExeFs {
            compressed: self
                .exheader()?
                .sci
                .flags
                .contains(ExheaderFlags::COMPRESS_EXEFS_CODE),
            encrypted: self.is_encrypted(),
            inner,
        })
    }
    /// Returns a decrypted Exheader stored in OwnedOrBorrowed
    pub fn exheader(&self) -> CytrynaResult<OwnedOrBorrowed<Exheader>> {
        if self.header.exheader_size == 0 {
            return Err(CytrynaError::MissingRegion);
        }

        // self.header.exheader_size is a fucking lie
        let exheader_size = mem::size_of::<Exheader>();

        if self.is_encrypted() {
            let x = KeyBag::global()?.get_key(KeyIndex::Slot(0x2c, KeyType::X))?;
            let y = &self.header.sig[..0x10];

            let key = crypto::keygen(*x, y.try_into().unwrap())?;
            let iv: [u8; 0x10] = unsafe {
                mem::transmute(Aes128Iv {
                    title_id: self.header.program_id.swap_bytes(),
                    ty: 1,
                    pad: [0u8; 7],
                })
            };

            let inp = &self.data[..exheader_size];
            let mut out = vec![0u8; inp.len()].into_boxed_slice();
            Aes128CtrDec::new(&key.into(), &iv.into())
                .apply_keystream_b2b(inp, &mut out)?;

            unsafe {
                let raw = Box::into_raw(out) as *mut u8 as *mut Exheader;
                Ok(OwnedOrBorrowed::Owned(Box::from_raw(raw)))
            }
        } else {
            unsafe {
                Ok(OwnedOrBorrowed::Borrowed(mem::transmute(
                    self.data[..exheader_size].as_ptr(),
                )))
            }
        }
    }
    /// Returns the RomFS region data as a byte slice
    pub fn romfs_region(&self) -> CytrynaResult<&[u8]> {
        self.region(self.header.romfs_offset, self.header.romfs_size)
    }
    /// Returns a reference to NCCH Flags
    #[must_use]
    pub fn flags(&self) -> &NcchFlags {
        &self.header.flags
    }
}

/// AES-128 Initialization Vector used in NCCH Exheader Decryption
#[repr(C)]
struct Aes128Iv {
    title_id: u64,
    ty: u8,
    pad: [u8; 7],
}
assert_eq_size!([u8; 0x10], Aes128Iv);

/// NCCH Extended Header
/// <https://www.3dbrew.org/wiki/NCCH/Extended_Header>
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

/// Exheader SystemControlInfo
/// <https://www.3dbrew.org/wiki/NCCH/Extended_Header#System_Control_Info>
#[derive(Derivative, Clone)]
#[derivative(Debug)]
#[repr(C)]
pub struct SystemControlInfo {
    app_title: SizedCString<0x8>,
    #[derivative(Debug = "ignore")]
    _reserved0: [u8; 0x5],
    flags: ExheaderFlags,
    remaster_version: u16,
    text_code_set_info: CodeSetInfo,
    stack_size: u32,
    read_only_code_set_info: CodeSetInfo,
    #[derivative(Debug = "ignore")]
    _reserved1: [u8; 0x4],
    data_code_set_info: CodeSetInfo,
    bss_size: u32,
    dep_list: [MaybeTitleId; 0x30],
    savedata_size: u64,
    jump_id: u64,
    #[derivative(Debug = "ignore")]
    _reserved2: [u8; 0x30],
}
assert_eq_size!([u8; 0x200], SystemControlInfo);

bitflags! {
    /// SystemControlInfo flags
    #[derive(Debug, Clone, Copy)]
    pub struct ExheaderFlags: u8 {
        const COMPRESS_EXEFS_CODE = 0x1;
        const SD_APPLICATION = 0x2;
        const _ = !0;
    }
}

/// idk what to put here
#[derive(Debug, Clone)]
#[repr(C)]
pub struct CodeSetInfo {
    addr: u32,
    phys_region_size_pages: u32,
    size_bytes: u32,
}
assert_eq_size!([u8; 0xc], CodeSetInfo);

/// Exheader Access Control Info
/// <https://www.3dbrew.org/wiki/NCCH/Extended_Header#Access_Control_Info>
#[derive(Debug, Clone)]
#[repr(C)]
pub struct AccessControlInfo {
    arm11_syscaps: Arm11LocalSystemCaps,
    arm11_kerncaps: Arm11KernelCaps,
    arm9: Arm9AccessControl,
}
assert_eq_size!([u8; 0x200], AccessControlInfo);

/// ARM11 Local system capabilities
/// <https://www.3dbrew.org/wiki/NCCH/Extended_Header#ARM11_Local_System_Capabilities>
#[derive(Derivative, Clone)]
#[derivative(Debug)]
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
    #[derivative(Debug = "ignore")]
    _reserved0: [u8; 0xf],
    resource_limit_category: ResourceLimitCategory,
}
assert_eq_size!([u8; 0x170], Arm11LocalSystemCaps);

/// ARM11 Local system capabilities Flag0 data
/// <https://www.3dbrew.org/wiki/NCCH/Extended_Header#Flag0>
#[bitfield(u8)]
pub struct Flag0 {
    #[bits(2)]
    ideal_proccessor: u8,
    #[bits(2)]
    affinity_mask: u8,
    #[bits(4)]
    old3ds_system_mode: Old3dsSystemMode,
}

/// Stores the Old3DS system mode data
/// <https://www.3dbrew.org/wiki/NCCH/Extended_Header#Old3DS_System_Mode>
#[derive(Debug, Clone)]
#[repr(u8)]
pub enum Old3dsSystemMode {
    /// Prod (64MB of usable application memory) 
    Prod64Mb = 0,
    /// Undefined (unusable)
    Undefined,
    /// Dev1 (96MB of usable application memory) 
    Dev1_96Mb,
    /// Dev2 (80MB of usable application memory) 
    Dev2_80Mb,
    /// Dev3 (72MB of usable application memory) 
    Dev3_72Mb,
    /// Dev4 (32MB of usable application memory) 
    Dev4_32Mb,
}

impl Old3dsSystemMode {
    const fn into_bits(self) -> u8 {
        self as _
    }
    const fn from_bits(value: u8) -> Self {
        match value {
            0 => Self::Prod64Mb,
            1 => Self::Undefined,
            2 => Self::Dev1_96Mb,
            3 => Self::Dev2_80Mb,
            4 => Self::Dev3_72Mb,
            5 => Self::Dev4_32Mb,
            _ => panic!("value out of range for Old3dsSystemMode"),
        }
    }
}

/// ARM11 Local system capabilities Flag1 data
/// <https://www.3dbrew.org/wiki/NCCH/Extended_Header#Flag1>
#[bitfield(u8)]
pub struct Flag1 {
    enable_l2_cache: bool,
    cpuspeed_804mhz: bool,
    #[bits(6)]
    __: u8,
}

/// ARM11 Local system capabilities New3DS system mode data
/// <https://www.3dbrew.org/wiki/NCCH/Extended_Header#New3DS_System_Mode>
#[derive(Debug, Clone)]
#[repr(u8)]
pub enum New3dsSystemMode {
    /// Legacy(use Old3DS system mode)
    Legacy = 0,
    /// Prod (124MB of usable application memory) 
    Prod124Mb,
    /// Dev1 (178MB of usable application memory) 
    Dev1_178Mb,
    /// Dev2 (124MB of usable application memory) 
    Dev2_124Mb,
}

/// ARM11 Local system capabilities storage info
/// <https://www.3dbrew.org/wiki/NCCH/Extended_Header#Storage_Info>
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
    /// StorageInfo's FS Access info flags
    /// https://www.3dbrew.org/wiki/NCCH/Extended_Header#Storage_Info
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

/// ARM11 Local system capabilities resource Limit Category
#[derive(Debug, Clone)]
#[repr(u8)]
pub enum ResourceLimitCategory {
    Application = 0,
    SysApplet = 1,
    LibApplet = 2,
    Other = 3,
}

/// ARM11 Kernel Capabilities
/// <https://www.3dbrew.org/wiki/NCCH/Extended_Header#ARM11_Kernel_Capabilities>
#[derive(Clone)]
#[repr(C)]
pub struct Arm11KernelCaps {
    descriptors: [KernelCapRaw; 0x1c],
    _reserved0: [u8; 0x10],
}
assert_eq_size!([u8; 0x80], Arm11KernelCaps);

impl Arm11KernelCaps {
    /// Returns a Vec of decoded ARM11 Kernel capability descriptors
    #[must_use]
    fn decode_descriptors(&self) -> Vec<KernelCap> {
        let mut ret = Vec::new();
        let mut expect_nine = false;

        for cap in self.descriptors.iter() {
            let ones = cap.0.leading_ones();
            let val = cap.0;

            let desc = match ones {
                3 => KernelCap::InterruptInfo,
                4 => KernelCap::EnableSyscalls(SyscallMask::from(val & !0xf0000000)),
                6 => {
                    let val = (val & !0xfc000000).to_le_bytes();
                    KernelCap::KernelReleaseVersion {
                        major: val[1],
                        minor: val[0],
                    }
                }
                7 => KernelCap::HandleTableSize(val & !0xfe000000),
                8 => KernelCap::KernelFlags(Arm11Flags::from(val & !0xff000000)),
                9 => {
                    expect_nine = !expect_nine;

                    let bit20 = (val & 1 << 20) != 0;
                    let addr = (val & !0xfff00000) << 16;

                    if expect_nine {
                        KernelCap::MapMemoryRangeStart {
                            read_only: bit20,
                            start: addr,
                        }
                    } else {
                        KernelCap::MapMemoryRangeEnd {
                            cacheable: bit20,
                            end: addr - 1,
                        }
                    }
                }
                11 => todo!("MapIoMemoryPage"),
                _ => continue,
            };

            ret.push(desc);
        }

        ret
    }
}

impl fmt::Debug for Arm11KernelCaps {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.decode_descriptors().fmt(f)
    }
}

/// what do i even put here
#[derive(Clone)]
#[repr(transparent)]
pub struct KernelCapRaw(u32);

/// Stores the decoded ARM11 Kernel Capability descriptor
/// <https://www.3dbrew.org/wiki/NCCH/Extended_Header#ARM11_Kernel_Capabilities>
#[derive(Debug, Clone)]
pub enum KernelCap {
    InterruptInfo,
    EnableSyscalls(SyscallMask),
    KernelReleaseVersion { major: u8, minor: u8 },
    HandleTableSize(u32),
    KernelFlags(Arm11Flags),
    MapMemoryRangeStart { read_only: bool, start: u32 },
    MapMemoryRangeEnd { cacheable: bool, end: u32 },
    MapIoMemoryPageStart,
    MapIoMemoryPageEnd,
}

/// ARM11 enabled syscall mask
#[bitfield(u32, debug = false)]
pub struct SyscallMask {
    #[bits(24)]
    mask: u32,
    #[bits(3)]
    idx: u8,
    #[bits(5)]
    __: u8,
}

impl SyscallMask {
    /// Returns whether the syscall number provided is enabled in this syscall mask.
    /// Note that other masks might have it enabled
    #[must_use]
    fn has_syscall(&self, num: u8) -> bool {
        let rem = num % 24;
        let idx = num / 24;

        if self.idx() != idx {
            false
        } else {
            self.mask() & (1 << (rem & 31)) != 0
        }
    }
    //pub fn iter(&self) -> impl Iterator<Item = (u8, bool)> {
    //    SyscallIter { mask: self.mask(), idx: self.idx(), mask_shift: 0 }
    //}
}

/*
pub struct SyscallIter {
    mask: u32,
    idx: u8,
    mask_shift: u8,
}

impl Iterator for SyscallIter {
    type Item = (u8, bool);

    fn next(&mut self) -> Option<Self::Item> {
        if self.mask_shift > 24 {
            return None;
        }

        let num = self.idx * 24 + self.mask_shift;
        let is_enabled = self.mask & (1 << self.mask_shift) != 0;
        Some((num, is_enabled))
    }
}*/

impl fmt::Debug for SyscallMask {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let idx = self.idx();
        let syscall = idx * 24;
        let mut dbg_list = f.debug_list();
        for num in syscall..syscall + 24 {
            if self.has_syscall(num) {
                dbg_list.entry(&num);
            }
        }
        dbg_list.finish()
    }
}

/// ARM11 Kernel Capabilities flag field data
/// <https://www.3dbrew.org/wiki/NCCH/Extended_Header#ARM11_Kernel_Flags>
#[bitfield(u32)]
pub struct Arm11Flags {
    allow_debug: bool,
    force_debug: bool,
    allow_non_alphanum: bool,
    shared_page_writing: bool,
    priviledge_priority: bool,
    allow_main_args: bool,
    shared_deice_memory: bool,
    runnable_on_sleep: bool,
    #[bits(4)]
    memory_type: Arm11MemoryType,
    special_memory: bool,
    access_core2: bool,
    #[bits(18)]
    __: u32,
}

/// ARM11 Memory Type
#[derive(Debug, Clone)]
#[repr(u8)]
pub enum Arm11MemoryType {
    Application = 1,
    System,
    Base,
}
impl Arm11MemoryType {
    const fn into_bits(self) -> u32 {
        self as _
    }
    const fn from_bits(value: u32) -> Self {
        match value {
            1 => Self::Application,
            2 => Self::System,
            3 => Self::Base,
            _ => panic!("Invalid value for Arm11MemoryType"),
        }
    }
}

/// ARM9 Access Control data
/// <https://www.3dbrew.org/wiki/NCCH/Extended_Header#ARM9_Access_Control>
#[derive(Derivative, Clone)]
#[derivative(Debug)]
#[repr(C)]
pub struct Arm9AccessControl {
    descriptors: Arm9Descriptors,
    #[derivative(Debug = "ignore")]
    _pad: [u8; 0xd],
    version: u8,
}
assert_eq_size!([u8; 0x10], Arm9AccessControl);

bitflags! {
    /// ARM9 Access Control Descriptor data
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
