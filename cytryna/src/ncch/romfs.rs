use crate::string::SizedCString;

use static_assertions::assert_eq_size;

#[repr(C, packed)]
pub struct RomfsHeader {
    magic: SizedCString<4>,
    magic_number: u32,
    master_hash_size: u32,
    lv1_logical_offset: u64,
    lv1_hashdata_size: u64,
    lv1_block_size: u32,
    _reserved0: [u8; 4],
    lv_logical_offset: u64,
    l21_hashdata_size: u64,
    l1_block_size: u32,
    _reserved1: [u8; 4],
    lv3_logical_offset: u64,
    lv3_hashdata_size: u64,
    lv3_block_size: u32,
    _reserved2: [u8; 8],
    optional_info_size: u32,
}

assert_eq_size!([u8; 0x5c], RomfsHeader);
