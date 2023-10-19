use std::mem;

use bitflags::bitflags;
use static_assertions::assert_eq_size;

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(C)]
pub struct TitleId {
    id: u32,
    category: Category,
    plat: Platform,
}
assert_eq_size!(u64, TitleId);

impl TitleId {
    pub fn is_null(&self) -> bool {
        self.to_u64() == 0
    }
    pub fn to_u64(self) -> u64 {
        unsafe { mem::transmute(self) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum Platform {
    Invalid = 0, // placeholder for debug derive to not shit itself when titleid is 0
    Wii = 1,
    Dsi = 3,
    Ctr = 4,
    Wiiu = 5,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct Category: u16 {
        const NORMAL = 0x0;
        const DLP_CHILD = 0x1;
        const DEMO = 0x2;
        const CONTENTS = 0x3;
        const ADDON_CONTENTS = 0x4;
        const PATCH = 0x6;
        const CANNOT_EXECUTION = 0x8;
        const SYSTEM = 0x10;
        const REQUIRE_BATCH_UPDATE = 0x20;
        const NOT_REQUIRE_USER_APPROVAL = 0x40;
        const NOT_REQUIRE_RIGHT_FOR_MOUNT = 0x80;
        const CAN_SKIP_CONVERT_JUMP_ID = 0x100;
        const TWL = 0x8000;

        // https://www.3dbrew.org/wiki/Title_list#CTR_System_Titles
        const SYSTEM_APPLICATION = Self::NORMAL.bits() | Self::SYSTEM.bits();
        const SYSTEM_CONTENT = Self::CONTENTS.bits() | Self::CANNOT_EXECUTION.bits() | Self::SYSTEM.bits();
        const SHARED_CONTENT = Self::CONTENTS.bits() | Self::CANNOT_EXECUTION.bits() | Self::NOT_REQUIRE_RIGHT_FOR_MOUNT.bits() | Self::SYSTEM.bits();
        const AUTO_UPDATE_CONTENT = Self::CONTENTS.bits() | Self::CANNOT_EXECUTION.bits() | Self::NOT_REQUIRE_USER_APPROVAL.bits() | Self::NOT_REQUIRE_RIGHT_FOR_MOUNT.bits() | Self::SYSTEM.bits();
        const APPLET = Self::NORMAL.bits() | Self::SYSTEM.bits() | Self::REQUIRE_BATCH_UPDATE.bits();
        const BASE = Self::NORMAL.bits() | Self::SYSTEM.bits() | Self::REQUIRE_BATCH_UPDATE.bits() | Self::CAN_SKIP_CONVERT_JUMP_ID.bits();
        const FIRMWARE = Self::NORMAL.bits() | Self::CANNOT_EXECUTION.bits() | Self::SYSTEM.bits() | Self::REQUIRE_BATCH_UPDATE.bits() | Self::CAN_SKIP_CONVERT_JUMP_ID.bits();

        const _ = !0;
    }
}
