use std::borrow::Cow;
use std::mem;
use bitflags::bitflags;
use derivative::Derivative;
use static_assertions::assert_eq_size;

#[derive(Derivative, Clone)]
#[derivative(Debug)]
#[repr(C)]
pub struct Smdh {
    #[derivative(Debug="ignore")] magic: [u8; 4],
    version: u16,
    #[derivative(Debug="ignore")] _reserved0: u16,
    titles: [SmdhTitle; 0x10],
    age_ratings: [AgeRating; 0x10],
    region_lockout: RegionLockout,
    matchmaker_id: MatchmakerId,
    flags: SmdhFlags,
    eula_version: EulaVersion,
    #[derivative(Debug="ignore")] _reserved1: u16,
    optimal_animation_default_frame: f32,
    cec_id: u32,
    #[derivative(Debug="ignore")] _reserved2: u64,
    #[derivative(Debug="ignore")] icon: [u8; 0x1680],
}
assert_eq_size!([u8; 0x36c0], Smdh);

#[derive(Debug, Clone)]
#[repr(C)]
pub struct EulaVersion {
    major: u8,
    minor: u8,
}

impl Smdh {
    pub fn looks_ok(&self) -> bool {
        self.magic == *b"SMDH"
    }
    pub fn title(&self, lang: Language) -> &SmdhTitle { &self.titles[lang as usize] }
    pub fn age_rating(&self, region: AgeRatingRegion) -> AgeRating { self.age_ratings[region as usize] }
    pub fn region_lockout(&self) -> RegionLockout { self.region_lockout }
    pub fn matchmaker_id(&self) -> &MatchmakerId { &self.matchmaker_id }
    pub fn flags(&self) -> SmdhFlags { self.flags }
    pub fn eula_version(&self) -> &EulaVersion { &self.eula_version }
    pub fn optimal_animation_default_frame(&self) -> f32 { self.optimal_animation_default_frame }
    pub fn cec_id(&self) -> u32 { self.cec_id }
}

#[derive(Debug, Clone, Copy)]
#[repr(usize)]
pub enum AgeRatingRegion {
    Cero = 0,
    Esrb = 1,
    // reserved
    Usk = 2,
    PegiGen = 3,
    // reserved
    PegiPrt = 5,
    PegiBbfc = 6,
    Cob = 7,
    Grb = 8,
    Cgsrr = 9,
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct AgeRating: u8 {
        const ENABLED = 0x80;
        const PENDING = 0x40;
        const NO_AGE_RESTRICTION = 0x20;
        const _ = !0;
    }

    #[derive(Debug, Clone, Copy)]
    pub struct RegionLockout: u32 {
        const JAPAN = 0x1;
        const NORTH_AMERICA = 0x2;
        const EUROPE = 0x4;
        const AUSTRALIA = 0x8;
        const CHINA = 0x10;
        const KOREA = 0x20;
        const TAIWAN = 0x40;
        const REGION_FREE = 0x7fff_ffff;
    }

    #[derive(Debug, Clone, Copy)]
    pub struct SmdhFlags: u32 {
        const VISIBLE_IN_HOMEMENU = 0x1;
        const AUTOBOOT_GAMECART = 0x2;
        const ALLOW_3D = 0x4;
        const REQUIRE_CTR_EULA = 0x8;
        const AUTOSAVE_ON_EXIT = 0x10;
        const EXTBANNER_USED = 0x20;
        const REGION_RATING_REQUIRED = 0x40;
        const USES_SAVE_DATA = 0x80;
        const RECORD_USAGE = 0x100;
        const DISABLE_SD_SAVE_BACKUP = 0x400;
        const NEW3DS_EXCLUSIVE = 0x1000;
    }
}

#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct MatchmakerId {
    id: u32,
    bit_id: u64,
}
assert_eq_size!([u8; 0xc], MatchmakerId);

impl MatchmakerId {
    pub fn id(&self) -> u32 { self.id }
    pub fn bit_id(&self) -> u64 { self.bit_id}
}

#[derive(Debug, Clone, Copy)]
#[repr(usize)]
pub enum Language {
    Japanese = 0,
    English,
    French,
    German,
    Italian,
    Spanish,
    SimplifiedChinese,
    Korean,
    Dutch,
    Portugese,
    Russian,
    TraditionalChinese,
}

#[derive(Derivative, Clone)]
#[derivative(Debug)]
#[repr(C)]
pub struct SmdhTitle {
    #[derivative(Debug(format_with="crate::smdh::format_title"))]
    short_desc: [u16; 0x40],
    #[derivative(Debug(format_with="crate::smdh::format_title"))]
    long_desc: [u16; 0x80],
    #[derivative(Debug(format_with="crate::smdh::format_title"))]
    publisher: [u16; 0x40],
}
assert_eq_size!([u8; 0x200], SmdhTitle);

impl SmdhTitle {
    pub fn short_desc(&self) -> &[u16; 0x40] { &self.short_desc }
    pub fn long_desc(&self) -> &[u16; 0x80] { &self.long_desc }
    pub fn publisher(&self) -> &[u16; 0x40] { &self.publisher }
    pub fn short_desc_string(&self) -> String { String::from_utf16_lossy(&self.short_desc) }
    pub fn long_desc_string(&self) -> String { String::from_utf16_lossy(&self.long_desc) }
    pub fn publisher_string(&self) -> String { String::from_utf16_lossy(&self.publisher) }
}

fn format_title(title: &[u16], fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
    fmt.write_fmt(format_args!("\"{}\"", String::from_utf16_lossy(title)))
}
