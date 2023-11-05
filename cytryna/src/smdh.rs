use std::mem;

use crate::string::SizedCStringUtf16;
use crate::{CytrynaError, CytrynaResult, FromBytes};

use bitflags::bitflags;
use derivative::Derivative;
use static_assertions::assert_eq_size;

#[derive(Derivative, Clone)]
#[derivative(Debug)]
#[repr(C)]
pub struct Smdh {
    #[derivative(Debug = "ignore")]
    magic: [u8; 4],
    version: u16,
    #[derivative(Debug = "ignore")]
    _reserved0: u16,
    titles: [SmdhTitle; 0x10],
    age_ratings: [AgeRating; 0x10],
    region_lockout: RegionLockout,
    matchmaker_id: MatchmakerId,
    flags: SmdhFlags,
    eula_version: EulaVersion,
    #[derivative(Debug = "ignore")]
    _reserved1: u16,
    optimal_animation_default_frame: f32,
    cec_id: u32,
    #[derivative(Debug = "ignore")]
    _reserved2: u64,
    #[derivative(Debug = "ignore")]
    icon: SmdhIcon,
}
assert_eq_size!([u8; 0x36c0], Smdh);

#[derive(Debug, Clone)]
#[repr(C)]
pub struct EulaVersion {
    major: u8,
    minor: u8,
}

impl FromBytes for Smdh {
    fn min_size() -> usize {
        mem::size_of::<Smdh>()
    }
    fn bytes_ok(bytes: &[u8]) -> CytrynaResult<()> {
        if [bytes[0], bytes[1], bytes[2], bytes[3]] != *b"SMDH" {
            return Err(CytrynaError::InvalidMagic);
        }
        
        Ok(())
    }
    fn cast(bytes: &[u8]) -> &Self {
        unsafe { mem::transmute(bytes.as_ptr()) }
    }
}

impl Smdh {
    #[must_use]
    pub fn title(&self, lang: Language) -> &SmdhTitle {
        &self.titles[lang as usize]
    }
    #[must_use]
    pub fn age_rating(&self, region: AgeRatingRegion) -> AgeRating {
        self.age_ratings[region as usize]
    }
    #[must_use]
    pub fn region_lockout(&self) -> RegionLockout {
        self.region_lockout
    }
    #[must_use]
    pub fn matchmaker_id(&self) -> &MatchmakerId {
        &self.matchmaker_id
    }
    #[must_use]
    pub fn flags(&self) -> SmdhFlags {
        self.flags
    }
    #[must_use]
    pub fn eula_version(&self) -> &EulaVersion {
        &self.eula_version
    }
    #[must_use]
    pub fn optimal_animation_default_frame(&self) -> f32 {
        self.optimal_animation_default_frame
    }
    #[must_use]
    pub fn cec_id(&self) -> u32 {
        self.cec_id
    }
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
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }
    #[must_use]
    pub fn bit_id(&self) -> u64 {
        self.bit_id
    }
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

#[derive(Debug, Clone)]
#[repr(C)]
pub struct SmdhTitle {
    short_desc: SizedCStringUtf16<0x40>,
    long_desc: SizedCStringUtf16<0x80>,
    publisher: SizedCStringUtf16<0x40>,
}
assert_eq_size!([u8; 0x200], SmdhTitle);

impl SmdhTitle {
    #[must_use]
    pub fn short_desc(&self) -> &SizedCStringUtf16<0x40> {
        &self.short_desc
    }
    #[must_use]
    pub fn long_desc(&self) -> &SizedCStringUtf16<0x80> {
        &self.long_desc
    }
    #[must_use]
    pub fn publisher(&self) -> &SizedCStringUtf16<0x40> {
        &self.publisher
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct SmdhIcon {
    small: IconData<0x240>,
    big: IconData<0x900>,
}
assert_eq_size!([u8; 0x1680], SmdhIcon);

#[derive(Clone)]
pub struct IconData<const SIZE: usize> {
    data: [u16; SIZE],
}

impl<const SIZE: usize> IconData<SIZE> {
    #[must_use]
    pub fn raw_data(&self) -> &[u16; SIZE] {
        &self.data
    }
}

// gonna be procrastinating on that, comment for now to silence warnings
/*
#[cfg(feature = "embedded_graphics")]
use embedded_graphics::{
    prelude::*,
    pixelcolor::Rgb565,
    primitives::Rectangle,
};

#[cfg(feature = "embedded_graphics")]
impl<const SIZE: usize> IconData<SIZE> {
    const TILE_ORDER: [u8; 64] =
        [00,01,08,09,02,03,10,11,
         16,17,24,25,18,19,26,27,
         04,05,12,13,06,07,14,15,
         20,21,28,29,22,23,30,31,
         32,33,40,41,34,35,42,43,
         48,49,56,57,50,51,58,59,
         36,37,44,45,38,39,46,47,
         52,53,60,61,54,55,62,63];
    fn pixel(&self, x: u8, y: u8) -> u16 {
        let tile_x = x - x % 8;
        let tile_y = y - y % 8;

        let mut offset = None;
        for i in 0..64 {
            let tmp_x = Self::TILE_ORDER[i] & 0x7;
            let tmp_y = Self::TILE_ORDER[i] >> 3;
            if tmp_x == x % 8 && tmp_y == y % 8 {
                offset = Some(i as u8);
                break;
            }
        }
        self.data[(tile_y * 8 + tile_x + offset.unwrap()) as usize]
    }
}

#[cfg(feature = "embedded_graphics")]
impl<const SIZE: usize> ImageDrawable for IconData<SIZE> {
    type Color = Rgb565;

    fn draw<D>(&self, target: &mut D) -> CytrynaResult<(), D::Error>
        where D: DrawTarget<Color = Self::Color>
    {
        todo!()
    }
    fn draw_sub_image<D>(&self, target: &mut D, area: &Rectangle) -> CytrynaResult<(), D::Error>
        where D: DrawTarget<Color = Self::Color>
    {
        todo!()
    }
}

#[cfg(feature = "embedded_graphics")]
impl<const SIZE: usize> OriginDimensions for IconData<SIZE> {
    fn size(&self) -> Size {
        match SIZE {
            0x240 => Size::new(24, 24),
            0x900 => Size::new(48, 48),
            _ => panic!("Unsupported SMDH icon size"),
        }
    }
}
*/
