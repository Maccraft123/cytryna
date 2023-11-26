use std::mem;
use std::slice;

use crate::string::{SizedCString, SizedCStringError, SizedCStringUtf16};
use crate::{CytrynaError, CytrynaResult, FromBytes};

use bitflags::bitflags;
use bmp::{px, Pixel};
use derivative::Derivative;
use modular_bitfield::prelude::*;
use static_assertions::assert_eq_size;
use thiserror::Error;

/// SMDH error type
#[derive(Error, Debug)]
pub enum SmdhError {
    #[error("Missing short description")]
    MissingShortDesc,
    #[error("Missing long description")]
    MissingLongDesc,
    #[error("Missing publisher name")]
    MissingPublisher,
    #[error("Missing icon data")]
    MissingIcon,
    #[error("SizedCString error: {0}")]
    StringErr(#[from] SizedCStringError),
    #[error("Invalid image size, got: {got}, expected: {expected}")]
    InvalidImageSize { got: u32, expected: u32 },
    #[error("Only square images can be SMDH icons")]
    OnlySquaresAllowed,
}

type SmdhResult<T> = Result<T, SmdhError>;

/// SMDH builder
///
/// # Examples
///
/// ```
/// use cytryna::prelude::*;
///
/// let bmp_image = bmp::Image::new(48, 48);
/// let smdh = Smdh::builder()
///     .with_short_desc("An example")?
///     .with_long_desc("This is an example data")?
///     .with_publisher("Maya")?
///     .with_icon((&bmp_image).try_into()?)
///     .build()?;
///
/// # Ok::<(), cytryna::smdh::SmdhError>(())
/// ```
pub struct SmdhBuilder {
    short_desc: Option<SizedCStringUtf16<0x40>>,
    long_desc: Option<SizedCStringUtf16<0x80>>,
    publisher: Option<SizedCStringUtf16<0x40>>,
    big_icon: Option<Box<IconData<0x900>>>,
    small_icon: Option<Box<IconData<0x240>>>,
}

impl SmdhBuilder {
    /// Sets the short description
    pub fn with_short_desc(&mut self, desc: &str) -> SmdhResult<&mut Self> {
        let _ = self.short_desc.insert(desc.try_into()?);
        Ok(self)
    }
    /// Sets the long description
    pub fn with_long_desc(&mut self, desc: &str) -> SmdhResult<&mut Self> {
        let _ = self.long_desc.insert(desc.try_into()?);
        Ok(self)
    }
    /// Sets the publisher
    pub fn with_publisher(&mut self, publisher: &str) -> SmdhResult<&mut Self> {
        let _ = self.publisher.insert(publisher.try_into()?);
        Ok(self)
    }
    /// Sets the small icon data. If not set big icon will be shrunk down and used instead
    pub fn with_small_icon(&mut self, icon: IconData<0x240>) -> &mut Self {
        let _ = self.small_icon.insert(Box::new(icon));
        self
    }
    /// Sets the icon data
    pub fn with_icon(&mut self, icon: IconData<0x900>) -> &mut Self {
        let _ = self.big_icon.insert(Box::new(icon));
        self
    }
    /// Builds the SMDH
    pub fn build(&mut self) -> Result<Smdh, SmdhError> {
        let title = SmdhTitle {
            short_desc: self.short_desc.take().ok_or(SmdhError::MissingShortDesc)?,
            long_desc: self.long_desc.take().ok_or(SmdhError::MissingLongDesc)?,
            publisher: self.publisher.take().ok_or(SmdhError::MissingPublisher)?,
        };
        // lol
        let titles = [
            title.clone(),
            title.clone(),
            title.clone(),
            title.clone(),
            title.clone(),
            title.clone(),
            title.clone(),
            title.clone(),
            title.clone(),
            title.clone(),
            title.clone(),
            title.clone(),
            title.clone(),
            title.clone(),
            title.clone(),
            title,
        ];

        let mut age_ratings = [AgeRating::empty(); 16];
        for (i, rating) in age_ratings.iter_mut().enumerate() {
            if i == 2 || i == 5 || i >= 12 {
                continue;
            }
            *rating = AgeRating::NO_AGE_RESTRICTION | AgeRating::ENABLED;
        }

        let big = self.big_icon.take().ok_or(SmdhError::MissingIcon)?;
        let small = self.small_icon.take().unwrap_or_else(|| {
            let mut img_big = bmp::Image::new(48, 48);
            for (x, y, rgb) in big.pixel_iter() {
                img_big.set_pixel(
                    x as u32,
                    y as u32,
                    px!(rgb.r() << 3, rgb.g() << 2, rgb.b() << 3),
                );
            }
            let data: [Rgb565Pixel; 0x240] = [0u16; 0x240].map(|v| v.into());
            let mut this = IconData { data };
            for (x, y, rgb) in this.pixel_iter_mut() {
                let one = img_big.get_pixel(x as u32, y as u32);
                let two = img_big.get_pixel(x as u32, (y + 1) as u32);
                let three = img_big.get_pixel((x + 1) as u32, y as u32);
                let four = img_big.get_pixel((x + 1) as u32, (y + 1) as u32);
                let r = (one.r as u32 + two.r as u32 + three.r as u32 + four.r as u32) / 4;
                let g = (one.g as u32 + two.g as u32 + three.g as u32 + four.g as u32) / 4;
                let b = (one.b as u32 + two.b as u32 + three.b as u32 + four.b as u32) / 4;
                rgb.set_r(r as u8 >> 3);
                rgb.set_g(g as u8 >> 2);
                rgb.set_b(b as u8 >> 3);
            }

            Box::new(this)
        });

        Ok(Smdh {
            magic: SizedCString::from(*b"SMDH"),
            version: 0,
            _reserved0: 0,
            titles,
            age_ratings,
            region_lockout: RegionLockout::REGION_FREE,
            matchmaker_id: MatchmakerId { id: 0, bit_id: 0 },
            flags: SmdhFlags::VISIBLE_IN_HOMEMENU
                | SmdhFlags::REGION_RATING_REQUIRED
                | SmdhFlags::RECORD_USAGE,
            eula_version: EulaVersion { major: 0, minor: 0 },
            _reserved1: 0,
            optimal_animation_default_frame: 0f32,
            cec_id: 0,
            _reserved2: 0,
            icon: SmdhIcon {
                big: *big,
                small: *small,
            },
        })
    }
}

/// SMDH Header data
/// <https://www.3dbrew.org/wiki/SMDH>
#[derive(Derivative, Clone)]
#[derivative(Debug)]
#[repr(C)]
pub struct Smdh {
    magic: SizedCString<4>,
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

/// SMDH EULA Version
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
    /// Returns a byte slice pointing to data of this struct
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 0x36c0] {
        unsafe { mem::transmute(self) }
    }
    /// Returns the SMDH builder
    #[must_use]
    pub fn builder() -> SmdhBuilder {
        SmdhBuilder {
            big_icon: None,
            small_icon: None,
            long_desc: None,
            short_desc: None,
            publisher: None,
        }
    }
    /// Returns title data(in a given language)
    #[must_use]
    pub fn title(&self, lang: Language) -> &SmdhTitle {
        &self.titles[lang as usize]
    }
    /// Returns age rating data(of a given region)
    #[must_use]
    pub fn age_rating(&self, region: AgeRatingRegion) -> AgeRating {
        self.age_ratings[region as usize]
    }
    /// Returns region lockout data
    #[must_use]
    pub fn region_lockout(&self) -> RegionLockout {
        self.region_lockout
    }
    /// Returns the matchmaker id data
    #[must_use]
    pub fn matchmaker_id(&self) -> &MatchmakerId {
        &self.matchmaker_id
    }
    /// Returns SMDH Flags
    /// <https://www.3dbrew.org/wiki/SMDH#Flags>
    #[must_use]
    pub fn flags(&self) -> SmdhFlags {
        self.flags
    }
    /// Returns the EULA version
    /// <https://www.3dbrew.org/wiki/SMDH#EULA_Version>
    #[must_use]
    pub fn eula_version(&self) -> &EulaVersion {
        &self.eula_version
    }
    /// Returns optimal/preferred/most representative animation frame for banner animation
    #[must_use]
    pub fn optimal_animation_default_frame(&self) -> f32 {
        self.optimal_animation_default_frame
    }
    /// Returns the CEC/StreetPass id
    #[must_use]
    pub fn cec_id(&self) -> u32 {
        self.cec_id
    }
    /// Returns a reference to big icon data
    #[must_use]
    pub fn big_icon(&self) -> &IconData<0x900> {
        &self.icon.big
    }
    /// Returns a reference to small icon data
    #[must_use]
    pub fn small_icon(&self) -> &IconData<0x240> {
        &self.icon.small
    }
}

/// Age Rating Region index
/// <https://www.3dbrew.org/wiki/SMDH#Region_Specific_Game_Age_Ratings>
#[derive(Debug, Clone, Copy)]
#[repr(usize)]
pub enum AgeRatingRegion {
    Cero = 0,
    Esrb = 1,
    // reserved
    Usk = 3,
    PegiGen = 4,
    // reserved
    PegiPrt = 5,
    PegiBbfc = 6,
    Cob = 7,
    Grb = 8,
    Cgsrr = 9,
}

bitflags! {
    /// Age Rating Data
    /// https://www.3dbrew.org/wiki/SMDH#Region_Specific_Game_Age_Ratings
    #[derive(Debug, Clone, Copy)]
    pub struct AgeRating: u8 {
        const ENABLED = 0x80;
        const PENDING = 0x40;
        const NO_AGE_RESTRICTION = 0x20;
        const _ = !0;
    }

    /// Region Lockout Data
    /// https://www.3dbrew.org/wiki/SMDH#Region_Lockout
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

    /// SMDH Flags data
    /// https://www.3dbrew.org/wiki/SMDH#Flags
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

/// Matchmaker ID data
/// <https://www.3dbrew.org/wiki/SMDH#Match_Maker_IDs>
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct MatchmakerId {
    id: u32,
    bit_id: u64,
}
assert_eq_size!([u8; 0xc], MatchmakerId);

impl MatchmakerId {
    /// Returns the ID
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }
    /// Returns the "bit ID"
    #[must_use]
    pub fn bit_id(&self) -> u64 {
        self.bit_id
    }
}

/// SMDH Title language index
/// <https://www.3dbrew.org/wiki/SMDH#Application_Titles>
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

/// SMDH Application title data
/// <https://www.3dbrew.org/wiki/SMDH#Application_Titles>
#[derive(Debug, Clone)]
#[repr(C)]
pub struct SmdhTitle {
    short_desc: SizedCStringUtf16<0x40>,
    long_desc: SizedCStringUtf16<0x80>,
    publisher: SizedCStringUtf16<0x40>,
}
assert_eq_size!([u8; 0x200], SmdhTitle);

impl SmdhTitle {
    /// Returns the short description data
    #[must_use]
    pub fn short_desc(&self) -> &SizedCStringUtf16<0x40> {
        &self.short_desc
    }
    /// Returns the long description data
    #[must_use]
    pub fn long_desc(&self) -> &SizedCStringUtf16<0x80> {
        &self.long_desc
    }
    /// Returns publisher data
    #[must_use]
    pub fn publisher(&self) -> &SizedCStringUtf16<0x40> {
        &self.publisher
    }
}

/// SMDH Icon data wrapper
/// <https://www.3dbrew.org/wiki/SMDH#Icon_graphics>
#[derive(Clone)]
#[repr(C)]
pub struct SmdhIcon {
    small: IconData<0x240>,
    big: IconData<0x900>,
}
assert_eq_size!([u8; 0x1680], SmdhIcon);

/// SMDH Icon Data(actual)
#[derive(Clone)]
#[repr(C)]
pub struct IconData<const SIZE: usize> {
    data: [Rgb565Pixel; SIZE],
}

/// SMDH Pixel data, it's actually BGR and not RGB
#[bitfield]
#[derive(Clone, Debug)]
#[repr(u16)]
pub struct Rgb565Pixel {
    b: B5,
    g: B6,
    r: B5,
}

impl Rgb565Pixel {
    /// Copies an image::Pixel<Subpixel = u8> into Rgb565Pixel
    /// It is not implemented as a From trait impl as that makes a compiler error
    fn from_image_pixel_subpixel_u8<T>(pixel: T) -> Self
    where
        T: image::Pixel<Subpixel = u8>,
    {
        let rgb = pixel.to_rgb();
        Self::new()
            .with_r(rgb.0[0] << 3)
            .with_g(rgb.0[1] << 4)
            .with_b(rgb.0[2] << 3)
    }
    /*fn from_image_pixel_subpixel_f32<T>(pixel: T) -> Self
    where
        T: image::Pixel<Subpixel = f32>,
    {
        let rgb = pixel.to_rgb();
        Self::new()
            .with_r((rgb.0[0] * 31.0) as u8) // scale from 0.0-1.0 to 0-31
            .with_g((rgb.0[1] * 63.0) as u8) // scale from 0.0-1.0 to 0-63
            .with_b((rgb.0[2] * 31.0) as u8) // scale from 0.0-1.0 to 0-31
    }*/
}

/// SMDH icon tile order
/// shamelessly stolen from smdhtool
const TILE_ORDER: [u8; 64] = [
    00, 01, 08, 09, 02, 03, 10, 11, 16, 17, 24, 25, 18, 19, 26, 27, 04, 05, 12, 13, 06, 07, 14, 15,
    20, 21, 28, 29, 22, 23, 30, 31, 32, 33, 40, 41, 34, 35, 42, 43, 48, 49, 56, 57, 50, 51, 58, 59,
    36, 37, 44, 45, 38, 39, 46, 47, 52, 53, 60, 61, 54, 55, 62, 63,
];

impl<const SIZE: usize> IconData<SIZE> {
    /// Returns the raw imge data
    #[must_use]
    pub fn raw_data(&self) -> &[Rgb565Pixel; SIZE] {
        &self.data
    }
    /// Gets the width of the icon
    #[must_use]
    pub fn width() -> u8 {
        if SIZE == 0x240 {
            24
        } else if SIZE == 0x900 {
            48
        } else {
            unreachable!("how the f-")
        }
    }
    /// Returns an iterator over x and y coordinates and an immutable refernce to Rgb565Pixel in that coordinates
    #[must_use]
    pub fn pixel_iter(&self) -> PixelIterator<SIZE> {
        PixelIterator {
            inner: self.data.iter(),
            width: Self::width(),
            i: 0,
            j: 0,
            k: 0,
        }
    }
    /// Returns an iterator over x and y coordinates and a mutable refernce to Rgb565Pixel in that coordinates
    #[must_use]
    pub fn pixel_iter_mut(&mut self) -> PixelIteratorMut<SIZE> {
        PixelIteratorMut {
            inner: self.data.iter_mut(),
            width: Self::width(),
            i: 0,
            j: 0,
            k: 0,
        }
    }
    /// Copies this icon into a new BMP Image
    #[must_use]
    pub fn to_bmp(&self) -> bmp::Image {
        let mut img = bmp::Image::new(Self::width() as u32, Self::width() as u32);
        for (x, y, rgb) in self.pixel_iter() {
            img.set_pixel(
                x as u32,
                y as u32,
                px!(rgb.r() << 3, rgb.g() << 2, rgb.b() << 3),
            );
        }
        img
    }
}

impl<const SIZE: usize> TryFrom<&bmp::Image> for IconData<SIZE> {
    type Error = SmdhError;

    fn try_from(src: &bmp::Image) -> Result<Self, Self::Error> {
        if src.get_width() != src.get_height() {
            return Err(SmdhError::OnlySquaresAllowed);
        }
        if src.get_width() * src.get_width() != SIZE as u32 {
            return Err(SmdhError::InvalidImageSize {
                got: src.get_width() * src.get_width(),
                expected: SIZE as u32,
            });
        }
        let data: [Rgb565Pixel; SIZE] = [0u16; SIZE].map(|v| v.into());
        let mut this = Self { data };
        for (x, y, rgb) in this.pixel_iter_mut() {
            let rgb888 = src.get_pixel(x as u32, y as u32);
            rgb.set_r(rgb888.r >> 3);
            rgb.set_g(rgb888.g >> 2);
            rgb.set_b(rgb888.b >> 3);
        }
        Ok(this)
    }
}

impl<const SIZE: usize> TryFrom<&image::DynamicImage> for IconData<SIZE> {
    type Error = SmdhError;

    fn try_from(src: &image::DynamicImage) -> Result<Self, Self::Error> {
        if src.width() != src.height() {
            return Err(SmdhError::OnlySquaresAllowed);
        }
        if src.width() * src.width() != SIZE as u32 {
            return Err(SmdhError::InvalidImageSize {
                got: src.width() * src.width(),
                expected: SIZE as u32,
            });
        }

        let data: [Rgb565Pixel; SIZE] = [0u16; SIZE].map(|v| v.into());
        let src = src.to_rgb8();
        let mut this = Self { data };
        for (x, y, rgb) in this.pixel_iter_mut() {
            *rgb = Rgb565Pixel::from_image_pixel_subpixel_u8(src.get_pixel(x as u32, y as u32).to_owned());
        }
        Ok(this)
    }
}

/// An iterator over x and y coordinates and a mutable refernce to Rgb565Pixel in that coordinates
#[derive(Debug)]
pub struct PixelIteratorMut<'a, const SIZE: usize> {
    inner: slice::IterMut<'a, Rgb565Pixel>,
    width: u8,
    j: u8,
    i: u8,
    k: u8,
}

impl<'a, const SIZE: usize> Iterator for PixelIteratorMut<'a, SIZE> {
    type Item = (u8, u8, &'a mut Rgb565Pixel);

    fn next(&mut self) -> Option<(u8, u8, &'a mut Rgb565Pixel)> {
        let x = (TILE_ORDER[self.k as usize] & 0x7) + self.i;
        let y = (TILE_ORDER[self.k as usize] >> 3) + self.j;
        let rgb = self.inner.next()?;

        self.k += 1;
        if self.k == 64 {
            self.k = 0;
            self.i += 8;
            if self.i == self.width {
                self.i = 0;
                self.j += 8;
            }
        }

        Some((x, y, rgb))
    }
}

/// An iterator over x and y coordinates and an immutable refernce to Rgb565Pixel in that coordinates
#[derive(Debug)]
pub struct PixelIterator<'a, const SIZE: usize> {
    inner: slice::Iter<'a, Rgb565Pixel>,
    width: u8,
    j: u8,
    i: u8,
    k: u8,
}

impl<'a, const SIZE: usize> Iterator for PixelIterator<'a, SIZE> {
    type Item = (u8, u8, &'a Rgb565Pixel);

    fn next(&mut self) -> Option<(u8, u8, &'a Rgb565Pixel)> {
        let x = (TILE_ORDER[self.k as usize] & 0x7) + self.i;
        let y = (TILE_ORDER[self.k as usize] >> 3) + self.j;
        let rgb = self.inner.next()?;

        self.k += 1;
        if self.k == 64 {
            self.k = 0;
            self.i += 8;
            if self.i == self.width {
                self.i = 0;
                self.j += 8;
            }
        }

        Some((x, y, rgb))
    }
}

#[cfg(test)]
mod tests {
    use super::IconData;
    use bmp::Pixel;

    #[test]
    fn bmp_to_smdh_to_bmp_24() {
        let mut src = bmp::Image::new(24, 24);
        for (x, y) in src.coordinates() {
            let r = (rand::random::<bool>() as u8) << 7;
            let g = (rand::random::<bool>() as u8) << 7;
            let b = (rand::random::<bool>() as u8) << 7;
            src.set_pixel(x, y, bmp::px!(r, g, b));
        }

        let dst: IconData<0x240> = (&src).try_into().unwrap();
        let other_src: bmp::Image = dst.to_bmp();

        assert_eq!(src, other_src);
    }

    #[test]
    fn bmp_to_smdh_to_bmp_48() {
        let mut src = bmp::Image::new(48, 48);
        for (x, y) in src.coordinates() {
            let r = (rand::random::<bool>() as u8) << 7;
            let g = (rand::random::<bool>() as u8) << 7;
            let b = (rand::random::<bool>() as u8) << 7;
            src.set_pixel(x, y, bmp::px!(r, g, b));
        }

        let dst: IconData<0x900> = (&src).try_into().unwrap();
        let other_src: bmp::Image = dst.to_bmp();

        assert_eq!(src, other_src);
    }
}
