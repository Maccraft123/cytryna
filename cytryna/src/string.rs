use core::{fmt, str};

use std::{borrow::Cow, string};

use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum SizedCStringError {
    #[snafu(display("Input string too big to fit into storage"))]
    TooBig,
}

#[derive(Clone)]
#[repr(transparent)]
pub struct SizedCString<const SIZE: usize>([u8; SIZE]);

impl<const SIZE: usize> SizedCString<SIZE> {
    #[must_use]
    pub fn as_str(&self) -> Result<&str, str::Utf8Error> {
        str::from_utf8(&self.0)
    }
    #[must_use]
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.0)
    }
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|v| *v == 0)
    }
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.0
    }
}

impl<const SIZE: usize> From<[u8; SIZE]> for SizedCString<SIZE> {
    fn from(other: [u8; SIZE]) -> SizedCString<SIZE> {
        SizedCString(other)
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct SizedCStringUtf16<const SIZE: usize> {
    data: [u16; SIZE],
}

impl<const SIZE: usize> SizedCStringUtf16<SIZE> {
    #[must_use]
    pub fn to_string(&self) -> Result<String, string::FromUtf16Error> {
        String::from_utf16(&self.data)
    }
    #[must_use]
    pub fn to_string_lossy(&self) -> String {
        String::from_utf16_lossy(&self.data)
    }
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.data.iter().all(|v| *v == 0)
    }
    #[must_use]
    pub fn data(&self) -> &[u16] {
        &self.data
    }
}

impl<const SIZE: usize> TryFrom<&str> for SizedCStringUtf16<SIZE> {
    type Error = SizedCStringError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut data: Vec<u16> = value.encode_utf16().collect();
        if data.len() > SIZE {
            return Err(SizedCStringError::TooBig);
        }
        data.resize(SIZE, 0u16);
        Ok(Self { data: data.try_into().unwrap() })
    }
}

impl<const SIZE: usize> fmt::Debug for SizedCString<SIZE> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_fmt(format_args!("\"{}\"", self.to_string_lossy()))
    }
}

impl<const SIZE: usize> fmt::Debug for SizedCStringUtf16<SIZE> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_fmt(format_args!("\"{}\"", self.to_string_lossy()))
    }
}
