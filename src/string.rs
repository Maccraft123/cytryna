use std::{fmt, string, str, mem, borrow::Cow};

#[derive(Clone)]
#[repr(transparent)]
pub struct SizedCString<const SIZE: usize>([u8; SIZE]);

impl<const SIZE: usize> SizedCString<SIZE> {
    pub fn as_str(&self) -> Result<&str, str::Utf8Error> {
        str::from_utf8(&self.0)
    }
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.0)
    }
    pub fn is_zero(&self) -> bool { self.0.iter().all(|v| *v == 0) }
    pub fn data(&self) -> &[u8] { &self.0 }
}

#[derive(Clone)]
#[repr(C)]
pub struct SizedCStringUtf16<const SIZE: usize> {
    data: [u16; SIZE]
}

impl<const SIZE: usize> SizedCStringUtf16<SIZE> {
    pub fn to_string(&self) -> Result<String, string::FromUtf16Error> {
        String::from_utf16(&self.data)
    }
    pub fn to_string_lossy(&self) -> String {
        String::from_utf16_lossy(&self.data)
    }
    pub fn is_zero(&self) -> bool { self.data.iter().all(|v| *v == 0) }
    pub fn data(&self) -> &[u16] { &self.data }
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

