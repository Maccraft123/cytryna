
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct Smdh {
    magic: [u8; 4],
    version: u16,
    _reserved0: u16,
    titles: [u8; 0x2000],
    settings: [u8; 0x30],
    _reserved1: u64,
    icon: [u8; 0x1680],
}
