use std::mem;

use crate::crypto::sha256;
use crate::string::SizedCString;
use crate::FromBytes;
use crate::{align_up, CytrynaError, CytrynaResult};

use derivative::Derivative;
use hex_literal::hex;
use static_assertions::assert_eq_size;
use thiserror::Error;

// source: https://gist.github.com/SciresM/cdd2266efb80175d37eabbe86f9d8c52
static RETAIL_NAND_FIRM: [u8; 0x100] = hex!("B6724531C448657A2A2EE306457E350A10D544B42859B0E5B0BED27534CCCC2A4D47EDEA60A7DD99939950A6357B1E35DFC7FAC773B7E12E7C1481234AF141B31CF08E9F62293AA6BAAE246C15095F8B78402A684D852C680549FA5B3F14D9E838A2FB9C09A15ABB40DCA25E40A3DDC1F58E79CEC901974363A946E99B4346E8A372B6CD55A707E1EAB9BEC0200B5BA0B661236A8708D704517F43C6C38EE9560111E1405E5E8ED356C49C4FF6823D1219AFAEEB3DF3C36B62BBA88FC15BA8648F9333FD9FC092B8146C3D908F73155D48BE89D72612E18E4AA8EB9B7FD2A5F7328C4ECBFB0083833CBD5C983A25CEB8B941CC68EB017CE87F5D793ACA09ACF7");
static RETAIL_NTR_FIRM: [u8; 0x100] = hex!("37E96B10BAF28C74A710EF35824C93F5FBB341CEE4FB446CE4D290ABFCEFACB063A9B55B3E8A65511D900C5A6E9403AAB5943CEF3A1E882B77D2347942B9E9EB0D7566370F0CB7310C38CB4AC940D1A6BB476BCC2C487D1C532120F1D2A37DDB3E36F8A2945BD8B16FB354980384998ECC380CD5CF8530F1DAD2FD74BA35ACB9C9DA2C131CB295736AE7EFA0D268EE01872EF033058ABA07B5C684EAD60D76EA84A18D866307AAAAB764786E396F2F8B630E60E30E3F1CD8A67D02F0A88152DE7A9E0DD5E64AB7593A3701E4846B6F338D22FD455D45DF212C5577266AA8C367AE6E4CE89DF41691BF1F7FE58F2261F5D251DF36DE9F5AF1F368E650D576810B");
static RETAIL_SPI_FIRM: [u8; 0x100] = RETAIL_NTR_FIRM;

/// FIRM header data
/// <https://www.3dbrew.org/wiki/FIRM#FIRM_Header>
#[derive(Derivative, Clone)]
#[derivative(Debug)]
#[repr(C)]
pub struct FirmHeader {
    magic: SizedCString<4>,
    boot_priority: u32,
    arm11_entrypoint: u32,
    arm9_entrypoint: u32,
    #[derivative(Debug = "ignore")]
    _reserved: [u8; 0x30],
    firmware_section_headers: [SectionHeader; 4],
    rsa2048_sig: [u8; 0x100],
}
assert_eq_size!([u8; 0x200], FirmHeader);

impl FirmHeader {
    /// Returns the boot priority, higher value = higher boot priority
    #[must_use]
    pub fn boot_priority(&self) -> u32 {
        self.boot_priority
    }
    /// Returns entry point address for the ARM11 CPU
    #[must_use]
    pub fn arm11_entrypoint(&self) -> u32 {
        self.arm11_entrypoint
    }
    /// Returns entry point address for ARM9 CPU
    #[must_use]
    pub fn arm9_entrypoint(&self) -> u32 {
        self.arm9_entrypoint
    }
    /// Returns a reference to array of section headers
    #[must_use]
    pub fn sections(&self) -> &[SectionHeader; 4] {
        &self.firmware_section_headers
    }
    /// Returns an iterator over section headers, ignoring headers that aren't used(have size of 0)
    pub fn section_iter(&self) -> impl Iterator<Item = &SectionHeader> {
        self.firmware_section_headers
            .iter()
            .filter(|section| section.size != 0)
    }
    /// Returns a reference to raw signature data
    #[must_use]
    pub fn sig(&self) -> &[u8; 0x100] {
        &self.rsa2048_sig
    }
}

/// FIRM Section Header
/// <https://www.3dbrew.org/wiki/FIRM#Firmware_Section_Headers>
#[derive(Derivative, Clone)]
#[derivative(Debug)]
#[repr(C)]
pub struct SectionHeader {
    offset: u32,
    phys_addr: u32,
    size: u32,
    copy_method: CopyMethod,
    hash: [u8; 0x20],
}
assert_eq_size!([u8; 0x30], SectionHeader);

impl SectionHeader {
    /// Makes an empty header
    pub(crate) fn empty() -> SectionHeader {
        Self {
            offset: 0,
            phys_addr: 0,
            size: 0,
            copy_method: CopyMethod::Ndma,
            hash: [0u8; 0x20],
        }
    }
    /// Returns offset in FIRM file of this section
    #[must_use]
    pub fn offset(&self) -> u32 {
        self.offset
    }
    /// Returns the load address of this sectoin
    #[must_use]
    pub fn load_addr(&self) -> u32 {
        self.phys_addr
    }
    /// Returns the copy method of this section
    #[must_use]
    pub fn copy_method(&self) -> CopyMethod {
        self.copy_method
    }
    /// Returns raw SHA256 hash data of this section
    #[must_use]
    pub fn hash(&self) -> &[u8; 0x20] {
        &self.hash
    }
}

/// Contains copy method of a section
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum CopyMethod {
    /// NDMA
    Ndma = 0,
    /// XDMA
    Xdma,
    /// memcpy()
    CpuMemcpy,
}

/// An error type for FirmBuilder
#[derive(Error, Debug)]
pub enum FirmBuilderError {
    #[error("Tried to add more than firware 4 sections")]
    TooManySections,
    #[error("Arm9 entry point is missing")]
    NoArm9Entry,
    #[error("Arm11 entry point is missing")]
    NoArm11Entry,
    #[error("Firmware sections are missing")]
    NoSections,
    #[error("Signature type is missing")]
    NoSig,
}

/// Contains signature data or sighax signature type
#[derive(Debug, Clone)]
pub enum FirmSignature {
    /// Sighaxed signature for NAND-booting
    RetailSighaxNand,
    /// Sighaxed signature for ntrboot
    RetailSighaxNtr,
    /// Sighaxed signature for SPI-boot
    RetailSighaxSpi,
    /// Custom signature data
    Custom(Box::<[u8; 0x100]>)
}

/// FIRM builder
#[derive(Debug, Clone)]
pub struct FirmBuilder {
    boot_priority: u32,
    arm11_entrypoint: Option<u32>,
    arm9_entrypoint: Option<u32>,
    fw_sections: [Option<FirmwareSection>; 4],
    signature: Option<FirmSignature>,
}

impl FirmBuilder {
    /// Sets the boot priority, default is 0
    pub fn boot_priority(&mut self, val: u32) -> &mut Self {
        self.boot_priority = val;
        self
    }
    /// Sets the ARM11 entry point
    pub fn arm11_entrypoint(&mut self, val: u32) -> &mut Self {
        self.arm11_entrypoint = Some(val);
        self
    }
    /// Sets the ARM9 entry point
    pub fn arm9_entrypoint(&mut self, val: u32) -> &mut Self {
        self.arm9_entrypoint = Some(val);
        self
    }
    /// Sets the signature
    pub fn signature(&mut self, sig: FirmSignature) -> &mut Self {
        self.signature = Some(sig);
        self
    }
    /// Adds a FirmwareSection
    pub fn add_fw_section(
        &mut self,
        section: FirmwareSection,
    ) -> Result<&mut Self, FirmBuilderError> {
        let slot = self
            .fw_sections
            .iter_mut()
            .find(|v| v.is_none())
            .ok_or(FirmBuilderError::TooManySections)?;
        *slot = Some(section);
        Ok(self)
    }
    /// Overrides a section of a given index
    pub fn override_section(&mut self, which: usize, section: FirmwareSection) -> &mut Self {
        self.fw_sections[which] = Some(section);
        self
    }
    /// Builds the FIRM
    pub fn build(&mut self) -> Result<Vec<u8>, FirmBuilderError> {
        let arm11_entrypoint = self
            .arm11_entrypoint
            .ok_or(FirmBuilderError::NoArm11Entry)?;
        let arm9_entrypoint = self.arm9_entrypoint.ok_or(FirmBuilderError::NoArm9Entry)?;
        let file_size = self
            .fw_sections
            .iter()
            .flatten()
            .map(|s| s.data.len())
            .reduce(|acc, size| acc + size)
            .ok_or(FirmBuilderError::NoSections)?
            + mem::size_of::<FirmHeader>();

        let sig = match self.signature.take().ok_or(FirmBuilderError::NoSig)? {
            FirmSignature::RetailSighaxNand => RETAIL_NAND_FIRM,
            FirmSignature::RetailSighaxNtr => RETAIL_NTR_FIRM,
            FirmSignature::RetailSighaxSpi => RETAIL_SPI_FIRM,
            FirmSignature::Custom(sig) => *sig,
        };

        let mut header = FirmHeader {
            magic: (*b"FIRM").into(),
            boot_priority: self.boot_priority,
            arm11_entrypoint,
            arm9_entrypoint,
            _reserved: [0u8; 0x30],
            firmware_section_headers: [
                SectionHeader::empty(),
                SectionHeader::empty(),
                SectionHeader::empty(),
                SectionHeader::empty(),
            ],
            rsa2048_sig: sig,
        };

        let mut buf = Vec::with_capacity(file_size);
        buf.resize(0x200, 0);

        let mut offset = 0x200;
        for (i, mut s) in self.fw_sections.clone().into_iter().flatten().enumerate() {
            // https://github.com/derrekr/ctr_firm_builder aligns to 0x200
            let size = align_up(s.data.len() as u32, 0x200);
            s.data.resize(size as usize, 0);

            let hash = sha256(&s.data);
            let hdr = SectionHeader {
                offset,
                phys_addr: s.addr,
                size: s.data.len() as u32,
                copy_method: s.copy_method,
                hash,
            };
            offset += size;
            header.firmware_section_headers[i] = hdr;
            buf.extend(s.data);
        }

        unsafe {
            let vec_ptr = buf.as_mut_ptr();
            let header_ptr = &header as *const FirmHeader as *const u8;
            vec_ptr.copy_from_nonoverlapping(header_ptr, mem::size_of::<FirmHeader>());
        }

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use crate::{FromBytes};
    use super::{Firm, FirmwareSection, FirmSignature};
    #[test]
    fn test_firm_building() {
        let input = include_bytes!("../testdata/fastboot3DS.firm");
        let input_firm = Firm::from_bytes(input).unwrap();

        let hdr = input_firm.header();
        let boot_priority = hdr.boot_priority();
        let arm11_entry = hdr.arm11_entrypoint();
        let arm9_entry = hdr.arm9_entrypoint();

        let mut firm_builder = Firm::builder();
        firm_builder.boot_priority(boot_priority)
            .arm11_entrypoint(arm11_entry)
            .arm9_entrypoint(arm9_entry)
            .signature(FirmSignature::Custom(Box::new(hdr.sig().clone())));

        for section in hdr.section_iter() {
            let load_addr = section.load_addr();
            let copy_method = section.copy_method();
            let data = input_firm.section_data(section).to_vec();

            firm_builder.add_fw_section(FirmwareSection::new(data, load_addr, copy_method)).unwrap();
        }

        let firm = firm_builder.build().unwrap();

        assert!(Firm::from_bytes(&firm).is_ok());
    }
}

/// Contains Firmware Section data used in FIRM building
#[derive(Debug, Clone)]
pub struct FirmwareSection {
    data: Vec<u8>,
    addr: u32,
    copy_method: CopyMethod,
}

impl FirmwareSection {
    /// Creates an instance of FirmwareSection
    pub fn new(data: Vec<u8>, addr: u32, copy_method: CopyMethod) -> Self {
        Self {
            data,
            addr,
            copy_method,
        }
    }
}

/// FIRM file
/// <https://www.3dbrew.org/wiki/FIRM>
#[repr(C)]
pub struct Firm {
    header: FirmHeader,
    data: [u8],
}

impl FromBytes for Firm {
    fn min_size() -> usize {
        mem::size_of::<FirmHeader>()
    }
    fn bytes_ok(bytes: &[u8]) -> CytrynaResult<()> {
        if bytes[0..4] != *b"FIRM" {
            return Err(CytrynaError::InvalidMagic);
        }
        Ok(())
    }
    fn cast(bytes: &[u8]) -> &Firm {
        unsafe { mem::transmute(bytes) }
    }
    fn hash_ok(&self) -> bool {
        for section in self.header.section_iter() {
            let data = self.section_data(section);
            if sha256(data) != section.hash {
                return false;
            }
        }
        true
    }
}

impl Firm {
    /// Returns the builder for creating FIRM files
    #[must_use]
    pub fn builder() -> FirmBuilder {
        FirmBuilder {
            boot_priority: 0,
            arm11_entrypoint: None,
            arm9_entrypoint: None,
            fw_sections: [None, None, None, None],
            signature: None,
        }
    }
    /// Returns section data as a byte slice of a given header
    #[must_use]
    pub fn section_data(&self, section: &SectionHeader) -> &[u8] {
        let offset = section.offset as usize - mem::size_of::<FirmHeader>();
        &self.data[offset..][..section.size as usize]
    }
    /// Returns a reference to FIRM Header
    #[must_use]
    pub fn header(&self) -> &FirmHeader {
        &self.header
    }
}
