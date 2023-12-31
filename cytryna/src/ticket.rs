use core::mem;

use crate::crypto::{aes128_ctr::*, KeyBag, KeyIndex, SignedData};
use crate::titleid::MaybeTitleIdBe;
use crate::{CytrynaResult, FromBytes};

use derivative::Derivative;

/// Ticket Data, excluding "Issuer" field
/// <https://www.3dbrew.org/wiki/Ticket#Ticket_Data>
#[derive(Derivative)]
#[derivative(Debug)]
#[repr(C, packed)]
pub struct TicketInner {
    ecc_pubkey: [u8; 0x3c],
    version: u8,
    ca_crl_version: u8,
    signer_crl_version: u8,
    title_key: [u8; 0x10],
    #[derivative(Debug = "ignore")]
    _reserved0: u8,
    ticket_id: [u8; 0x8],
    console_id: [u8; 0x4],
    title_id: MaybeTitleIdBe,
    #[derivative(Debug = "ignore")]
    _reserved1: [u8; 0x2],
    ticket_title_version: [u8; 0x2],
    #[derivative(Debug = "ignore")]
    _reserved2: [u8; 0x8],
    license_type: u8,
    key_index: u8,
    #[derivative(Debug = "ignore")]
    _reserved3: [u8; 0x2a],
    maybe_eshop_account_id: [u8; 0x4],
    #[derivative(Debug = "ignore")]
    _reserved4: u8,
    audit: u8,
    #[derivative(Debug = "ignore")]
    _reserved5: [u8; 0x42],
    limits: [u8; 0x40],
    #[derivative(Debug = "ignore")]
    content_index: [u8],
}

impl FromBytes for TicketInner {
    fn min_size() -> usize {
        // https://www.3dbrew.org/wiki/Ticket#Ticket_Data
        0x124
    }
    fn bytes_ok(_: &[u8]) -> CytrynaResult<()> {
        Ok(())
    }
    fn cast(bytes: &[u8]) -> &Self {
        unsafe { mem::transmute(bytes) }
    }
}

/// Type alias for convienent usage of TicketInner
pub type Ticket<'a> = SignedData<'a, TicketInner>;

impl Ticket<'_> {
    /// Returns the decrypted title key
    pub fn title_key(&self) -> CytrynaResult<[u8; 0x10]> {
        let mut iv = [0u8; 0x10];
        iv[..0x8].copy_from_slice(&self.data().title_id.to_bytes());

        let mut title_key = self.data().title_key;
        let idx = self.data().key_index;
        let key = KeyBag::global()?.get_key(KeyIndex::CommonN(idx))?;

        Aes128CbcDec::new(key.into(), &iv.into())
            .decrypt_padded_mut::<NoPadding>(&mut title_key)
            .unwrap();
        Ok(title_key)
    }
    /// Returns the un-decrypted title key
    #[must_use]
    pub fn title_key_raw(&self) -> &[u8; 0x10] {
        &self.data().title_key
    }
    /// Returns the common key index
    #[must_use]
    pub fn key_index(&self) -> u8 {
        self.data().key_index
    }
}
