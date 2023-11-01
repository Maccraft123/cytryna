use std::sync::OnceLock;
use std::collections::HashMap;

pub type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

static KEY_BAG: OnceLock<KeyBag> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct KeyBag {
    keys: HashMap<KeyIndex, [u8; 0x10]>,
}

impl KeyBag {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new()
        }
    }
    pub fn set_key(&mut self, idx: KeyIndex, key: [u8; 0x10]) {
        self.keys.insert(idx, key);
    }
    pub fn finalize(self) {
        let _ = KEY_BAG.set(self);
    }
    pub fn get_key(&self, idx: KeyIndex) -> Option<&[u8; 0x10]> {
        self.keys.get(&idx)
    }
    pub fn global() -> Option<&'static Self> {
        KEY_BAG.get()
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum KeyIndex {
    Generator,
    Slot(u8, KeyType),
    Common(u8),
    CommonN(u8),
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum KeyType {
    X,
    Y,
    N,
}
