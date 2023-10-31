use std::sync::OnceLock;

pub(crate) static KEY_BAG: OnceLock<KeyBag> = OnceLock::new();

pub struct KeyBag {
    common_keys: [Option<[u8; 0x10]>; 2],
}

impl KeyBag {
    pub fn new() -> Self {
        Self {
            common_keys: [None, None],
        }
    }
    pub fn set_common_key(&mut self, key: [u8; 0x10], idx: usize) {
        self.common_keys[idx] = Some(key);
    }
    pub fn set(self) {
        let _ = KEY_BAG.set(self);
    }
}
