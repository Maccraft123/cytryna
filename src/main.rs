mod ncch;
mod cia;
mod titleid;
mod tmd;
mod smdh;
mod string;
mod crypto;
mod ticket;

use ncch::Ncch;
use cia::Cia;
use smdh::Language;
use crypto::{KeyBag, KeyIndex};

fn main() {
    let mut keybag = KeyBag::new();
    //keybag.set_key(KeyIndex::CommonN(0), [REDACTED TO NOT GET SUED BY BIG N]);
    keybag.finalize();
    let file = std::env::args().nth(1).unwrap();
    let data = std::fs::read(file).unwrap();
    let cia = Cia::from_slice(&data);
    println!("{:x?}", cia.ticket_region().unwrap().title_key().unwrap());
}


