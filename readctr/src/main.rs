use cytryna::{
    ncch::Ncch,
    cia::Cia,
    smdh::Language,
    crypto::{KeyBag, KeyIndex},
    ncch,
};
use std::mem;

fn main() {
    let mut keybag = KeyBag::new();
    keybag.set_key(KeyIndex::CommonN(0), [0x64, 0xC5, 0xFD, 0x55, 0xDD, 0x3A, 0xD9, 0x88, 0x32, 0x5B, 0xAA, 0xEC, 0x52, 0x43, 0xDB, 0x98]);
    keybag.finalize();
    let file = std::env::args().nth(1).unwrap();
    let data = std::fs::read(file).unwrap();
    let cia = Cia::from_slice(&data);
    println!("{:#x?}", cia.header());
    let tmd = cia.tmd_region().unwrap();
    for chunk in tmd.content_chunks() {
        println!("{:x}", chunk.size());
        println!("{:x}", chunk.ty());
        println!("{:?}", chunk.idx());
    }
    let ncch = cia.content_region().unwrap().next().unwrap();
    println!("{:#?}", Ncch::from_slice(ncch.data()).header());
}


