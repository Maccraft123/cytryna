mod ncch;
mod cia;
mod titleid;
mod tmd;
mod smdh;

use ncch::Ncch;
use cia::Cia;
use smdh::Language;

fn main() {
    let file = std::env::args().nth(1).unwrap();
    let data = std::fs::read(file).unwrap();
    let cia = Cia::from_slice(&data);
    println!("{:#x?}", cia.tmd_region().unwrap());
    println!("{:#x?}", cia.meta_region().unwrap().icon());
}
