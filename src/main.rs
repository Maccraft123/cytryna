mod ncch;
mod cia;

use ncch::Ncch;
use cia::Cia;

fn main() {
    let file = std::env::args().nth(1).unwrap();
    let data = std::fs::read(file).unwrap();
    let cia = Cia::from_slice(&data);
    println!("{:x?}", cia.cert_chain());
    let size = cia.header.hdr_size;
    println!("{:x}", size);
}
