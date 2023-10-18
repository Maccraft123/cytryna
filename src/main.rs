mod ncch;
mod cia;
mod titleid;

use ncch::Ncch;
use cia::Cia;

fn main() {
    let file = std::env::args().nth(1).unwrap();
    let data = std::fs::read(file).unwrap();
    let cia = Cia::from_slice(&data);
    for dep in cia.meta_region().unwrap().dependencies_iter() {
        println!("{:x?}", dep);
    }
}
