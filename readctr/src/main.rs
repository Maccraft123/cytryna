use cytryna::prelude::*;
use cytryna::firm::{FirmSignature, FirmwareSection};
use cytryna::crypto::KeyBag;

fn main() -> anyhow::Result<()> {
    KeyBag::from_string(include_str!("aes_keys.txt"))?.finalize();

    let file = std::env::args().nth(1).unwrap();
    let data = std::fs::read(file)?;
    let hb3dsx = Hb3dsx::from_bytes(&data)?;

    println!("{:#x?}", hb3dsx.header().code_reloc_table_offset());
    println!("{:#x?}", hb3dsx.code_reloc_header());

    for (ty, rel) in hb3dsx.code_reloc_iter() {
        println!("{:?} {:#x?}", ty, rel);
    }



    Ok(())
}
