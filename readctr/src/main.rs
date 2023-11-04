use cytryna::prelude::*;
use cytryna::crypto::KeyBag;

fn main() -> anyhow::Result<()> {
    KeyBag::from_string(include_str!("aes_keys.txt"))?.finalize();

    let file = std::env::args().nth(1).unwrap();
    let data = std::fs::read(file)?;


    let cia = Cia::from_slice(&data)?;
    let ncch_region = cia.content_region()?.next().unwrap();
    let ncch = Ncch::from_slice(ncch_region.data())?;
    let exefs = ncch.exefs()?;
    let icon = exefs.file_by_name(b"icon").unwrap();

    println!("{:#x?}", Smdh::from_slice(icon)?);
    Ok(())
}


