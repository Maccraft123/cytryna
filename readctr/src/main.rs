use cytryna::prelude::*;
use cytryna::firm::{FirmSignature, FirmwareSection};
use cytryna::crypto::KeyBag;

fn main() -> anyhow::Result<()> {
    KeyBag::from_string(include_str!("aes_keys.txt"))?.finalize();

    let file = std::env::args().nth(1).unwrap();
    let data = std::fs::read(file)?;


    //let cia = Cia::from_slice(&data)?;
    //let ncch_region = cia.content_region()?.next().unwrap();
    //let ncch = Ncch::from_slice(ncch_region.data())?;
    let input_firm = Firm::from_bytes(&data)?;

    let hdr = input_firm.header();
    let boot_priority = hdr.boot_priority();
    let arm11_entry = hdr.arm11_entrypoint();
    let arm9_entry = hdr.arm9_entrypoint();

    let mut firm_builder = Firm::builder();
    firm_builder.boot_priority(boot_priority)
        .arm11_entrypoint(arm11_entry)
        .arm9_entrypoint(arm9_entry)
        .signature(FirmSignature::Custom(Box::new(hdr.sig().clone())));

    for section in hdr.section_iter() {
        let load_addr = section.load_addr();
        let copy_method = section.copy_method();
        let data = input_firm.section_data(section).to_vec();

        firm_builder.add_fw_section(FirmwareSection::new(data, load_addr, copy_method)).unwrap();
    }

    let firm = firm_builder.build().unwrap();
    let out_firm = Firm::from_bytes(&firm)?;

    println!("input: {:#x?}", input_firm.header());
    println!("output: {:#x?}", out_firm.header());


    Ok(())
}


