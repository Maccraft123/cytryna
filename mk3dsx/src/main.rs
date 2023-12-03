use anyhow::{bail, ensure, Context, Result};
use clap::{Subcommand, Parser};
use cytryna::prelude::*;
use std::{fs, path::PathBuf};
use goblin::elf::{Elf, header, program_header};

#[derive(Debug, Parser)]
struct Args {
    input_file: PathBuf,
    output_file: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let input_bytes = fs::read(&args.input_file)
        .context("Failed to read input ELF file")?;
    let elf = Elf::parse(&input_bytes)
        .context("Failed to parse input data as ELF")?;

    ensure!(!elf.is_64, "Only 32-bit ELF files are supported");
    ensure!(elf.header.e_type == header::ET_EXEC, "Only ET_EXEC binaries are supported");

    // Not the best for performance, but who cares
    ensure!(elf.program_headers.iter().all(|h| h.p_memsz & 3 == 0), "All segments have to be word-aligned");
    ensure!(elf.program_headers.iter().all(|h| h.p_filesz & 3 == 0), "Loadable part of all segments have to be word-aligned");

    let mut base_addr = 0;
    let mut top_addr = 0;
    let mut code_slice;
    let mut rodata_slice;
    let mut data_slice;

    let iter = elf.program_headers.iter()
        .filter(|hdr| hdr.p_type == program_header::PT_LOAD)
        .filter(|hdr| hdr.p_memsz > 0)
        .enumerate();

    for (i, hdr) in iter {
        if i == 0 {
            base_addr = hdr.p_vaddr;
        } else if hdr.p_vaddr != top_addr {
            bail!("Segments have to be contigous");
        }

        match hdr.p_flags {
            5 => {
                ensure!(i == 0, "Code must be the first segment");
                code_slice = &input_bytes[hdr.p_offset as usize..][..hdr.p_filesz as usize];
            },
            4 => {
                ensure!(i == 1, "Rodata must be the second segment");
                rodata_slice = &input_bytes[hdr.p_offset as usize..][..hdr.p_filesz as usize];
            },
            6 => {
                ensure!(i == 2, "Data must be the third segment");
                data_slice = &input_bytes[hdr.p_offset as usize..][..hdr.p_filesz as usize];
            },
            _ if i > 2 => bail!("Too many segments"),
            other => bail!("Invalid segment {:x}", other),
        }

        top_addr = hdr.p_vaddr + (hdr.p_memsz + 0xfff) & !0xfff;

        println!("{:#?}", hdr);
    }

    let len = top_addr - base_addr;
    ensure!(len < 0x10000000, "The executable has to be smaller than 256MiB!");
    ensure!(elf.header.e_entry == base_addr, "Entry point has to be at the start of code segment");

    let mut abs_reloc_map = vec![false; (len/4) as usize];
    let mut rel_reloc_map = vec![false; (len/4) as usize];

    Ok(())
}
