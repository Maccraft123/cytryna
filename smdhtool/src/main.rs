use anyhow::{Result, Context};
use clap::{Subcommand, Parser};
use cytryna::prelude::*;
use std::{fs, path::PathBuf};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    cmd: Commands
}

#[derive(Subcommand)]
enum Commands {
    Dump {
        #[arg(short, long)]
        input_path: PathBuf,
        #[arg(short, long)]
        big_icon_path: Option<PathBuf>,
        #[arg(short, long)]
        small_icon_path: Option<PathBuf>,
    },
    Create {
        #[arg(short, long)]
        short_desc: String,
        #[arg(short, long)]
        long_desc: String,
        #[arg(short, long)]
        publisher: String,
        #[arg(long)]
        icon: PathBuf,
        #[arg(long)]
        small_icon: Option<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
    }
}


fn main() -> Result<()> {
    let args = Args::parse();
    match args.cmd {
        Commands::Create {
            short_desc, long_desc, publisher, icon, small_icon, output,
        } => {
            let icon_big = bmp::open(&icon)
                .context("Failed to open big icon")?;
            
            let smdh = Smdh::builder()
                .with_short_desc(&short_desc)
                    .context("Failed to set short description")?
                .with_long_desc(&long_desc)
                    .context("Failed to set long description")?
                .with_publisher(&publisher)
                    .context("Filed to set publisher info")?
                .with_icon((&icon_big).try_into().context("Failed to set big icon info")?)
                .build()
                    .context("Failed to build SMDH")?;

            fs::write(output, smdh.as_bytes())
                .context("Failed to write SMDH data")?;
        },
        Commands::Dump {
            input_path, big_icon_path, small_icon_path
        } => {
            let vec = fs::read(input_path)
                .context("Failed to read SMDH file")?;
            let smdh = Smdh::from_bytes(&vec)
                .context("Failed to parse file as SMDH data")?;
            println!("{:#?}", smdh);

            if let Some(path) = big_icon_path {
                smdh.big_icon()
                    .to_bmp()
                    .save(path)
                    .context("Failed to write big icon BMP")?;
            }

            if let Some(path) = small_icon_path {
                smdh.small_icon()
                    .to_bmp()
                    .save(path)
                    .context("Failed to write small icon BMP")?;
            }
        }
    }
    Ok(())
}


