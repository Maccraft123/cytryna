use anyhow::{Result, Context};
use clap::Parser;
use cytryna::prelude::*;
use std::{fs, path::PathBuf};

#[derive(Parser)]
struct Args {
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


fn main() -> Result<()> {
    let args = Args::parse();
    let icon_big = bmp::open(&args.icon)?;

    let smdh = Smdh::builder()
        .with_short_desc(&args.short_desc)?
        .with_long_desc(&args.long_desc)?
        .with_publisher(&args.publisher)?
        .with_icon((&icon_big).try_into()?)
        .build()?;

    fs::write(args.output, smdh.as_bytes())?;

    Ok(())
}


