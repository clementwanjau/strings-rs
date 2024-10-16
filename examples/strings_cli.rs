use log::Level;
use simple_logger::init_with_level;
use std::{
    env::{self},
    process::exit,
};
use std::error::Error;
use strings::analyze;

pub fn main() -> Result<(), Box<dyn Error>>{
    init_with_level(Level::Info)?; // Logging
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        println!("Please provide the filename to the binary to extract strings!");
        exit(1);
    }
    let file = args[1].to_owned();
    // let signature_path = format!("");
    let results = analyze(
        &file
    )?;

    println!("{:#?}", results);
    Ok(())
}
