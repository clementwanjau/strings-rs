use log::Level;
use simple_logger::init_with_level;
use std::{
    env::{self, current_dir},
    process::exit,
};
use std::error::Error;
use strings::analyze;

pub fn main() -> Result<(), Box<dyn Error>>{
    init_with_level(Level::Info)?; // Logging
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        println!("please give filename to extract strings!");
        exit(1);
    }
    let file = args[1].to_owned();
    let signature_path = format!("{}/assets/sigs", current_dir()?.display());
    // let signature_path = format!("");
    let results = analyze(
        &file,
        vec![],
        vec![],
        "sc32",
        signature_path.as_str(),
        false,
    )?;

    println!("{:#?}", results);
    Ok(())
}
