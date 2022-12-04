use log::Level;
use simple_logger::init_with_level;
use std::{
    env::{self, current_dir},
    process::exit,
};
use strings::analyze;

pub fn main() {
    init_with_level(Level::Debug).unwrap(); // Logging
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        println!("please give filename to extract strings!");
        exit(1);
    }
    let file = args[1].to_owned();
    let signature_path = format!("{}/assets/sigs", current_dir().unwrap().display());
    // let signature_path = format!("");
    let results = analyze(
        &file,
        vec![],
        vec![],
        "sc32",
        signature_path.as_str(),
        false,
    );

    println!("{:?}", results);
}
