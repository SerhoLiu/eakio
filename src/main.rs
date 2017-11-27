extern crate eakio;

use std::process;

fn main() {
    eakio::init_logger();

    if let Err(e) = eakio::command() {
        println!("Error: {}", e);
        process::exit(1)
    }
}
