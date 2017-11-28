extern crate ansi_term;
extern crate crossbeam;
extern crate docopt;
extern crate env_logger;
extern crate glob;
#[macro_use]
extern crate log;
extern crate num_cpus;
extern crate ring;
extern crate rpassword;
extern crate scoped_threadpool;
#[macro_use]
extern crate serde_derive;
extern crate time;
extern crate walkdir;

mod crypto;
mod file;
mod task;
mod util;
mod cli;

mod v1 {
    pub const VERSION: u8 = 0x01;
    pub const MAGIC: &[u8] = b"KELSI";
}

pub use cli::command;
pub use util::init_logger;

pub const VERSION: &str = "0.10";
