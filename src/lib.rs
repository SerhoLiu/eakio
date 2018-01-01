extern crate ansi_term;
extern crate byteorder;
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

pub use cli::command;
pub use util::init_logger;

pub const VERSION: &str = "1.0";
