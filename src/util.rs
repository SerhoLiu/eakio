use std::io;
use std::env;
use std::fmt;

use ansi_term::Color;
use env_logger::LogBuilder;
use log::{LogLevel, LogLevelFilter, LogRecord};
use time;


struct ColorLevel(LogLevel);

impl fmt::Display for ColorLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            LogLevel::Trace => Color::Purple.paint("TRACE"),
            LogLevel::Debug => Color::Blue.paint("DEBUG"),
            LogLevel::Info => Color::Green.paint("INFO "),
            LogLevel::Warn => Color::Yellow.paint("WARN "),
            LogLevel::Error => Color::Red.paint("ERROR"),
        }.fmt(f)
    }
}

pub fn init_logger() {
    let format = |record: &LogRecord| {
        let now = time::now();
        let ms = now.tm_nsec / 1000 / 1000;
        let t = time::strftime("%Y-%m-%d %T", &now).unwrap();
        format!(
            "{}.{:03} [{}]  {}",
            t,
            ms,
            ColorLevel(record.level()),
            record.args()
        )
    };

    let mut builder = LogBuilder::new();
    builder.format(format).filter(None, LogLevelFilter::Info);

    if env::var("RUST_LOG").is_ok() {
        builder.parse(&env::var("RUST_LOG").unwrap());
    }

    if env::var("EAKIO_LOG").is_ok() {
        builder.parse(&env::var("EAKIO_LOG").unwrap());
    }

    builder.init().unwrap();
}

#[inline]
pub fn io_error(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}
