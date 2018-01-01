use std::borrow::Cow;
use std::env;
use std::fmt;
use std::io;

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

/// expand path like ~/xxx
pub fn expand_tilde_path(path: &str) -> Cow<str> {
    if !path.starts_with('~') {
        return path.into();
    }

    let path_after_tilde = &path[1..];
    if path_after_tilde.is_empty() || path_after_tilde.starts_with('/') {
        if let Some(hd) = env::home_dir() {
            let result = format!("{}{}", hd.display(), path_after_tilde);
            result.into()
        } else {
            // home dir is not available
            path.into()
        }
    } else {
        // we cannot handle `~otheruser/` paths yet
        path.into()
    }
}

#[inline]
pub fn io_error(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

#[cfg(test)]
mod test {
    use std::env;

    #[test]
    fn test_expand_tilde_path() {
        let old_home = env::var("HOME").ok();
        env::set_var("HOME", "/home/morty");

        assert_eq!("/home/morty", super::expand_tilde_path("~"));
        assert_eq!("/home/morty/rick", super::expand_tilde_path("~/rick"));
        assert_eq!("~rick", super::expand_tilde_path("~rick"));
        assert_eq!("/home", super::expand_tilde_path("/home"));

        if let Some(old) = old_home {
            env::set_var("HOME", old);
        }
    }
}
