use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::result;
use std::sync::Arc;

use crossbeam::sync::MsQueue;
use num_cpus;
use scoped_threadpool;

use super::file::FileCrypt;

type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    NotFile,
    Skip,
    Exists,
    Io(io::Error),
}

#[derive(Copy, Clone, Debug)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Debug)]
pub struct Task {
    pub src: PathBuf,
    pub dest: PathBuf,
}

#[derive(Clone)]
pub struct TaskRuner<'a> {
    mode: Mode,
    skip_exists: bool,
    overwrite: bool,
    dry_run: bool,
    file_crypt: FileCrypt<'a>,
}

impl<'a> TaskRuner<'a> {
    pub fn new(
        secret: &'a [u8],
        mode: Mode,
        skip_exists: bool,
        overwrite: bool,
        dry_run: bool,
    ) -> TaskRuner<'a> {
        TaskRuner {
            mode,
            skip_exists,
            overwrite,
            dry_run,
            file_crypt: FileCrypt::new(secret),
        }
    }

    pub fn simple_run(&mut self, tasks: &[Task]) {
        let total = tasks.len();
        for (index, task) in tasks.iter().enumerate() {
            self.run_task(index + 1, total, task);
        }
    }

    pub fn parallel_run(&mut self, tasks: &[Task], parallel: i32) {
        let num_threads = if parallel > 0 {
            parallel as u32
        } else {
            num_cpus::get() as u32
        };

        let cache = MsQueue::<Self>::new();
        for _ in 0..num_threads {
            cache.push(self.clone());
        }
        let cache = Arc::new(cache);

        let mut pool = scoped_threadpool::Pool::new(num_threads);
        pool.scoped(|scoped| {
            let total = tasks.len();
            for (index, task) in tasks.iter().enumerate() {
                let cache = Arc::clone(&cache);
                scoped.execute(move || {
                    let mut this = cache.pop();
                    this.run_task(index + 1, total, task);
                    cache.push(this);
                });
            }
        });
    }

    fn run_task(&mut self, index: usize, total: usize, task: &Task) {
        if self.dry_run {
            info!("({}/{}) {}: {} (dry run)", index, total, self.mode, task);
            return;
        }
        match self.do_task(task) {
            Ok(()) => info!("({}/{}) {}: {} (success)", index, total, self.mode, task),
            Err(e) => {
                if let Error::Io(_) = e {
                    if task.dest.is_file() {
                        fs::remove_file(&task.dest).unwrap();
                    }
                }
                error!("({}/{}) {}: {} ({})", index, total, self.mode, task, e)
            }
        };
    }

    fn do_task(&mut self, task: &Task) -> Result<()> {
        if !task.src.is_file() {
            return Err(Error::NotFile);
        }

        if task.dest.exists() {
            if self.skip_exists {
                return Err(Error::Skip);
            }

            if !self.overwrite {
                return Err(Error::Exists);
            }
        }

        let dest_dir = task.dest.parent().unwrap();
        fs::create_dir_all(dest_dir)?;

        match self.mode {
            Mode::Encrypt => self.file_crypt.encrypt(&task.src, &task.dest)?,
            Mode::Decrypt => self.file_crypt.decrypt(&task.src, &task.dest)?,
        }

        Ok(())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::NotFile => write!(f, "not file"),
            Error::Skip => write!(f, "skip exists"),
            Error::Exists => write!(f, "local file exists"),
            Error::Io(ref e) => write!(f, "{}", e),
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Mode::Encrypt => write!(f, "encrypt"),
            Mode::Decrypt => write!(f, "decrypt"),
        }
    }
}

impl fmt::Display for Task {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} -> {:?}", self.src, self.dest)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}
