use std::io;
use std::path::{PathBuf, MAIN_SEPARATOR};

use glob;
use rpassword;
use docopt::Docopt;
use walkdir::{DirEntry, WalkDir};

use super::util::io_error;
use super::task::{Mode, Task, TaskRuner};


const USAGE: &str = "
Eakio, encrypt your file.

Usage:
    eakio encrypt <src>... <dest> [-n] [--skip | --overwrite] [--hidden] [--parallel=<N>]
    eakio decrypt <src>... <dest> [-n] [--skip | --overwrite] [--hidden] [--parallel=<N>]
    eakio (-h | --help)
    eakio (-v | --version)

Options:
    -h --help       Show this screen.
    -v --version    Show version.
    -n --dryrun     Only show what should be do.
    --skip          Skip exists dest file.
    --overwrite     Overwrite exists dest file.
    --hidden        Include hidden files.
    --parallel=<N>  Parallel run, -1 use cpu count.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_skip: bool,
    flag_overwrite: bool,
    flag_hidden: bool,
    flag_dryrun: bool,
    flag_parallel: i32,
    arg_src: Vec<String>,
    arg_dest: String,
    cmd_encrypt: bool,
    cmd_decrypt: bool,
}

pub fn command() -> io::Result<()> {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    command_crypt(&args)
}

fn command_crypt(args: &Args) -> io::Result<()> {
    let mode = if args.cmd_encrypt {
        Mode::Encrypt
    } else {
        Mode::Decrypt
    };

    let dest_is_dir = args.arg_dest.ends_with(MAIN_SEPARATOR);
    let dest = PathBuf::from(&args.arg_dest);

    let files = list_src_files(&args.arg_src, args.flag_hidden)?;
    let count: usize = files.iter().map(|pg| pg.subs.len()).sum();

    info!("Found {} files to {}", count, mode);
    if count == 0 {
        return Ok(());
    }
    if count > 1 && !dest_is_dir {
        return Err(io_error(&format!(
            "multiple files dest must a dir, '{}' need endswith '{}'",
            dest.display(),
            MAIN_SEPARATOR
        )));
    }

    let tasks = build_tasks(&files, &dest, dest_is_dir);

    let secret = input_password()?.into_bytes();
    let mut runer = TaskRuner::new(
        &secret,
        mode,
        args.flag_skip,
        args.flag_overwrite,
        args.flag_dryrun,
    );

    if args.flag_parallel == 0 {
        runer.simple_run(&tasks);
    } else {
        runer.parallel_run(&tasks, args.flag_parallel);
    }

    Ok(())
}


#[derive(Debug)]
struct PathGroup {
    path: PathBuf,
    is_file: bool,
    subs: Vec<PathBuf>,
}

fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with("."))
        .unwrap_or(false)
}

fn list_src_files(srcs: &[String], hidden: bool) -> io::Result<Vec<PathGroup>> {
    let mut globs = Vec::<PathBuf>::new();
    for src in srcs.iter() {
        let paths = glob::glob(src).map_err(|e| io_error(&format!("{}", e)))?;
        for entry in paths {
            let path = entry.map_err(|e| io_error(&format!("{}", e)))?;
            globs.push(path);
        }
    }
    let mut path_groups = Vec::<PathGroup>::new();

    for path in globs {
        let mut subs = Vec::<PathBuf>::new();
        if path.is_file() {
            subs.push(path.clone());
            path_groups.push(PathGroup {
                path,
                is_file: true,
                subs,
            });
        } else if path.is_dir() {
            for entry in WalkDir::new(&path)
                .into_iter()
                .filter_entry(|e| hidden || !is_hidden(e))
            {
                let de = entry.map_err(|e| io_error(&format!("{}", e)))?;
                if de.file_type().is_file() {
                    subs.push(de.path().to_path_buf());
                }
            }

            path_groups.push(PathGroup {
                path,
                is_file: false,
                subs,
            });
        }
    }

    Ok(path_groups)
}

fn build_tasks(srcs: &[PathGroup], dest: &PathBuf, dest_is_dir: bool) -> Vec<Task> {
    let mut tasks = Vec::<Task>::new();

    // 这里目标文件的路径由以下方式决定
    // - src 是文件
    //   1. dest 是文件, 则 dest
    //   2. dest 是目录, 则 dest/filename(src)
    // - src 是目录, 将 src 到 dest/src
    for pg in srcs.iter() {
        for path in &pg.subs {
            let mut task_dest = PathBuf::from(&dest);

            if pg.is_file {
                if dest_is_dir {
                    let filename = path.file_name().unwrap();
                    task_dest.push(filename);
                }
            } else {
                // remove prefix
                let filename = path.strip_prefix(&pg.path).unwrap();
                if let Some(dirname) = pg.path.file_name() {
                    task_dest.push(dirname);
                }
                task_dest.push(filename);
            }

            tasks.push(Task {
                src: path.clone(),
                dest: task_dest,
            })
        }
    }

    tasks
}

fn input_password() -> io::Result<String> {
    let pass = rpassword::prompt_password_stdout("        Password: ")?;
    let pass2 = rpassword::prompt_password_stdout("Confirm Password: ")?;

    if pass != pass2 {
        Err(io_error("passwords you provided do not match"))
    } else {
        Ok(pass)
    }
}
