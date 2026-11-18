//! Fixed subprocess behaviors for command-boundary tests, never proof evidence
//! or a guest-registered command provider.
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

enum Mode {
    FloodStderr,
    FloodStdout,
    PidThenSleep,
    InheritedPipes,
    Exit,
}

fn mode() -> Option<Mode> {
    let mut args = std::env::args_os().skip(1);
    let selected = match args.next()?.to_str()? {
        "flood-stderr" => Mode::FloodStderr,
        "flood-stdout" => Mode::FloodStdout,
        "pid-then-sleep" => Mode::PidThenSleep,
        "inherited-pipes" => Mode::InheritedPipes,
        "exit" => Mode::Exit,
        _ => return None,
    };
    if args.next().is_some() {
        return None;
    }
    Some(selected)
}

fn run(mode: Mode) -> io::Result<()> {
    match mode {
        Mode::FloodStderr => {
            let mut stderr = io::stderr().lock();
            for _ in 0..4096 {
                stderr.write_all(b"PRIVATE-STDERR-MARKER")?;
            }
        }
        Mode::FloodStdout => {
            let mut stdout = io::stdout().lock();
            for _ in 0..256 {
                stdout.write_all(&[b'x'; 4096])?;
            }
        }
        Mode::PidThenSleep => {
            let mut input = Vec::new();
            io::stdin().take(4097).read_to_end(&mut input)?;
            if input.is_empty() || input.len() > 4096 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let path = std::str::from_utf8(&input).map_err(|_| io::ErrorKind::InvalidInput)?;
            if !Path::new(path).is_absolute() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let mut marker = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            marker.write_all(std::process::id().to_string().as_bytes())?;
            marker.sync_all()?;
            std::thread::sleep(Duration::from_secs(30));
        }
        Mode::InheritedPipes => {
            // Deliberately leave inherited outputs open after the leader exits.
            // The native descendant is finite even if its owner fails cleanup.
            let _child = Command::new("/bin/sleep")
                .arg("2")
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()?;
            std::process::exit(0);
        }
        Mode::Exit => {
            io::stderr().write_all(b"PRIVATE-STDERR-MARKER\n")?;
            std::process::exit(23);
        }
    }
    Ok(())
}

fn main() {
    let Some(mode) = mode() else {
        eprintln!("Expected exactly one reviewed command fixture mode");
        std::process::exit(2);
    };
    if run(mode).is_err() {
        eprintln!("Command fixture operation failed");
        std::process::exit(2);
    }
}
