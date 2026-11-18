use std::io::{ErrorKind, Read};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Compiler {
    child: Child,
    reaped: bool,
}
impl Drop for Compiler {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // Keep the unreaped compiler leader's PID pinned while terminating only
        // the process group created for this query. No build dependencies or
        // unsafe signal calls are needed for this native, fixed-argv operation.
        if let Ok(mut signal) = Command::new("/bin/kill")
            .arg("-KILL")
            .arg(format!("-{}", self.child.id()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                match signal.try_wait() {
                    Ok(Some(_)) => break,
                    _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(1)),
                    _ => {
                        let _ = signal.kill();
                        let _ = signal.wait();
                        break;
                    }
                }
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn channel() -> (UnixStream, Stdio) {
    let (host, compiler) = UnixStream::pair().expect("create compiler provenance channel");
    host.set_nonblocking(true)
        .expect("bound compiler provenance reads");
    (host, Stdio::from(OwnedFd::from(compiler)))
}

fn read_chunk(stream: &mut UnixStream, bytes: &mut Vec<u8>) -> bool {
    let mut buffer = [0; 1024];
    match stream.read(&mut buffer) {
        Ok(0) => true,
        Ok(count) => {
            assert!(
                bytes.len() + count <= 4096,
                "compiler provenance output limit exceeded"
            );
            bytes.extend_from_slice(&buffer[..count]);
            false
        }
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
            false
        }
        Err(_) => panic!("compiler provenance I/O failed"),
    }
}

fn main() {
    for key in [
        "RUSTC",
        "RUSTUP_TOOLCHAIN",
        "RUSTUP_HOME",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "TARGET",
    ] {
        println!("cargo:rerun-if-env-changed={key}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../rust-toolchain.toml");
    let rustc =
        PathBuf::from(std::env::var_os("RUSTC").expect("Cargo must identify its actual RUSTC"));
    assert!(
        rustc.is_absolute(),
        "Cargo RUSTC must be an absolute compiler path"
    );
    println!("cargo:rerun-if-changed={}", rustc.display());
    let (mut stdout, child_stdout) = channel();
    let (mut stderr, child_stderr) = channel();
    let child = Command::new(&rustc)
        .arg("--version")
        .current_dir(std::env::var_os("OUT_DIR").expect("Cargo output directory"))
        .stdin(Stdio::null())
        .stdout(child_stdout)
        .stderr(child_stderr)
        .process_group(0)
        .spawn()
        .expect("invoke Cargo's actual compiler for provenance");
    let mut compiler = Compiler {
        child,
        reaped: false,
    };
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    let mut stdout_closed = false;
    let mut stderr_closed = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            Instant::now() < deadline,
            "compiler provenance deadline exceeded"
        );
        if !stdout_closed {
            stdout_closed = read_chunk(&mut stdout, &mut output);
        }
        if !stderr_closed {
            stderr_closed = read_chunk(&mut stderr, &mut diagnostics);
        }
        if stdout_closed
            && stderr_closed
            && let Some(status) = compiler
                .child
                .try_wait()
                .expect("observe actual compiler exit")
        {
            compiler.reaped = true;
            assert!(status.success(), "actual compiler version query failed");
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let version = std::str::from_utf8(&output)
        .expect("compiler version must be UTF-8")
        .trim();
    assert!(
        version.starts_with("rustc ")
            && version.len() <= 256
            && !version.chars().any(char::is_control),
        "invalid actual compiler provenance"
    );
    println!("cargo:rustc-env=RAZEN_BUILD_RUSTC={version}");
    let target = std::env::var("TARGET").expect("Cargo compilation target");
    assert!(
        !target.chars().any(char::is_control),
        "invalid Cargo target"
    );
    println!("cargo:rustc-env=RAZEN_BUILD_TARGET={target}");
}
