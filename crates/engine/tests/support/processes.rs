use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::owned_child::{OwnedChild, PROCESS_DEADLINE};
use crate::private_root::PrivateRoot;
use serde_json::Value;
use uuid::Uuid;

const IO_DEADLINE: Duration = Duration::from_secs(5);
const MAX_HTTP_RESPONSE: u64 = 64 * 1024;

pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn count(&self, action_id: &str) -> u64 {
        assert_eq!(self.status, 200, "counter operation must succeed");
        let body: Value = serde_json::from_slice(&self.body).expect("counter response JSON");
        let object = body.as_object().expect("counter response object");
        assert_eq!(
            object.len(),
            2,
            "counter response must contain only action_id/count"
        );
        assert_eq!(
            object.get("action_id").and_then(Value::as_str),
            Some(action_id)
        );
        let count = object
            .get("count")
            .and_then(Value::as_u64)
            .expect("counter is an unsigned JSON integer");
        assert!(
            count <= 9_007_199_254_740_991,
            "counter stays within the wire integer bound"
        );
        count
    }
}

/// Independent real receiver, token file, and SQLite state owned by one fixture.
/// Field order ensures the process is reaped before its files are removed.
pub struct ReceiverFixture {
    child: OwnedChild,
    root: PrivateRoot,
    binary: PathBuf,
    token: String,
    address: SocketAddr,
}

impl ReceiverFixture {
    pub fn start(binary: &Path) -> Self {
        let root = PrivateRoot::new();
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let mut token_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.path().join("token"))
            .expect("create private receiver token file");
        token_file
            .write_all(token.as_bytes())
            .expect("write receiver token");
        token_file.sync_all().expect("sync receiver token");
        let (child, address) = Self::launch(binary, root.path(), &token);
        Self {
            child,
            root,
            binary: binary.to_path_buf(),
            token,
            address,
        }
    }

    fn launch(binary: &Path, root: &Path, token: &str) -> (OwnedChild, SocketAddr) {
        let mut child = OwnedChild::spawn(
            Command::new(binary)
                .args(["--bind", "127.0.0.1:0", "--token-file"])
                .arg(root.join("token"))
                .arg("--state")
                .arg(root.join("counter.sqlite3"))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit()),
        );
        let stdout = child.child.stdout.take().expect("receiver readiness pipe");
        let (sender, receiver) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout)
                .take(4097)
                .read_line(&mut line)
                .map(|_| line);
            // The receiver may have timed out and dropped its channel during unwinding.
            let _ = sender.send(result);
        });
        let line = receiver
            .recv_timeout(PROCESS_DEADLINE)
            .expect("receiver emits readiness within deadline")
            .expect("read receiver readiness");
        reader.join().expect("readiness reader finishes");
        assert!(
            line.len() <= 4096 && line.ends_with('\n'),
            "bounded readiness JSON line"
        );
        assert!(
            !line.contains(token),
            "readiness must not expose the capability"
        );
        let readiness: Value = serde_json::from_str(&line).expect("readiness JSON");
        let object = readiness.as_object().expect("readiness object");
        assert_eq!(
            object.len(),
            2,
            "readiness discloses only protocol and address"
        );
        assert_eq!(object["protocol"], "razen.fixture-receiver/0.1.0");
        let address: SocketAddr = object["address"]
            .as_str()
            .expect("readiness address string")
            .parse()
            .expect("readiness socket address");
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
        child.assert_running();
        (child, address)
    }

    pub fn root(&self) -> &Path {
        self.root.path()
    }

    pub fn state_path(&self) -> PathBuf {
        self.root.path().join("counter.sqlite3")
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn assert_running(&mut self) {
        self.child.assert_running();
    }

    pub fn restart(&mut self) {
        self.child.kill_and_wait();
        let (child, address) = Self::launch(&self.binary, self.root.path(), &self.token);
        self.child = child;
        self.address = address;
    }

    pub fn authorized(&self, method: &str, route: &str) -> HttpResponse {
        self.request(method, route, Some(&format!("Bearer {}", self.token)))
    }

    pub fn request(&self, method: &str, route: &str, authorization: Option<&str>) -> HttpResponse {
        let mut stream = TcpStream::connect_timeout(&self.address, IO_DEADLINE)
            .expect("connect to real loopback receiver");
        stream
            .set_read_timeout(Some(IO_DEADLINE))
            .expect("bound HTTP read time");
        stream
            .set_write_timeout(Some(IO_DEADLINE))
            .expect("bound HTTP write time");
        let authorization = authorization
            .map(|value| format!("Authorization: {value}\r\n"))
            .unwrap_or_default();
        write!(
            stream,
            "{method} {route} HTTP/1.1\r\nHost: {}\r\n{authorization}Content-Length: 0\r\nConnection: close\r\n\r\n",
            self.address,
        )
        .expect("send actual receiver request");
        stream.flush().expect("flush actual receiver request");
        let mut response = Vec::new();
        stream
            .take(MAX_HTTP_RESPONSE + 1)
            .read_to_end(&mut response)
            .expect("read bounded receiver response");
        assert!(
            response.len() as u64 <= MAX_HTTP_RESPONSE,
            "receiver response is bounded"
        );
        let split = response
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .expect("HTTP response header terminator");
        let headers = std::str::from_utf8(&response[..split]).expect("HTTP response headers");
        let status = headers
            .lines()
            .next()
            .expect("HTTP status line")
            .split_whitespace()
            .nth(1)
            .expect("HTTP status code")
            .parse()
            .expect("numeric HTTP status code");
        HttpResponse {
            status,
            body: response[split + 4..].to_vec(),
        }
    }
}

/// A synchronous reader separate from the workspace API, useful for visibility assertions.
pub fn read_file(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path)
        .expect("open independently visible file")
        .read_to_end(&mut bytes)
        .expect("read independently visible file");
    bytes
}
