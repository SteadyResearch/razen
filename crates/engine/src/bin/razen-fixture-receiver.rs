use std::ffi::OsStr;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use razen_engine::domain::values::{EntityId, MAX_WIRE_INT, WireInt};
use razen_engine::protocol::error::{ErrorCode, ProofError, ProofResult};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use rustix::fs::{self, FileType, FlockOperation, Mode, OFlags};
use serde::Serialize;
use subtle::ConstantTimeEq;

const APP_ID: u32 = 0x525a_5230;
const HEADER_LIMIT: usize = 8192;
const CONNECTION_DEADLINE: Duration = Duration::from_secs(2);
const MAX_ACTIONS: u64 = 1024;

struct Options {
    bind: SocketAddr,
    token_file: PathBuf,
    state: PathBuf,
}

struct CounterState {
    connection: Connection,
    _lock: File,
}

#[derive(Serialize)]
struct CounterReply {
    action_id: EntityId,
    count: WireInt,
}

struct Request<'a> {
    action_id: EntityId,
    action_key: &'a str,
    increment: bool,
}

#[derive(Clone, Copy)]
struct HttpFailure {
    status: u16,
    code: ErrorCode,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("fixture receiver: {error}");
        std::process::exit(2);
    }
}

fn run() -> ProofResult<()> {
    let options = options()?;
    if !options.bind.ip().is_loopback() {
        return Err(failure(
            ErrorCode::PermissionDenied,
            "Receiver binding must be loopback",
        ));
    }
    let (directory, token_name) = private_parent(&options.token_file)?;
    let token = read_token(&directory, token_name)?;
    let (state_directory, state_name) = private_parent(&options.state)?;
    let token_stat = fs::fstat(&directory).map_err(storage_error)?;
    let state_stat = fs::fstat(&state_directory).map_err(storage_error)?;
    if token_stat.st_dev != state_stat.st_dev || token_stat.st_ino != state_stat.st_ino {
        return Err(failure(
            ErrorCode::PermissionDenied,
            "Receiver inputs must share owned private storage",
        ));
    }
    let mut state = CounterState::open(&state_directory, state_name, &options.state)?;
    let listener = TcpListener::bind(options.bind).map_err(|_| {
        failure(
            ErrorCode::ProviderUnavailable,
            "Cannot bind the owned fixture receiver",
        )
    })?;
    #[derive(Serialize)]
    struct Ready {
        protocol: &'static str,
        address: SocketAddr,
    }
    let ready = Ready {
        protocol: "razen.fixture-receiver/0.1.0",
        address: listener.local_addr().map_err(storage_error)?,
    };
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &ready).map_err(storage_error)?;
    stdout.write_all(b"\n").map_err(storage_error)?;
    stdout.flush().map_err(storage_error)?;
    drop(stdout);
    loop {
        let (mut stream, peer) = listener.accept().map_err(storage_error)?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let mut headers = [0; HEADER_LIMIT];
        let result = read_headers(&mut stream, &mut headers)
            .and_then(|length| parse_request(&headers[..length], &token))
            .and_then(|request| state.count(request));
        // A disconnected client receives no success. Any committed effect remains in the
        // independent database, so callers can observe uncertainty rather than infer retry.
        match result {
            Ok(reply) => {
                if write_reply(&mut stream, 200, &reply).is_err() {
                    state.record_reply_failure()?;
                }
            }
            Err(error) => {
                if write_error(&mut stream, error).is_err() {
                    state.record_reply_failure()?;
                }
            }
        }
    }
}

fn options() -> ProofResult<Options> {
    let mut bind = None;
    let mut token_file = None;
    let mut state = None;
    let mut arguments = std::env::args_os().skip(1);
    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| invalid("Missing receiver argument value"))?;
        match flag.to_str() {
            Some("--bind") if bind.is_none() => {
                bind = Some(
                    value
                        .to_str()
                        .ok_or_else(|| invalid("Invalid bind address"))?
                        .parse()
                        .map_err(|_| invalid("Invalid bind address"))?,
                );
            }
            Some("--token-file") if token_file.is_none() => token_file = Some(PathBuf::from(value)),
            Some("--state") if state.is_none() => state = Some(PathBuf::from(value)),
            _ => return Err(invalid("Unknown or duplicate receiver argument")),
        }
    }
    Ok(Options {
        bind: bind.ok_or_else(|| invalid("Receiver requires an explicit bind address"))?,
        token_file: token_file
            .ok_or_else(|| invalid("Receiver requires a private capability file"))?,
        state: state.ok_or_else(|| invalid("Receiver requires independent state storage"))?,
    })
}

fn private_parent(path: &Path) -> ProofResult<(File, &OsStr)> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid(
            "Receiver paths must be explicit and traversal-free",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Invalid receiver storage path"))?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("Invalid receiver storage name"))?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let directory = File::from(fs::open(parent, flags, Mode::empty()).map_err(storage_error)?);
    let stat = fs::fstat(&directory).map_err(storage_error)?;
    if stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o777 != 0o700
        || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
    {
        return Err(failure(
            ErrorCode::PermissionDenied,
            "Receiver storage is not private owned storage",
        ));
    }
    Ok((directory, name))
}

fn validate_file(file: &File) -> ProofResult<()> {
    let stat = fs::fstat(file).map_err(storage_error)?;
    if stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o777 != 0o600
        || stat.st_nlink != 1
        || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
    {
        return Err(failure(
            ErrorCode::PermissionDenied,
            "Receiver file is not private single-link storage",
        ));
    }
    Ok(())
}

fn read_token(directory: &File, name: &OsStr) -> ProofResult<[u8; 64]> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let mut file =
        File::from(fs::openat(directory, name, flags, Mode::empty()).map_err(storage_error)?);
    validate_file(&file)?;
    if file.metadata().map_err(storage_error)?.len() != 64 {
        return Err(invalid(
            "Receiver capability must contain exactly 64 hexadecimal bytes",
        ));
    }
    let mut token = [0; 64];
    file.read_exact(&mut token).map_err(storage_error)?;
    let mut extra = [0];
    if file.read(&mut extra).map_err(storage_error)? != 0
        || !token.iter().all(u8::is_ascii_hexdigit)
    {
        return Err(invalid("Malformed receiver capability"));
    }
    Ok(token)
}

fn canonical_state_path(directory: &File, path: &Path, name: &OsStr) -> ProofResult<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Invalid receiver storage path"))?;
    let canonical = parent.canonicalize().map_err(storage_error)?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let resolved = fs::open(&canonical, flags, Mode::empty()).map_err(storage_error)?;
    let expected = fs::fstat(directory).map_err(storage_error)?;
    let actual = fs::fstat(resolved).map_err(storage_error)?;
    if expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino {
        return Err(failure(
            ErrorCode::IntegrityError,
            "Receiver storage directory changed",
        ));
    }
    Ok(canonical.join(name))
}

impl CounterState {
    fn open(directory: &File, name: &OsStr, path: &Path) -> ProofResult<Self> {
        // BSD locks on SQLite's own inode conflict with its transactions.
        let lock_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let lock = File::from(
            fs::openat(directory, ".", lock_flags, Mode::empty()).map_err(storage_error)?,
        );
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(storage_error)?;
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let (mut file, fresh) = match fs::openat(
            directory,
            name,
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(file) => (File::from(file), true),
            Err(rustix::io::Errno::EXIST) => (
                File::from(
                    fs::openat(directory, name, flags, Mode::empty()).map_err(storage_error)?,
                ),
                false,
            ),
            Err(error) => return Err(storage_error(error)),
        };
        validate_file(&file)?;
        if !fresh {
            let mut header = [0; 100];
            file.read_exact(&mut header).map_err(storage_error)?;
            let app = u32::from_be_bytes([header[68], header[69], header[70], header[71]]);
            let version = u32::from_be_bytes([header[60], header[61], header[62], header[63]]);
            if !header.starts_with(b"SQLite format 3\0") || app != APP_ID || version != 1 {
                return Err(failure(
                    ErrorCode::IntegrityError,
                    "Refusing unrelated receiver state",
                ));
            }
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let canonical = canonical_state_path(directory, path, name)?;
        let connection = Connection::open_with_flags(canonical, flags).map_err(storage_error)?;
        connection
            .busy_timeout(Duration::from_millis(250))
            .map_err(storage_error)?;
        connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA foreign_keys=ON;")
            .map_err(storage_error)?;
        if fresh {
            connection.execute_batch(&format!(
                "BEGIN IMMEDIATE; PRAGMA application_id={APP_ID}; PRAGMA user_version=1; CREATE TABLE counters(action_id TEXT PRIMARY KEY NOT NULL,count INTEGER NOT NULL CHECK(count >= 0 AND count <= {MAX_WIRE_INT})); CREATE TABLE receiver_meta(id INTEGER PRIMARY KEY CHECK(id=1),reply_failures INTEGER NOT NULL CHECK(reply_failures >= 0 AND reply_failures <= {MAX_WIRE_INT})); INSERT INTO receiver_meta VALUES(1,0); COMMIT;"
            )).map_err(storage_error)?;
            directory.sync_all().map_err(storage_error)?;
        }
        let integrity: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(storage_error)?;
        if integrity != "ok" {
            return Err(failure(
                ErrorCode::IntegrityError,
                "Receiver state integrity check failed",
            ));
        }
        connection
            .prepare("SELECT count FROM counters WHERE action_id=?1")
            .map_err(storage_error)?;
        Ok(Self {
            connection,
            _lock: lock,
        })
    }

    fn record_reply_failure(&mut self) -> ProofResult<()> {
        let changed = self.connection.execute(
            "UPDATE receiver_meta SET reply_failures=reply_failures+1 WHERE id=1 AND reply_failures < ?1",
            [MAX_WIRE_INT as i64],
        ).map_err(storage_error)?;
        if changed != 1 {
            return Err(failure(
                ErrorCode::BudgetExhausted,
                "Receiver diagnostic counter exhausted",
            ));
        }
        Ok(())
    }

    fn count(&mut self, request: Request<'_>) -> Result<CounterReply, HttpFailure> {
        if !request.increment {
            let count: Option<WireInt> = self
                .connection
                .query_row(
                    "SELECT count FROM counters WHERE action_id=?1",
                    [request.action_key],
                    read_wire_counter,
                )
                .optional()
                .map_err(storage_http)?;
            return Ok(CounterReply {
                action_id: request.action_id,
                count: count.unwrap_or(WireInt::ZERO),
            });
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_http)?;
        let current: Option<WireInt> = transaction
            .query_row(
                "SELECT count FROM counters WHERE action_id=?1",
                [request.action_key],
                read_wire_counter,
            )
            .optional()
            .map_err(storage_http)?;
        if current.is_none() {
            let actions: WireInt = transaction
                .query_row("SELECT COUNT(*) FROM counters", [], read_wire_counter)
                .map_err(storage_http)?;
            if actions.get() >= MAX_ACTIONS {
                return Err(HttpFailure {
                    status: 503,
                    code: ErrorCode::BudgetExhausted,
                });
            }
        }
        let next = current
            .unwrap_or(WireInt::ZERO)
            .checked_add(WireInt::new(1).map_err(storage_http)?)
            .map_err(|_| HttpFailure {
                status: 503,
                code: ErrorCode::BudgetExhausted,
            })?;
        transaction.execute(
            "INSERT INTO counters(action_id,count) VALUES(?1,?2) ON CONFLICT(action_id) DO UPDATE SET count=excluded.count",
            // WireInt is bounded by 2^53-1, strictly inside SQLite's signed INTEGER range.
            params![request.action_key, next.get() as i64],
        ).map_err(storage_http)?;
        transaction.commit().map_err(storage_http)?;
        Ok(CounterReply {
            action_id: request.action_id,
            count: next,
        })
    }
}

fn read_wire_counter(row: &rusqlite::Row<'_>) -> rusqlite::Result<WireInt> {
    let signed: i64 = row.get(0)?;
    let value =
        u64::try_from(signed).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, signed))?;
    WireInt::new(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, signed))
}

fn read_headers(
    stream: &mut TcpStream,
    buffer: &mut [u8; HEADER_LIMIT],
) -> Result<usize, HttpFailure> {
    let deadline = Instant::now() + CONNECTION_DEADLINE;
    let mut used: usize = 0;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(HttpFailure {
                status: 408,
                code: ErrorCode::Timeout,
            })?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(storage_http)?;
        let count = stream.read(&mut buffer[used..]).map_err(|_| HttpFailure {
            status: 400,
            code: ErrorCode::InvalidInput,
        })?;
        if count == 0 {
            return Err(HttpFailure {
                status: 400,
                code: ErrorCode::InvalidInput,
            });
        }
        let search_from = used.saturating_sub(3);
        used += count;
        if let Some(end) = buffer[search_from..used]
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
        {
            return Ok(search_from + end + 4);
        }
        if used == buffer.len() {
            return Err(HttpFailure {
                status: 413,
                code: ErrorCode::BudgetExhausted,
            });
        }
    }
}

fn parse_request<'a>(bytes: &'a [u8], token: &[u8; 64]) -> Result<Request<'a>, HttpFailure> {
    let bad = HttpFailure {
        status: 400,
        code: ErrorCode::InvalidInput,
    };
    if !bytes.is_ascii() {
        return Err(bad);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| bad)?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next().ok_or(bad)?.split(' ');
    let method = first.next().ok_or(bad)?;
    let target = first.next().ok_or(bad)?;
    if first.next() != Some("HTTP/1.1") || first.next().is_some() {
        return Err(bad);
    }
    let mut authorization = None;
    let mut content_length = None;
    let mut host = None;
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(bad)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return Err(bad);
        }
        let value = value.trim_matches([' ', '\t']);
        if value.bytes().any(|byte| byte < 32 && byte != b'\t') {
            return Err(bad);
        }
        if name.eq_ignore_ascii_case("authorization") {
            if authorization.replace(value).is_some() {
                return Err(bad);
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length.replace(value).is_some() || value != "0" {
                return Err(bad);
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("host")
                && (host.replace(value).is_some() || value.is_empty()))
        {
            return Err(bad);
        }
    }
    if host.is_none() {
        return Err(bad);
    }
    let authorized = authorization
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| {
            value.len() == token.len() && bool::from(value.as_bytes().ct_eq(token))
        });
    if !authorized {
        return Err(HttpFailure {
            status: 401,
            code: ErrorCode::PermissionDenied,
        });
    }
    let (action_key, increment) = match method {
        "POST" => (target.strip_prefix("/effect/").ok_or(bad)?, true),
        "GET" => (target.strip_prefix("/count/").ok_or(bad)?, false),
        _ => {
            return Err(HttpFailure {
                status: 405,
                code: ErrorCode::UnsupportedProtocol,
            });
        }
    };
    let action_id = EntityId::parse(action_key).map_err(|_| bad)?;
    Ok(Request {
        action_id,
        action_key,
        increment,
    })
}

fn write_reply<T: Serialize>(
    stream: &mut TcpStream,
    status: u16,
    reply: &T,
) -> std::io::Result<()> {
    let mut body = [0; 160];
    let mut encoded = Cursor::new(body.as_mut_slice());
    serde_json::to_writer(&mut encoded, reply).map_err(std::io::Error::other)?;
    let length = usize::try_from(encoded.position()).map_err(std::io::Error::other)?;
    stream.set_write_timeout(Some(CONNECTION_DEADLINE))?;
    write!(
        stream,
        "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
    )?;
    stream.write_all(&body[..length])
}

fn write_error(stream: &mut TcpStream, error: HttpFailure) -> std::io::Result<()> {
    #[derive(Serialize)]
    struct ErrorReply {
        code: ErrorCode,
    }
    write_reply(stream, error.status, &ErrorReply { code: error.code })
}

fn storage_http<E>(_: E) -> HttpFailure {
    HttpFailure {
        status: 500,
        code: ErrorCode::IntegrityError,
    }
}

fn storage_error<E: std::error::Error + 'static>(error: E) -> ProofError {
    let cause = &error as &(dyn std::error::Error + 'static);
    let mut failure = failure(
        ErrorCode::IntegrityError,
        "Receiver private storage operation failed",
    );
    // Retain error classes/codes, never library messages containing paths or input bytes.
    if let Some(rusqlite::Error::SqliteFailure(code, _)) = cause.downcast_ref::<rusqlite::Error>() {
        failure.message = std::borrow::Cow::Owned(format!(
            "Receiver SQLite operation failed (code {})",
            code.extended_code
        ));
    } else if let Some(error) = cause.downcast_ref::<std::io::Error>() {
        failure.message = std::borrow::Cow::Owned(format!(
            "Receiver storage I/O failed ({:?}, code {:?})",
            error.kind(),
            error.raw_os_error()
        ));
    } else if let Some(error) = cause.downcast_ref::<rustix::io::Errno>() {
        failure.message = std::borrow::Cow::Owned(format!(
            "Receiver storage syscall failed (code {})",
            error.raw_os_error()
        ));
    }
    failure
}

fn invalid(message: &'static str) -> ProofError {
    failure(ErrorCode::InvalidInput, message)
}

fn failure(code: ErrorCode, message: &'static str) -> ProofError {
    ProofError::new(code, message)
}
