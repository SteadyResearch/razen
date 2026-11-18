use crate::{Result, fail, wire};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, UdpSocket},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, net::UnixListener},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const OBSERVER_FAMILIES: [&str; 10] = [
    "ipv4_tcp", "ipv6_tcp", "ipv4_udp", "ipv6_udp", "unix", "vsock", "dns", "gateway", "target",
    "model",
];

pub struct Observers {
    tcp4: TcpListener,
    tcp6: TcpListener,
    role_receivers: [TcpListener; 3],
    udp4: UdpSocket,
    udp6: UdpSocket,
    dns: UdpSocket,
    unix: UnixListener,
    vsock: OwnedFd,
    path: PathBuf,
    pub endpoints: Value,
    healthy: [u64; OBSERVER_FAMILIES.len()],
    arrivals: [u64; OBSERVER_FAMILIES.len()],
}
impl Observers {
    pub fn new(directory: &Path) -> Result<Self> {
        let deadline = Instant::now() + Duration::from_millis(250);
        let tcp4 = context("observer.tcp4.bind", TcpListener::bind(("127.0.0.1", 0)))?;
        let tcp6 = context("observer.tcp6.bind", TcpListener::bind(("::1", 0)))?;
        let udp4 = context("observer.udp4.bind", UdpSocket::bind(("127.0.0.1", 0)))?;
        let udp6 = context("observer.udp6.bind", UdpSocket::bind(("::1", 0)))?;
        let dns = context("observer.dns.bind", UdpSocket::bind(("127.0.0.1", 0)))?;
        let path = directory.join("manager.sock");
        let unix = context("observer.unix.bind", UnixListener::bind(&path))?;
        // Fixture roles live outside the workload's network namespace. Never expose
        // host loopback or substitute Lima's intentionally refused gateway alias.
        let role_receivers = [
            context("observer.gateway.bind", TcpListener::bind(("127.0.0.1", 0)))?,
            context("observer.target.bind", TcpListener::bind(("127.0.0.1", 0)))?,
            context("observer.model.bind", TcpListener::bind(("127.0.0.1", 0)))?,
        ];
        context("observer.tcp4.nonblocking", tcp4.set_nonblocking(true))?;
        context("observer.tcp6.nonblocking", tcp6.set_nonblocking(true))?;
        context("observer.udp4.nonblocking", udp4.set_nonblocking(true))?;
        context("observer.udp6.nonblocking", udp6.set_nonblocking(true))?;
        context("observer.dns.nonblocking", dns.set_nonblocking(true))?;
        context("observer.unix.nonblocking", unix.set_nonblocking(true))?;
        for (listener, operation) in role_receivers.iter().zip([
            "observer.gateway.nonblocking",
            "observer.target.nonblocking",
            "observer.model.nonblocking",
        ]) {
            context(operation, listener.set_nonblocking(true))?;
        }
        // SAFETY: socket returns a newly owned FD; sockaddr_vm is initialized with valid family/port/CID.
        let raw = unsafe {
            libc::socket(
                libc::AF_VSOCK,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if raw < 0 {
            return context(
                "observer.vsock.socket",
                Err(std::io::Error::last_os_error()),
            );
        }
        // SAFETY: raw is a unique successful socket descriptor.
        let vsock = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: zero is valid padding/flags initialization for sockaddr_vm.
        let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        address.svm_family = libc::AF_VSOCK as u16;
        address.svm_cid = libc::VMADDR_CID_ANY;
        address.svm_port = libc::VMADDR_PORT_ANY;
        // SAFETY: address points to an initialized sockaddr_vm of the supplied length.
        if unsafe {
            libc::bind(
                raw,
                (&address as *const libc::sockaddr_vm).cast(),
                std::mem::size_of_val(&address) as u32,
            )
        } < 0
        {
            return context("observer.vsock.bind", Err(std::io::Error::last_os_error()));
        }
        // SAFETY: raw is a live socket which has successfully bound.
        if unsafe { libc::listen(raw, 16) } < 0 {
            return context(
                "observer.vsock.listen",
                Err(std::io::Error::last_os_error()),
            );
        }
        let mut length = std::mem::size_of_val(&address) as u32;
        // SAFETY: address and length are writable and describe the socket's address buffer.
        if unsafe {
            libc::getsockname(
                raw,
                (&mut address as *mut libc::sockaddr_vm).cast(),
                &mut length,
            )
        } < 0
        {
            return context(
                "observer.vsock.getsockname",
                Err(std::io::Error::last_os_error()),
            );
        }
        let tcp4_addr = context("observer.tcp4.local_addr", tcp4.local_addr())?;
        let tcp6_addr = context("observer.tcp6.local_addr", tcp6.local_addr())?;
        let udp4_addr = context("observer.udp4.local_addr", udp4.local_addr())?;
        let udp6_addr = context("observer.udp6.local_addr", udp6.local_addr())?;
        let dns_addr = context("observer.dns.local_addr", dns.local_addr())?;
        let role_addresses = [
            context(
                "observer.gateway.local_addr",
                role_receivers[0].local_addr(),
            )?,
            context("observer.target.local_addr", role_receivers[1].local_addr())?,
            context("observer.model.local_addr", role_receivers[2].local_addr())?,
        ];
        let endpoints = json!({"tcp4":tcp4_addr.to_string(),"tcp6":tcp6_addr.to_string(),"udp4":udp4_addr.to_string(),"udp6":udp6_addr.to_string(),"dns":dns_addr.to_string(),"unix":path,"vsock_port":address.svm_port,"gateway":role_addresses[0].to_string(),"target":role_addresses[1].to_string(),"model":role_addresses[2].to_string()});
        let mut observers = Self {
            tcp4,
            tcp6,
            role_receivers,
            udp4,
            udp6,
            dns,
            unix,
            vsock,
            path,
            endpoints,
            healthy: [0; OBSERVER_FAMILIES.len()],
            arrivals: [0; OBSERVER_FAMILIES.len()],
        };
        let tcp4_control = context(
            "observer.tcp4.control.connect",
            inet_connect(tcp4_addr, deadline),
        )?;
        context(
            "observer.tcp4.control.write",
            write_healthy_control(tcp4_control),
        )?;
        let tcp6_control = context(
            "observer.tcp6.control.connect",
            inet_connect(tcp6_addr, deadline),
        )?;
        context(
            "observer.tcp6.control.write",
            write_healthy_control(tcp6_control),
        )?;
        for (address, (connect_operation, write_operation)) in role_addresses.into_iter().zip([
            (
                "observer.gateway.control.connect",
                "observer.gateway.control.write",
            ),
            (
                "observer.target.control.connect",
                "observer.target.control.write",
            ),
            (
                "observer.model.control.connect",
                "observer.model.control.write",
            ),
        ]) {
            let control = context(connect_operation, inet_connect(address, deadline))?;
            context(write_operation, write_healthy_control(control))?;
        }
        let udp4_control = context(
            "observer.udp4.control.bind",
            UdpSocket::bind(("127.0.0.1", 0)),
        )?;
        context(
            "observer.udp4.control.sendto",
            udp4_control.send_to(b"healthy", udp4_addr),
        )?;
        let udp6_control = context("observer.udp6.control.bind", UdpSocket::bind(("::1", 0)))?;
        context(
            "observer.udp6.control.sendto",
            udp6_control.send_to(b"healthy", udp6_addr),
        )?;
        let unix_control = context(
            "observer.unix.control.connect",
            unix_connect(&observers.path, deadline),
        )?;
        context(
            "observer.unix.control.write",
            write_healthy_control(unix_control),
        )?;
        context(
            "observer.vsock.control.connect",
            vsock_connect(address.svm_port, deadline),
        )?;
        let dns_client = context(
            "observer.dns.control.bind",
            UdpSocket::bind(("127.0.0.1", 0)),
        )?;
        context(
            "observer.dns.control.read_timeout",
            dns_client.set_read_timeout(Some(Duration::from_millis(200))),
        )?;
        context(
            "observer.dns.control.sendto",
            dns_client.send_to(dns_query(), dns_addr),
        )?;
        while observers.arrivals.contains(&0) && Instant::now() < deadline {
            context("observer.control.poll", observers.poll())?;
            std::thread::sleep(Duration::from_millis(1));
        }
        if observers.arrivals.iter().any(|n| *n != 1) {
            return Err(fail(
                "observer.control.arrivals: reachable independent observer healthy controls failed",
            ));
        }
        let mut answer = [0u8; 512];
        let received = context("observer.dns.control.recv", dns_client.recv(&mut answer))?;
        if received < 16
            || answer[0..2] != dns_query()[0..2]
            || answer[2] & 0x80 == 0
            || answer[3] & 15 != 0
            || answer[6..8] != [0, 1]
            || answer[received - 4..received] != [127, 0, 0, 1]
        {
            return Err(fail(
                "observer.dns.control.answer: healthy permitted DNS query did not receive a valid owned A response",
            ));
        }
        observers.healthy = observers.arrivals;
        Ok(observers)
    }
    pub fn poll(&mut self) -> Result<()> {
        for (index, listener, operation) in [
            (0, &self.tcp4, "observer.tcp4.accept"),
            (1, &self.tcp6, "observer.tcp6.accept"),
            (7, &self.role_receivers[0], "observer.gateway.accept"),
            (8, &self.role_receivers[1], "observer.target.accept"),
            (9, &self.role_receivers[2], "observer.model.accept"),
        ] {
            for _ in 0..64 {
                match listener.accept() {
                    Ok((_socket, _)) => self.arrivals[index] += 1,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return context(operation, Err(e)),
                }
            }
        }
        let mut bytes = [0u8; 512];
        for (index, socket) in [(2, &self.udp4), (3, &self.udp6)] {
            for _ in 0..64 {
                match socket.recv_from(&mut bytes) {
                    Ok(_) => self.arrivals[index] += 1,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        return context(
                            if index == 2 {
                                "observer.udp4.recvfrom"
                            } else {
                                "observer.udp6.recvfrom"
                            },
                            Err(e),
                        );
                    }
                }
            }
        }
        for _ in 0..64 {
            match self.dns.recv_from(&mut bytes) {
                Ok((count, peer)) => {
                    self.arrivals[6] += 1;
                    if &bytes[..count] == dns_query() {
                        let mut response = bytes[..count].to_vec();
                        response[2] = 0x81;
                        response[3] = 0x80;
                        response[7] = 1;
                        response.extend_from_slice(&[
                            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1,
                        ]);
                        context("observer.dns.sendto", self.dns.send_to(&response, peer))?;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return context("observer.dns.recvfrom", Err(e)),
            }
        }
        for _ in 0..64 {
            match self.unix.accept() {
                Ok(_) => self.arrivals[4] += 1,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return context("observer.unix.accept", Err(e)),
            }
        }
        for _ in 0..64 {
            // SAFETY: accept4 reads no address when both address pointers are null; returns an owned FD.
            let fd = unsafe {
                libc::accept4(
                    self.vsock.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                )
            };
            if fd >= 0 {
                self.arrivals[5] += 1;
                // SAFETY: the just-accepted owned FD is not retained elsewhere.
                unsafe {
                    libc::close(fd);
                }
            } else {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    break;
                }
                return context("observer.vsock.accept", Err(error));
            }
        }
        Ok(())
    }
    pub fn facts(&self) -> Vec<Value> {
        OBSERVER_FAMILIES
            .iter()
            .enumerate()
            .map(|(index, family)| {
                json!({
                    "family":family,
                    "healthy_arrivals":self.healthy[index],
                    "unauthorized_arrivals":self.arrivals[index].saturating_sub(self.healthy[index])
                })
            })
            .collect()
    }
}
#[derive(Debug)]
struct OperationError {
    operation: &'static str,
    source: Box<dyn std::error::Error + Send + Sync>,
}
impl std::fmt::Display for OperationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.operation)
    }
}
impl std::error::Error for OperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}
fn context<T, E: Into<Box<dyn std::error::Error + Send + Sync>>>(
    operation: &'static str,
    result: std::result::Result<T, E>,
) -> Result<T> {
    result.map_err(|source| {
        Box::new(OperationError {
            operation,
            source: source.into(),
        }) as Box<dyn std::error::Error + Send + Sync>
    })
}

#[derive(Debug)]
struct NetworkError {
    primitive: &'static str,
    source: std::io::Error,
    incomplete: bool,
}
impl NetworkError {
    fn denied(primitive: &'static str, source: std::io::Error) -> Self {
        Self {
            primitive,
            source,
            incomplete: false,
        }
    }
    fn incomplete(primitive: &'static str, message: &'static str) -> Self {
        Self {
            primitive,
            source: std::io::Error::new(std::io::ErrorKind::TimedOut, message),
            incomplete: true,
        }
    }
}
impl std::fmt::Display for NetworkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.primitive)
    }
}
impl std::error::Error for NetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
type NetworkResult<T> = std::result::Result<T, NetworkError>;

fn network_socket(domain: i32, kind: i32) -> NetworkResult<OwnedFd> {
    // SAFETY: socket returns a newly owned descriptor and receives no pointers.
    let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(NetworkError::denied(
            "socket",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: fd is a successful socket result with unique ownership.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn inet_address(address: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: all-zero storage is valid padding; each write is aligned and fits storage.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let length = match address {
        SocketAddr::V4(address) => {
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as _,
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: storage is large and aligned enough for sockaddr_in.
            unsafe { std::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), raw) };
            std::mem::size_of_val(&raw)
        }
        SocketAddr::V6(address) => {
            let raw = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as _,
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo().to_be(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            };
            // SAFETY: storage is large and aligned enough for sockaddr_in6.
            unsafe { std::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), raw) };
            std::mem::size_of_val(&raw)
        }
    };
    (storage, length as libc::socklen_t)
}

fn connect_socket(
    domain: i32,
    address: &libc::sockaddr_storage,
    length: libc::socklen_t,
    deadline: Instant,
) -> NetworkResult<OwnedFd> {
    let socket = network_socket(domain, libc::SOCK_STREAM)?;
    if Instant::now() >= deadline {
        return Err(NetworkError::incomplete(
            "socket",
            "connection budget exhausted before connect",
        ));
    }
    // SAFETY: callers initialize storage with the matching family and exact address length.
    let rc = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (address as *const libc::sockaddr_storage).cast(),
            length,
        )
    };
    if rc < 0 {
        let error = std::io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::EINPROGRESS) | Some(libc::EALREADY)
        ) {
            return Err(NetworkError::denied("connect", error));
        }
    }
    // Even immediate connect success must have writable completion and a zero SO_ERROR.
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(NetworkError::incomplete(
                "connect",
                "connection completion budget exhausted",
            ));
        }
        let mut descriptor = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // Round down so poll cannot extend the existing absolute deadline.
        let timeout = remaining.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: descriptor is a live, writable pollfd and its count is one.
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(NetworkError::denied("poll", error));
        }
        if ready == 0 {
            continue;
        }
        let mut error: libc::c_int = 0;
        let mut size = std::mem::size_of_val(&error) as libc::socklen_t;
        // SAFETY: error/size describe a writable c_int buffer; socket remains live.
        if unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut error as *mut libc::c_int).cast(),
                &mut size,
            )
        } < 0
        {
            return Err(NetworkError::denied(
                "getsockopt",
                std::io::Error::last_os_error(),
            ));
        }
        if error != 0 {
            return Err(NetworkError::denied(
                "connect",
                std::io::Error::from_raw_os_error(error),
            ));
        }
        if descriptor.revents & libc::POLLOUT == 0 {
            return Err(NetworkError::incomplete(
                "connect",
                "connection completion lacked writable readiness",
            ));
        }
        if Instant::now() >= deadline {
            return Err(NetworkError::incomplete(
                "connect",
                "connection completion budget exhausted",
            ));
        }
        return Ok(socket);
    }
}

fn write_healthy_control(socket: OwnedFd) -> std::io::Result<()> {
    // One nonblocking send preserves the real payload without a write_all retry loop.
    let payload = b"healthy";
    // SAFETY: socket is live and payload remains readable for its supplied length.
    let sent = unsafe {
        libc::send(
            socket.as_raw_fd(),
            payload.as_ptr().cast(),
            payload.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if sent as usize != payload.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "healthy control write was incomplete",
        ));
    }
    Ok(())
}

fn inet_connect(address: SocketAddr, deadline: Instant) -> NetworkResult<OwnedFd> {
    let (raw, length) = inet_address(address);
    connect_socket(
        if address.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        },
        &raw,
        length,
        deadline,
    )
}

fn unix_connect(path: &Path, deadline: Instant) -> NetworkResult<OwnedFd> {
    // SAFETY: zero initialization provides valid fields, padding and path terminator.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as _;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(NetworkError {
            primitive: "none",
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UNIX control address is invalid",
            ),
            incomplete: true,
        });
    }
    for (destination, byte) in address.sun_path.iter_mut().zip(bytes) {
        *destination = *byte as libc::c_char;
    }
    // SAFETY: storage is sufficiently aligned/large and address is fully initialized.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    // SAFETY: sockaddr_storage is sufficiently large and aligned for sockaddr_un,
    // and the source and destination are initialized, live stack values.
    unsafe {
        std::ptr::write(
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            address,
        )
    };
    connect_socket(
        libc::AF_UNIX,
        &storage,
        std::mem::size_of_val(&address) as _,
        deadline,
    )
}

fn vsock_connect(port: u32, deadline: Instant) -> NetworkResult<OwnedFd> {
    // SAFETY: zero initializes sockaddr_vm's reserved fields and padding.
    let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    address.svm_family = libc::AF_VSOCK as _;
    address.svm_cid = libc::VMADDR_CID_LOCAL;
    address.svm_port = port;
    // SAFETY: storage is sufficiently aligned/large and address is fully initialized.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    // SAFETY: sockaddr_storage is sufficiently large and aligned for sockaddr_vm,
    // and the source and destination are initialized, live stack values.
    unsafe {
        std::ptr::write(
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            address,
        )
    };
    connect_socket(
        libc::AF_VSOCK,
        &storage,
        std::mem::size_of_val(&address) as _,
        deadline,
    )
}

fn udp_send(address: SocketAddr, payload: &[u8]) -> NetworkResult<()> {
    let domain = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let socket = network_socket(domain, libc::SOCK_DGRAM)?;
    let bind_address = if address.is_ipv4() {
        SocketAddr::from(([0u8; 4], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let (bind_address, bind_length) = inet_address(bind_address);
    // SAFETY: bind_address is an initialized address of the socket's family.
    if unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&bind_address as *const libc::sockaddr_storage).cast(),
            bind_length,
        )
    } < 0
    {
        return Err(NetworkError::denied(
            "bind",
            std::io::Error::last_os_error(),
        ));
    }
    let (destination, length) = inet_address(address);
    // SAFETY: payload and destination remain live for their exact supplied lengths.
    if unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            payload.as_ptr().cast(),
            payload.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            (&destination as *const libc::sockaddr_storage).cast(),
            length,
        )
    } < 0
    {
        return Err(NetworkError::denied(
            "sendto",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

// An unfinished connection is not a denial: only a real syscall error or nonzero
// SO_ERROR supplies denied_primitive/errno. Counts remain one per logical attempt.
fn network_outcome(
    variant: &str,
    actor: &str,
    result: NetworkResult<()>,
    mut detail: Value,
    primitive: &'static str,
) -> Result<()> {
    note_primitive();
    let (status, errno, reached, denied) = match result {
        Ok(()) => ("allowed", None, primitive, None),
        Err(error) => (
            if error.incomplete {
                "incomplete"
            } else {
                "denied"
            },
            error.source.raw_os_error(),
            error.primitive,
            (!error.incomplete).then_some(error.primitive),
        ),
    };
    detail["attempted_primitive"] = json!((reached != "none").then_some(reached));
    detail["denied_primitive"] = json!(denied);
    if ["ipv4_udp", "ipv6_udp", "dns"].contains(&variant) {
        detail["udp_send_attempted"] = json!(reached == "sendto");
    }
    emit(variant, actor, status, errno, detail)
}
std::thread_local! {static PRIMITIVE_ATTEMPTS:std::cell::Cell<u64>=const{std::cell::Cell::new(0)};}
fn note_primitive() {
    PRIMITIVE_ATTEMPTS.with(|count| count.set(count.get() + 1));
}
fn emit(variant: &str, actor: &str, result: &str, errno: Option<i32>, detail: Value) -> Result<()> {
    let attempts = PRIMITIVE_ATTEMPTS.with(std::cell::Cell::get);
    let v = json!({"variant":variant,"actor":actor,"pid":std::process::id(),"primitive_attempt_count":attempts,"count_semantics":"completed_primitive_attempts","result":result,"errno":errno,"detail":detail});
    let mut bytes = serde_json::to_vec(&v)?;
    bytes.push(b'\n');
    if bytes.len() > 4096 {
        return Err(fail("atomic attempt record exceeds PIPE_BUF"));
    }
    let mut output = std::io::stdout().lock();
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(())
}
fn outcome(variant: &str, actor: &str, result: std::io::Result<()>, detail: Value) -> Result<()> {
    note_primitive();
    match result {
        Ok(()) => emit(variant, actor, "allowed", None, detail),
        Err(e) => emit(variant, actor, "denied", e.raw_os_error(), detail),
    }
}
fn raw_result(value: i64) -> std::io::Result<()> {
    if value < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub fn run(variant: &str, actor: &str) -> Result<()> {
    let configuration = wire::unique(&fs::read("/inputs/fixture.json")?)?;
    let endpoints = &configuration["endpoints"];
    if actor == "exec_descendant"
        && ["fork", "thread", "memory", "cpu", "output", "orphan"].contains(&variant)
    {
        prime(variant, actor)?;
    }
    match variant {
        "snapshot_control" => {
            let bytes = fs::read("/inputs/snapshot")?;
            note_primitive();
            let digest = crate::sandbox::hash(&bytes);
            emit(
                variant,
                actor,
                if digest == configuration["snapshot_sha256"] {
                    "completed"
                } else {
                    "invalid"
                },
                None,
                json!({"snapshot_sha256":digest,"bytes":bytes.len()}),
            )?;
        }
        "host_canary" | "manager_canary" | "other_invocation" | "credential" => {
            let path = configuration["canaries"][variant]
                .as_str()
                .ok_or_else(|| fail("real canary target missing"))?;
            let result = File::open(path).and_then(|mut f| {
                let mut b = [0u8; 1];
                f.read_exact(&mut b)
            });
            outcome(
                variant,
                actor,
                result,
                json!({"target_sha256":crate::sandbox::hash(path.as_bytes())}),
            )?;
            if variant == "credential" {
                let path = configuration["canaries"]["ssh_private"]
                    .as_str()
                    .ok_or_else(|| fail("actual managed SSH credential target missing"))?;
                outcome(
                    variant,
                    actor,
                    File::open(path).and_then(|mut file| {
                        let mut byte = [0u8; 1];
                        file.read_exact(&mut byte)
                    }),
                    json!({"target_kind":"vm-ssh-private","target_sha256":crate::sandbox::hash(path.as_bytes())}),
                )?;
            }
        }
        "ipv4_tcp" | "ipv6_tcp" | "loopback" | "gateway" | "target" | "model" => {
            let key = if variant == "ipv6_tcp" {
                "tcp6"
            } else if ["gateway", "target", "model"].contains(&variant) {
                variant
            } else {
                "tcp4"
            };
            let addr = endpoints[key]
                .as_str()
                .ok_or_else(|| fail("reachable TCP observer target missing"))?;
            let deadline = Instant::now() + Duration::from_millis(100);
            network_outcome(
                variant,
                actor,
                inet_connect(addr.parse()?, deadline).map(|_| ()),
                json!({"destination":crate::sandbox::hash(addr.as_bytes())}),
                "connect",
            )?;
        }
        "ipv4_udp" | "ipv6_udp" | "dns" => {
            let ipv6 = variant == "ipv6_udp";
            let key = if variant == "dns" {
                "dns"
            } else if ipv6 {
                "udp6"
            } else {
                "udp4"
            };
            let addr = endpoints[key]
                .as_str()
                .ok_or_else(|| fail("UDP/DNS observer missing"))?;
            let result = udp_send(
                addr.parse()?,
                if variant == "dns" {
                    dns_query()
                } else {
                    b"unauthorized"
                },
            );
            network_outcome(variant, actor, result, json!({}), "sendto")?;
        }
        "unix" => {
            let path = endpoints["unix"]
                .as_str()
                .ok_or_else(|| fail("Unix observer missing"))?;
            let deadline = Instant::now() + Duration::from_millis(100);
            network_outcome(
                variant,
                actor,
                unix_connect(Path::new(path), deadline).map(|_| ()),
                json!({"manager_socket_path_sha256":crate::sandbox::hash(path.as_bytes())}),
                "connect",
            )?;
        }
        "vsock" => {
            let port = endpoints["vsock_port"]
                .as_u64()
                .ok_or_else(|| fail("VSOCK observer missing"))? as u32;
            let deadline = Instant::now() + Duration::from_millis(100);
            network_outcome(
                variant,
                actor,
                vsock_connect(port, deadline).map(|_| ()),
                json!({"cid":libc::VMADDR_CID_LOCAL,"port":port}),
                "connect",
            )?;
        }
        "inherited_fd" | "descriptor" => {
            let mut leaked = 0;
            for fd in 3..64 {
                // SAFETY: fcntl F_GETFD only probes numeric descriptors and does not dereference memory.
                let result = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                note_primitive();
                if result >= 0 {
                    leaked += 1;
                }
            }
            let result = File::open("/proc/1/root/var/lib/razen/credentials/synthetic").map(|_| ());
            outcome(
                variant,
                actor,
                result,
                json!({"inherited_nonstdio_fds":leaked,"probed_descriptors":61}),
            )?;
        }
        "privilege" => {
            // SAFETY: actual self-directed privilege escalation attempt, no foreign process/address.
            let rc = unsafe { libc::setresuid(0, 0, 0) };
            outcome(
                variant,
                actor,
                raw_result(rc as i64),
                json!({"requested_uid":0}),
            )?;
            // SAFETY: valid numeric self-directed privilege syscall arguments, deliberately subjected to seccomp.
            let gid = unsafe { libc::setresgid(0, 0, 0) };
            outcome(
                variant,
                actor,
                raw_result(gid as i64),
                json!({"operation":"setresgid"}),
            )?;
            // SAFETY: ptrace's TRACEME request uses no user pointers and concerns only this fixture.
            let ptrace = unsafe {
                libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            };
            outcome(
                variant,
                actor,
                raw_result(ptrace),
                json!({"operation":"ptrace"}),
            )?;
            let mut bpf_attribute = [0u32; 36];
            bpf_attribute[0] = 2;
            bpf_attribute[1] = 4;
            bpf_attribute[2] = 4;
            bpf_attribute[3] = 1;
            // SAFETY: valid BPF_MAP_CREATE array-map attributes in a bounded initialized buffer; no invalid-argument denial is used.
            let bpf = unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    0,
                    bpf_attribute.as_ptr(),
                    std::mem::size_of_val(&bpf_attribute),
                )
            };
            if bpf >= 0 {
                // SAFETY: a successful BPF_MAP_CREATE returns an owned FD.
                unsafe {
                    libc::close(bpf as i32);
                }
            }
            outcome(variant, actor, raw_result(bpf), json!({"operation":"bpf"}))?;
            let mut ring_parameters = [0u64; 16];
            // SAFETY: io_uring_setup receives an initialized, writable buffer larger than io_uring_params.
            let ring =
                unsafe { libc::syscall(libc::SYS_io_uring_setup, 1, ring_parameters.as_mut_ptr()) };
            if ring >= 0 {
                // SAFETY: a successful io_uring_setup returns an owned descriptor.
                unsafe {
                    libc::close(ring as i32);
                }
            }
            outcome(
                variant,
                actor,
                raw_result(ring),
                json!({"operation":"io_uring_setup"}),
            )?;
        }
        "namespace" => {
            // SAFETY: this invokes the actual self namespace-creation syscall, expected to be filtered.
            let rc = unsafe {
                libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWNET)
            };
            outcome(
                variant,
                actor,
                raw_result(rc as i64),
                json!({"operation":"unshare"}),
            )?;
            let namespace = File::open("/proc/self/ns/user")?;
            // SAFETY: namespace refers to this process's actual namespace FD; no foreign namespace is selected.
            let setns = unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWUSER) };
            outcome(
                variant,
                actor,
                raw_result(setns as i64),
                json!({"operation":"setns"}),
            )?;
            let target = format!("/tmp/mount-probe-{actor}");
            fs::create_dir(&target)?;
            let target = std::ffi::CString::new(target)?;
            // SAFETY: static filesystem/source and an owned NUL-terminated target directory; no untrusted pointer.
            let mount = unsafe {
                libc::mount(
                    c"none".as_ptr(),
                    target.as_ptr(),
                    c"tmpfs".as_ptr(),
                    0,
                    std::ptr::null(),
                )
            };
            outcome(
                variant,
                actor,
                raw_result(mount as i64),
                json!({"operation":"mount"}),
            )?;
        }
        "cgroup" => {
            outcome(
                variant,
                actor,
                fs::write(
                    "/sys/fs/cgroup/cgroup.procs",
                    std::process::id().to_string(),
                ),
                json!({"operation":"write_cgroup_procs"}),
            )?;
        }
        "fork" => {
            emit(
                variant,
                actor,
                "attempt_started",
                None,
                json!({"operation":"fork_until_denied"}),
            )?;
            let mut children = Vec::new();
            loop {
                // SAFETY: this single-threaded adversary forks a sleeping child; no parent shared locks are touched.
                let pid = unsafe { libc::fork() };
                let error = (pid < 0).then(std::io::Error::last_os_error);
                note_primitive();
                if let Some(error) = error {
                    emit(
                        variant,
                        actor,
                        "denied",
                        error.raw_os_error(),
                        json!({"children_created":children.len()}),
                    )?;
                    break;
                }
                if pid == 0 {
                    loop {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
                children.push(pid);
                if children.len() > 128 {
                    return Err(fail("PID controller failed to bound descendants"));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            loop {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        "thread" => {
            emit(
                variant,
                actor,
                "attempt_started",
                None,
                json!({"operation":"thread_until_denied"}),
            )?;
            let mut threads = Vec::new();
            loop {
                let spawned = std::thread::Builder::new().spawn(|| {
                    loop {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                });
                note_primitive();
                match spawned {
                    Ok(t) => threads.push(t),
                    Err(e) => {
                        emit(
                            variant,
                            actor,
                            "denied",
                            e.raw_os_error(),
                            json!({"threads_created":threads.len()}),
                        )?;
                        break;
                    }
                }
                if threads.len() > 128 {
                    return Err(fail("PID controller failed to bound threads"));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            loop {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        "memory" => {
            emit(
                variant,
                actor,
                "attempt_started",
                None,
                json!({"operation":"allocate_and_touch"}),
            )?;
            let mut blocks = Vec::new();
            loop {
                let mut block = vec![0u8; 1024 * 1024];
                for i in (0..block.len()).step_by(4096) {
                    block[i] = 1;
                    note_primitive();
                }
                std::hint::black_box(&block);
                blocks.push(block);
                if blocks.len() == 16 {
                    emit(
                        variant,
                        actor,
                        "flood_progress",
                        None,
                        json!({"touched_bytes":blocks.len()*1048576}),
                    )?;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        "cpu" => {
            emit(
                variant,
                actor,
                "attempt_started",
                None,
                json!({"operation":"compute_forever"}),
            )?;
            let mut x = 1u64;
            loop {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                std::hint::black_box(x);
                note_primitive();
            }
        }
        "tmpfs" => {
            emit(
                variant,
                actor,
                "attempt_started",
                None,
                json!({"operation":"write_tmpfs_until_full"}),
            )?;
            let mut f = File::create(format!("/tmp/flood-{actor}"))?;
            let block = [7u8; 65536];
            let mut bytes = 0u64;
            loop {
                let written = f.write(&block);
                note_primitive();
                match written {
                    Ok(0) => return Err(fail("tmpfs write made no progress")),
                    Ok(n) => bytes += n as u64,
                    Err(e) => {
                        emit(
                            variant,
                            actor,
                            "denied",
                            e.raw_os_error(),
                            json!({"bytes_written":bytes}),
                        )?;
                        break;
                    }
                }
            }
        }
        "output" => {
            emit(
                variant,
                actor,
                "attempt_started",
                None,
                json!({"operation":"stdout_flood"}),
            )?;
            let mut block = [b'x'; 2048];
            block[2047] = b'\n';
            let mut written = 0u64;
            loop {
                std::io::stdout().write_all(&block)?;
                note_primitive();
                written += block.len() as u64;
                if written == 65536 {
                    emit(
                        variant,
                        actor,
                        "flood_progress",
                        None,
                        json!({"written_bytes":written}),
                    )?;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        "orphan" => {
            emit(
                variant,
                actor,
                "attempt_started",
                None,
                json!({"operation":"descendant_heartbeat"}),
            )?;
            loop {
                std::io::stdout().write_all(b"heartbeat\n")?;
                note_primitive();
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        _ => return Err(fail("unapproved adversary operation")),
    }
    Ok(())
}
fn prime(variant: &str, actor: &str) -> Result<()> {
    match variant {
        "fork" => {
            // SAFETY: single-threaded fixture forks one child which immediately sleeps until cgroup cleanup.
            let pid = unsafe { libc::fork() };
            let error = (pid < 0).then(std::io::Error::last_os_error);
            note_primitive();
            if let Some(error) = error {
                return Err(error.into());
            }
            if pid == 0 {
                loop {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            emit(variant, actor, "primed", None, json!({"created_pid":pid}))?;
        }
        "thread" => {
            let _thread = std::thread::Builder::new().spawn(|| {
                loop {
                    std::thread::sleep(Duration::from_millis(100));
                }
            })?;
            note_primitive();
            emit(
                variant,
                actor,
                "primed",
                None,
                json!({"threads_created":PRIMITIVE_ATTEMPTS.with(std::cell::Cell::get)}),
            )?;
        }
        "memory" => {
            let mut bytes = vec![0u8; 1048576];
            for i in (0..bytes.len()).step_by(4096) {
                bytes[i] = 1;
                note_primitive();
            }
            std::hint::black_box(&bytes);
            emit(
                variant,
                actor,
                "primed",
                None,
                json!({"touched_bytes":bytes.len()}),
            )?;
        }
        "cpu" => {
            let start = Instant::now();
            let mut value = 1u64;
            for _ in 0..10000 {
                value = value.wrapping_mul(1664525).wrapping_add(1013904223);
                std::hint::black_box(value);
                note_primitive();
            }
            emit(
                variant,
                actor,
                "primed",
                None,
                json!({"iterations":PRIMITIVE_ATTEMPTS.with(std::cell::Cell::get),"elapsed_ns":start.elapsed().as_nanos()}),
            )?;
        }
        "output" => {
            let body = b"output-primitive-control\n";
            std::io::stdout().write_all(body)?;
            note_primitive();
            emit(
                variant,
                actor,
                "primed",
                None,
                json!({"written_bytes":body.len()}),
            )?;
        }
        "orphan" => {
            let body = b"heartbeat\n";
            std::io::stdout().write_all(body)?;
            note_primitive();
            emit(
                variant,
                actor,
                "primed",
                None,
                json!({"heartbeat_bytes":body.len()}),
            )?;
        }
        _ => {}
    }
    Ok(())
}
pub fn parent_and_descendant(variant: &str) -> Result<()> {
    if ["fork", "thread", "memory", "cpu", "output", "orphan"].contains(&variant) {
        prime(variant, "parent")?;
        // Start the exec descendant first so a parent flood cannot prevent descendant coverage.
        let mut child = Command::new("/runtime/razen-sandbox-adversary")
            .args(["--descendant", variant])
            .env_clear()
            .stdin(Stdio::null())
            .spawn()?;
        if variant == "orphan" {
            run(variant, "parent")?;
        } else {
            std::thread::sleep(Duration::from_millis(20));
            run(variant, "parent")?;
        }
        let _ = child.wait();
        return Ok(());
    }
    run(variant, "parent")?;
    let status = Command::new("/runtime/razen-sandbox-adversary")
        .args(["--descendant", variant])
        .env_clear()
        .stdin(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(fail(
            "exec descendant failed before reporting actual operation",
        ));
    }
    Ok(())
}
fn dns_query() -> &'static [u8] {
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07fixture\x04test\x00\x00\x01\x00\x01"
}
