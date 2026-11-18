use crate::{Result, fail};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::AsRawFd,
};

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Operation {
    Arguments = 1,
    ReadPlacementGate = 2,
    ClosePlacementGate = 3,
    CloseDescriptors = 4,
    LimitDescriptors = 5,
    DisableCoreDump = 6,
    ClearGroups = 7,
    SetGroup = 8,
    SetUser = 9,
    NoNewPrivileges = 10,
    DiagnosticCloexec = 11,
    ExecBubblewrap = 12,
}
impl Operation {
    pub fn name(self) -> &'static str {
        match self {
            Self::Arguments => "launcher.arguments",
            Self::ReadPlacementGate => "launcher.read_placement_gate",
            Self::ClosePlacementGate => "launcher.close_placement_gate",
            Self::CloseDescriptors => "launcher.close_descriptors",
            Self::LimitDescriptors => "launcher.setrlimit_nofile",
            Self::DisableCoreDump => "launcher.setrlimit_core",
            Self::ClearGroups => "launcher.setgroups",
            Self::SetGroup => "launcher.setresgid",
            Self::SetUser => "launcher.setresuid",
            Self::NoNewPrivileges => "launcher.no_new_privs",
            Self::DiagnosticCloexec => "launcher.diagnostic_cloexec",
            Self::ExecBubblewrap => "launcher.exec_bubblewrap",
        }
    }
    fn decode(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Arguments,
            2 => Self::ReadPlacementGate,
            3 => Self::ClosePlacementGate,
            4 => Self::CloseDescriptors,
            5 => Self::LimitDescriptors,
            6 => Self::DisableCoreDump,
            7 => Self::ClearGroups,
            8 => Self::SetGroup,
            9 => Self::SetUser,
            10 => Self::NoNewPrivileges,
            11 => Self::DiagnosticCloexec,
            12 => Self::ExecBubblewrap,
            _ => return None,
        })
    }
}

#[derive(Debug)]
pub struct Failure {
    operation: Operation,
    source: io::Error,
}
impl Failure {
    pub fn io(operation: Operation, source: io::Error) -> Self {
        Self { operation, source }
    }
    pub fn condition(operation: Operation, kind: io::ErrorKind) -> Self {
        Self::io(operation, io::Error::from(kind))
    }
    pub fn operation(&self) -> &'static str {
        self.operation.name()
    }
    pub fn report(&self, channel: &mut File) -> io::Result<()> {
        // Fixed, atomic-sized private record: magic, version, closed operation, Linux errno.
        let mut bytes = [b'R', b'Z', 1, self.operation as u8, 0, 0, 0, 0];
        bytes[4..].copy_from_slice(&self.source.raw_os_error().unwrap_or(0).to_le_bytes());
        channel.write_all(&bytes)
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.operation.name(), self.source)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

pub struct Channel {
    file: File,
    bytes: [u8; 9],
    length: usize,
    eof: bool,
    delivered: bool,
}
impl Channel {
    pub fn new(file: File) -> Result<Self> {
        crate::lifecycle::nonblocking(file.as_raw_fd())?;
        Ok(Self {
            file,
            bytes: [0; 9],
            length: 0,
            eof: false,
            delivered: false,
        })
    }
    pub fn read(&mut self) -> Result<Option<Failure>> {
        if self.delivered {
            return Ok(None);
        }
        while !self.eof && self.length < self.bytes.len() {
            match self.file.read(&mut self.bytes[self.length..]) {
                Ok(0) => self.eof = true,
                Ok(count) => self.length += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        if self.length > 8 {
            return Err(fail(
                "trusted launcher failure metadata exceeds its fixed bound",
            ));
        }
        if self.length == 8 {
            if self.bytes[..3] != [b'R', b'Z', 1] {
                return Err(fail("trusted launcher failure metadata version is invalid"));
            }
            let operation = Operation::decode(self.bytes[3])
                .ok_or_else(|| fail("trusted launcher failure operation is invalid"))?;
            let errno =
                i32::from_le_bytes([self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]]);
            if !(0..=4095).contains(&errno) {
                return Err(fail("trusted launcher failure errno is invalid"));
            }
            let source = if errno == 0 {
                io::Error::from(io::ErrorKind::Other)
            } else {
                io::Error::from_raw_os_error(errno)
            };
            self.delivered = true;
            return Ok(Some(Failure::io(operation, source)));
        }
        if self.eof && self.length != 0 {
            return Err(fail("trusted launcher failure metadata is truncated"));
        }
        Ok(None)
    }
    pub fn exec_closed(&self) -> bool {
        self.eof && self.length == 0
    }
}
