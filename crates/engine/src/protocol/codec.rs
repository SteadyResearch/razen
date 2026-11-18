use std::borrow::Cow;
use std::collections::VecDeque;
use std::io::{self, BufRead, Write};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::error::{ErrorCode, ProofError, ProofResult};
use super::messages::{Message, decode_payload};
use crate::domain::values::{EntityId, non_null_optional};

pub const PROTOCOL: &str = "razen.proof/0.1.0";
const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_QUEUE_ITEMS: usize = 256;
const MAX_DIAGNOSTIC_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelRole {
    Runtime,
    Supervisor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    HostToPeer,
    PeerToHost,
}

/// Header references and typed payload borrow this one bounded input frame.
/// They do not establish authority; the host must resolve the authenticated binding.
#[derive(Debug, Serialize)]
pub struct Envelope<'a> {
    pub protocol: Cow<'a, str>,
    pub message_id: EntityId,
    pub kind: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<EntityId>,
    pub payload: &'a RawValue,
    #[serde(skip)]
    message: Message<'a>,
}

impl<'a> Envelope<'a> {
    pub fn message(&self) -> &Message<'a> {
        &self.message
    }

    pub fn into_message(self) -> Message<'a> {
        self.message
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header<'a> {
    #[serde(borrow)]
    protocol: Cow<'a, str>,
    message_id: EntityId,
    #[serde(borrow)]
    kind: Cow<'a, str>,
    #[serde(default, deserialize_with = "non_null_optional")]
    correlation_id: Option<EntityId>,
    #[serde(borrow)]
    payload: &'a RawValue,
}

pub fn decode_frame(
    bytes: &[u8],
    max_bytes: usize,
    role: ChannelRole,
    direction: Direction,
) -> ProofResult<Envelope<'_>> {
    validate_limit(max_bytes)?;
    if bytes.len() > max_bytes {
        return Err(capacity_error("Protocol frame exceeds its byte limit"));
    }
    let Some(body) = bytes.strip_suffix(b"\n") else {
        return Err(invalid("Protocol frame lacks its LF terminator"));
    };
    if body.contains(&b'\n') {
        return Err(invalid("Expected one JSON object per protocol line"));
    }
    let header: Header<'_> = serde_json::from_slice(body)
        .map_err(|_| invalid("Malformed or unknown protocol header fields"))?;
    if header.protocol != PROTOCOL {
        return Err(ProofError::new(
            ErrorCode::UnsupportedVersion,
            "Unsupported protocol version",
        ));
    }
    if header.kind.len() > 128 {
        return Err(invalid("Protocol kind exceeds its byte limit"));
    }
    let message = decode_payload(header.payload, role, direction, header.kind.as_ref())?;
    Ok(Envelope {
        protocol: header.protocol,
        message_id: header.message_id,
        kind: header.kind,
        correlation_id: header.correlation_id,
        payload: header.payload,
        message,
    })
}

/// Never drain a peer past its frame budget while searching for an eventual newline.
pub fn read_frame<R: BufRead>(reader: &mut R, max_bytes: usize) -> ProofResult<Option<Vec<u8>>> {
    validate_limit(max_bytes)?;
    let mut frame = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|_| invalid("Cannot read protocol channel"))?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(invalid("Incomplete protocol frame"))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(available.len(), |position| position + 1);
        if count > max_bytes - frame.len() {
            return Err(capacity_error("Protocol frame exceeds its byte limit"));
        }
        frame.extend_from_slice(&available[..count]);
        reader.consume(count);
        if newline.is_some() {
            return Ok(Some(frame));
        }
    }
}

pub fn encode_frame<T: Serialize>(value: &T, max_bytes: usize) -> ProofResult<Vec<u8>> {
    let mut bytes = Vec::new();
    encode_frame_into(value, &mut bytes, max_bytes)?;
    Ok(bytes)
}

/// Reuse caller-owned storage; failures leave no partial or previous frame.
pub fn encode_frame_into<T: Serialize>(
    value: &T,
    bytes: &mut Vec<u8>,
    max_bytes: usize,
) -> ProofResult<()> {
    bytes.clear();
    validate_limit(max_bytes)?;
    let mut writer = BoundedWriter {
        bytes,
        limit: max_bytes,
        exceeded: false,
    };
    if serde_json::to_writer(&mut writer, value).is_err() {
        let error = if writer.exceeded {
            capacity_error("Encoded protocol frame exceeds its byte limit")
        } else {
            invalid("Cannot encode protocol object")
        };
        writer.bytes.clear();
        return Err(error);
    }
    if writer.write_all(b"\n").is_err() {
        writer.bytes.clear();
        return Err(capacity_error(
            "Encoded protocol frame exceeds its byte limit",
        ));
    }
    Ok(())
}

struct BoundedWriter<'a> {
    bytes: &'a mut Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Protocol byte limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct BoundedQueue<T> {
    values: VecDeque<T>,
    capacity: usize,
}

impl<T> BoundedQueue<T> {
    pub fn new(capacity: usize) -> ProofResult<Self> {
        if capacity == 0 || capacity > MAX_QUEUE_ITEMS {
            return Err(invalid("Queue capacity is outside the permitted range"));
        }
        Ok(Self {
            values: VecDeque::with_capacity(capacity),
            capacity,
        })
    }

    pub fn push(&mut self, value: T) -> ProofResult<()> {
        if self.values.len() == self.capacity {
            return Err(capacity_error("Required protocol queue is full"));
        }
        self.values.push_back(value);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<T> {
        self.values.pop_front()
    }
}

pub struct DiagnosticBuffer {
    bytes: Vec<u8>,
    limit: usize,
    truncated: bool,
}

pub struct DiagnosticOutput {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

impl DiagnosticBuffer {
    pub fn new(limit: usize) -> ProofResult<Self> {
        if limit == 0 || limit > MAX_DIAGNOSTIC_BYTES {
            return Err(invalid(
                "Diagnostic capacity is outside the permitted range",
            ));
        }
        Ok(Self {
            bytes: Vec::new(),
            limit,
            truncated: false,
        })
    }

    pub fn push(&mut self, bytes: &[u8]) -> ProofResult<()> {
        let remaining = self.limit - self.bytes.len();
        self.bytes
            .extend_from_slice(&bytes[..bytes.len().min(remaining)]);
        if bytes.len() > remaining {
            self.truncated = true;
            return Err(capacity_error(
                "Diagnostic output was truncated at its byte limit",
            ));
        }
        Ok(())
    }

    pub fn finish(mut self, forbidden: &[&[u8]]) -> DiagnosticOutput {
        for secret in forbidden
            .iter()
            .copied()
            .filter(|secret| !secret.is_empty())
        {
            redact(&mut self.bytes, secret, self.truncated);
        }
        DiagnosticOutput {
            bytes: self.bytes,
            truncated: self.truncated,
        }
    }
}

fn redact(bytes: &mut [u8], secret: &[u8], truncated: bool) {
    let mut position = 0;
    while position < bytes.len() {
        let remaining = bytes.len() - position;
        let count = secret.len().min(remaining);
        if (count == secret.len() || truncated)
            && bytes[position..position + count] == secret[..count]
        {
            bytes[position..position + count].fill(b'*');
            position += count;
        } else {
            position += 1;
        }
    }
}

fn validate_limit(limit: usize) -> ProofResult<()> {
    if limit == 0 || limit > MAX_FRAME_BYTES {
        return Err(invalid("Frame limit is outside the permitted range"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> ProofError {
    ProofError::new(ErrorCode::InvalidInput, message)
}

fn capacity_error(message: &'static str) -> ProofError {
    ProofError::new(ErrorCode::BudgetExhausted, message)
}
