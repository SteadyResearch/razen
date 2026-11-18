use std::fmt;
use std::time::SystemTime;

use jiff::{Timestamp, civil::DateTime, tz::Offset};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use uuid::{Uuid, Variant, Version};

pub const MAX_WIRE_INT: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueError {
    InvalidId,
    InvalidDigest,
    InvalidCatalogId,
    InvalidVersion,
    InvalidTimestamp,
    OutOfRange,
    InvalidRange,
}

impl ValueError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidId => "Expected a canonical UUID v4",
            Self::InvalidDigest => "Expected a lowercase SHA-256 digest",
            Self::InvalidCatalogId => "Invalid bounded catalog handle",
            Self::InvalidVersion => "Unsupported contract version",
            Self::InvalidTimestamp => "Expected a UTC RFC3339 timestamp",
            Self::OutOfRange => "Integer exceeds the permitted wire range",
            Self::InvalidRange => "Invalid half-open byte range",
        }
    }
}

impl fmt::Display for ValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for ValueError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EntityId(Uuid);

impl EntityId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn parse(value: &str) -> Result<Self, ValueError> {
        let uuid = Uuid::parse_str(value).map_err(|_| ValueError::InvalidId)?;
        if uuid.get_version() != Some(Version::Random) || uuid.get_variant() != Variant::RFC4122 {
            return Err(ValueError::InvalidId);
        }
        let mut canonical = [0; 36];
        if uuid.hyphenated().encode_lower(&mut canonical) != value {
            return Err(ValueError::InvalidId);
        }
        Ok(Self(uuid))
    }
}

impl Default for EntityId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WireInt(u64);

impl WireInt {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u64) -> Result<Self, ValueError> {
        if value > MAX_WIRE_INT {
            return Err(ValueError::OutOfRange);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, other: Self) -> Result<Self, ValueError> {
        Self::new(self.0.checked_add(other.0).ok_or(ValueError::OutOfRange)?)
    }

    pub fn checked_sub(self, other: Self) -> Result<Self, ValueError> {
        Self::new(self.0.checked_sub(other.0).ok_or(ValueError::OutOfRange)?)
    }
}

impl Serialize for WireInt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for WireInt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct IntegerVisitor;
        impl Visitor<'_> for IntegerVisitor {
            type Value = WireInt;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a nonnegative exact JSON wire integer")
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                WireInt::new(value).map_err(E::custom)
            }
        }
        deserializer.deserialize_u64(IntegerVisitor)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest([u8; 32]);

impl Digest {
    pub const fn from_sha256(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn parse(value: &str) -> Result<Self, ValueError> {
        if value.len() != 64 {
            return Err(ValueError::InvalidDigest);
        }
        let mut digest = [0; 32];
        for (target, pair) in digest.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
            *target = hex_nibble(pair[0])? * 16 + hex_nibble(pair[1])?;
        }
        Ok(Self(digest))
    }
}

fn hex_nibble(value: u8) -> Result<u8, ValueError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ValueError::InvalidDigest),
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = [0; 64];
        for (pair, byte) in encoded.as_chunks_mut::<2>().0.iter_mut().zip(self.0) {
            pair[0] = HEX[usize::from(byte >> 4)];
            pair[1] = HEX[usize::from(byte & 15)];
        }
        let encoded = std::str::from_utf8(&encoded).map_err(|_| fmt::Error)?;
        formatter.write_str(encoded)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CatalogId(Box<str>);

impl CatalogId {
    pub fn parse(value: &str) -> Result<Self, ValueError> {
        validate_catalog_id(value)?;
        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_catalog_id(value: &str) -> Result<(), ValueError> {
    if value.is_empty() || value.len() > 128 {
        return Err(ValueError::InvalidCatalogId);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(ValueError::InvalidCatalogId);
    }
    Ok(())
}

impl fmt::Display for CatalogId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for CatalogId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CatalogId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CatalogVisitor;
        impl Visitor<'_> for CatalogVisitor {
            type Value = CatalogId;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded catalog handle")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                CatalogId::parse(value).map_err(E::custom)
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                validate_catalog_id(&value).map_err(E::custom)?;
                Ok(CatalogId(value.into_boxed_str()))
            }
        }
        deserializer.deserialize_str(CatalogVisitor)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ContractVersion {
    #[serde(rename = "0.1.0")]
    V0_1_0,
}

impl ContractVersion {
    pub fn parse(value: &str) -> Result<Self, ValueError> {
        match value {
            "0.1.0" => Ok(Self::V0_1_0),
            _ => Err(ValueError::InvalidVersion),
        }
    }
}

impl fmt::Display for ContractVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("0.1.0")
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AuditTime(DateTime);

impl AuditTime {
    /// Absolute UTC grant expiry arithmetic; deadlines still use a monotonic clock.
    pub fn checked_add(self, duration: std::time::Duration) -> Result<Self, ValueError> {
        self.0
            .checked_add(duration)
            .map(Self)
            .map_err(|_| ValueError::InvalidTimestamp)
    }

    pub fn now() -> Self {
        let timestamp = Timestamp::try_from(SystemTime::now()).expect("system time is valid");
        Self(Offset::UTC.to_datetime(timestamp))
    }

    pub fn parse(value: &str) -> Result<Self, ValueError> {
        let civil = value
            .strip_suffix('Z')
            .or_else(|| value.strip_suffix('z'))
            .or_else(|| value.strip_suffix("+00:00"))
            .ok_or(ValueError::InvalidTimestamp)?;
        let bytes = civil.as_bytes();
        // Keep the RFC3339 boundary narrower than Jiff's Temporal syntax.
        // Jiff remains responsible for parsing and validating calendar fields.
        if bytes.len() < 19
            || !bytes[..4].iter().all(u8::is_ascii_digit)
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || !matches!(bytes[10], b'T' | b't' | b' ')
            || bytes[13] != b':'
            || bytes[16] != b':'
            || (bytes.len() > 19
                && (bytes[19] != b'.'
                    || bytes.len() == 20
                    || !bytes[20..].iter().all(u8::is_ascii_digit)))
        {
            return Err(ValueError::InvalidTimestamp);
        }
        // R0 rejects leap seconds rather than allowing Jiff to clamp 60 to 59.
        if &bytes[17..19] == b"60" {
            return Err(ValueError::InvalidTimestamp);
        }
        // RFC3339 permits arbitrary fraction length; stored precision is nanos.
        civil[..civil.len().min(29)]
            .parse()
            .map(Self)
            .map_err(|_| ValueError::InvalidTimestamp)
    }
}

impl fmt::Display for AuditTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let nanos = self.0.subsec_nanosecond();
        let precision = if nanos == 0 {
            0
        } else if nanos % 1_000_000 == 0 {
            3
        } else if nanos % 1_000 == 0 {
            6
        } else {
            9
        };
        write!(formatter, "{:.*}+00:00", precision, self.0)
    }
}

macro_rules! text_serde {
    ($kind:ty, $description:literal) => {
        impl Serialize for $kind {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $kind {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct TextVisitor;
                impl Visitor<'_> for TextVisitor {
                    type Value = $kind;
                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str($description)
                    }
                    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                        <$kind>::parse(value).map_err(E::custom)
                    }
                }
                deserializer.deserialize_str(TextVisitor)
            }
        }
    };
}

text_serde!(EntityId, "a canonical UUID v4");
text_serde!(Digest, "a lowercase SHA-256 digest");
text_serde!(AuditTime, "a UTC RFC3339 timestamp");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    start: WireInt,
    end: WireInt,
}

impl ByteRange {
    pub fn new(start: WireInt, end: WireInt, length: WireInt) -> Result<Self, ValueError> {
        if start > end || end > length {
            return Err(ValueError::InvalidRange);
        }
        Ok(Self { start, end })
    }

    pub const fn start(self) -> WireInt {
        self.start
    }

    pub const fn end(self) -> WireInt {
        self.end
    }

    pub const fn len(self) -> WireInt {
        WireInt(self.end.0 - self.start.0)
    }

    pub const fn is_empty(self) -> bool {
        self.start.0 == self.end.0
    }
}

pub fn non_null_optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Shared nonnegative resource counters; missing fields never default on the wire.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub units: WireInt,
    pub bytes: WireInt,
    pub cpu_us: WireInt,
    pub elapsed_us: WireInt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationState {
    Proposed,
    Rejected,
    WaitingApproval,
    Reserved,
    Sending,
    Completed,
    Failed,
    OutcomeUnknown,
    Cancelled,
}
