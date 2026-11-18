//! Shared record-boundary decoding; authority, execution and history use one policy.
use std::fmt;

use serde::de::{self, DeserializeSeed, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::protocol::error::{ErrorCode, ProofError};

pub(crate) const MAX_RECORD_ITEMS: usize = 256;
pub(crate) const MAX_METADATA_BYTES: usize = 256;

pub(crate) fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Record does not satisfy its contract",
    )
}

pub(crate) fn bounded_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Items<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Items<T> {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded record collection")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let size = sequence.size_hint().unwrap_or(0);
            if size > MAX_RECORD_ITEMS {
                return Err(de::Error::custom("record collection exceeds its limit"));
            }
            let mut values = Vec::with_capacity(size);
            while values.len() < MAX_RECORD_ITEMS {
                let Some(value) = sequence.next_element()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            // Detect an extra element without allocating/deserializing its payload.
            if sequence.next_element_seed(RejectAdditionalItem)?.is_some() {
                return Err(de::Error::custom("record collection exceeds its limit"));
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Items(std::marker::PhantomData))
}

struct RejectAdditionalItem;
impl<'de> DeserializeSeed<'de> for RejectAdditionalItem {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, _: D) -> Result<(), D::Error> {
        Err(de::Error::custom("record collection exceeds its limit"))
    }
}

pub(crate) fn bounded_text<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    text_limit::<D, MAX_METADATA_BYTES>(deserializer)
}

pub(crate) fn text_limit<'de, D: Deserializer<'de>, const MAX: usize>(
    deserializer: D,
) -> Result<String, D::Error> {
    fn validate<E: de::Error, const N: usize>(value: &str) -> Result<(), E> {
        if value.is_empty() || value.len() > N || value.chars().any(char::is_control) {
            return Err(E::custom("invalid record text"));
        }
        Ok(())
    }
    struct Text<const N: usize>;
    impl<const N: usize> Visitor<'_> for Text<N> {
        type Value = String;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("bounded nonempty UTF-8 text")
        }
        fn visit_str<E: de::Error>(self, value: &str) -> Result<String, E> {
            validate::<E, N>(value)?;
            Ok(value.to_owned())
        }
        fn visit_string<E: de::Error>(self, value: String) -> Result<String, E> {
            validate::<E, N>(&value)?;
            Ok(value)
        }
    }
    deserializer.deserialize_str(Text::<MAX>)
}
