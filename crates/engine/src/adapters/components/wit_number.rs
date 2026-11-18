//! Invalid WIT u64 inputs are quoted decimal witnesses, not out-of-range WireInts.
use serde::{Deserialize, Deserializer, Serializer};
pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let value = String::deserialize(deserializer)?;
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(serde::de::Error::custom("invalid unsigned WIT witness"));
    }
    value.parse().map_err(serde::de::Error::custom)
}
pub(crate) mod observations {
    use super::super::bindings::{Observation, SnapshotReference};
    use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq};
    #[derive(Serialize)]
    struct Borrowed<'a> {
        rule_id: &'a str,
        title: &'a str,
        snapshot: &'a SnapshotReference,
        #[serde(with = "super")]
        range_start: u64,
        #[serde(with = "super")]
        range_end: u64,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Owned {
        rule_id: String,
        title: String,
        snapshot: SnapshotReference,
        #[serde(with = "super")]
        range_start: u64,
        #[serde(with = "super")]
        range_end: u64,
    }
    pub fn serialize<S: Serializer>(
        values: &[Observation],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(values.len()))?;
        for value in values {
            sequence.serialize_element(&Borrowed {
                rule_id: &value.rule_id,
                title: &value.title,
                snapshot: &value.snapshot,
                range_start: value.range_start,
                range_end: value.range_end,
            })?;
        }
        sequence.end()
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Observation>, D::Error> {
        let values = Vec::<Owned>::deserialize(deserializer)?;
        if values.len() > 128 {
            return Err(serde::de::Error::custom(
                "too many WIT observation witnesses",
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Observation {
                rule_id: value.rule_id,
                title: value.title,
                snapshot: value.snapshot,
                range_start: value.range_start,
                range_end: value.range_end,
            })
            .collect())
    }
}
