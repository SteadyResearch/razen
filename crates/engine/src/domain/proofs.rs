//! Proof records and catalog gates only. A record-level pass does not resolve evidence,
//! verify packet bytes, or supply the independent maintainer approval required for exit.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::domain::evidence::EvidenceRef;
use crate::domain::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, Usage, WireInt, non_null_optional,
};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult as ModelResult};

const MAX_ITEMS: usize = 128;
const MAX_TEXT_BYTES: usize = 4096;

fn invalid(message: &'static str) -> ProofError {
    ProofError::new(ErrorCode::InvalidInput, message)
}

fn bounded_text<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    struct TextVisitor;
    impl Visitor<'_> for TextVisitor {
        type Value = String;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a nonempty bounded metadata string")
        }
        fn visit_str<E: de::Error>(self, value: &str) -> Result<String, E> {
            if value.is_empty() || value.len() > MAX_TEXT_BYTES {
                return Err(E::custom("Metadata string exceeds its permitted bounds"));
            }
            Ok(value.to_owned())
        }
        fn visit_string<E: de::Error>(self, value: String) -> Result<String, E> {
            if value.is_empty() || value.len() > MAX_TEXT_BYTES {
                return Err(E::custom("Metadata string exceeds its permitted bounds"));
            }
            Ok(value)
        }
    }
    deserializer.deserialize_string(TextVisitor)
}

fn bounded_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ListVisitor<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for ListVisitor<T> {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded record-reference list")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Vec<T>, A::Error> {
            if sequence.size_hint().is_some_and(|size| size > MAX_ITEMS) {
                return Err(de::Error::custom(
                    "Reference list exceeds its permitted bound",
                ));
            }
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX_ITEMS {
                    return Err(de::Error::custom(
                        "Reference list exceeds its permitted bound",
                    ));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(ListVisitor(PhantomData))
}

fn bounded_map<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    struct MapVisitor<K, V>(PhantomData<(K, V)>);
    impl<'de, K: Deserialize<'de> + Ord, V: Deserialize<'de>> Visitor<'de> for MapVisitor<K, V> {
        type Value = BTreeMap<K, V>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded map with unique typed keys")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            if map.size_hint().is_some_and(|size| size > MAX_ITEMS) {
                return Err(de::Error::custom(
                    "Metadata map exceeds its permitted bound",
                ));
            }
            let mut values = BTreeMap::new();
            while let Some(key) = map.next_key()? {
                if values.len() == MAX_ITEMS || values.contains_key(&key) {
                    return Err(de::Error::custom(
                        "Metadata map exceeds its bound or repeats a key",
                    ));
                }
                values.insert(key, map.next_value()?);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(MapVisitor(PhantomData))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckName {
    RoundTrip,
    StableReferences,
    EvidenceVariants,
    InvalidRejected,
    FramingFuzz,
    TypedFuzz,
    CompleteBudget,
    Replayable,
    StaleRejected,
    ForeignRejected,
    OriginalUnchanged,
    ConsumerEquivalence,
    RevocationEnforced,
    ChildScopeBounded,
    AggregateQuota,
    GraphsDistinct,
    OwnershipFiltered,
    TwoMemoryLevels,
    PromotionBounded,
    Forwarded,
    HeadersPreserved,
    BodyExact,
    CaptureReferenced,
    OpaqueTunnel,
    UpstreamVerified,
    IsolatedTrust,
    TrustUnchanged,
    H2BothLegs,
    ConcurrentStreams,
    ScopeRechecked,
    PivotsDenied,
    HealthyObserver,
    ZeroForbiddenArrivals,
    InvalidTlsRejected,
    AuthoritiesMatch,
    SecretsAbsent,
    BodyBounded,
    RepresentationExplicit,
    NoPartialReplacement,
    StreamReset,
    ValidStreamSurvives,
    ErrorsAttributed,
    PublicWit,
    BoundedRead,
    ValidProposal,
    ExecutionInterrupted,
    DeadlineMet,
    MemoryBounded,
    AggregateInvocationsBounded,
    ControlAck,
    RssObserved,
    OutputBounded,
    HostCallDeadline,
    AggregateHostCallsBounded,
    UngrantedAccessDenied,
    AllVariantsObserved,
    SlotsReleased,
    FreshSuccess,
    RuntimeLifecycle,
    BrokeredCalls,
    ModelSeparate,
    ZeroModelEgress,
    EffectiveConfigAttested,
    MandatoryIsolation,
    ContaminationRejected,
    NoFallback,
    ActualAttempts,
    DescendantsRestricted,
    GrantedRead,
    DescriptorsClosed,
    ResourceLimits,
    TenControlSamples,
    NoStaleAdmissions,
    Contained,
    EventsDeduplicated,
    CausalityPreserved,
    LateWorkDenied,
    HostTransportLost,
    LeaseExpired,
    DescendantsTerminated,
    ReservationSeams,
    ConsumptionPreserved,
    ReservationReconciled,
    ZeroResends,
    SendingSeams,
    UnknownRestored,
    ReadOnlyReconciliation,
    CompletionRestored,
    CurrentAuthority,
    CurrentVersions,
    StaleWorkDenied,
    StorageFaults,
    AdmissionClosed,
    PartialEvidence,
    StablePins,
    Provenance,
    LicensesRecorded,
    DecisionsRecorded,
    RawMeasurements,
    CompleteInventory,
    PacketIntegrity,
    FailureBlocksExit,
    ApprovalRequired,
    R0Only,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Assertions(BTreeMap<CheckName, bool>);

impl Assertions {
    pub fn new(values: impl IntoIterator<Item = (CheckName, bool)>) -> ModelResult<Self> {
        let mut checks = BTreeMap::new();
        for (name, value) in values {
            if checks.len() == MAX_ITEMS || checks.contains_key(&name) {
                return Err(invalid(
                    "Assertion list exceeds its bound or repeats a check",
                ));
            }
            checks.insert(name, value);
        }
        Ok(Self(checks))
    }

    pub fn get(&self, name: CheckName) -> Option<bool> {
        self.0.get(&name).copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (CheckName, bool)> + '_ {
        self.0.iter().map(|(&name, &value)| (name, value))
    }

    fn matches_expected(&self, spec: &CaseSpec) -> bool {
        self.0.len() == spec.checks.len()
            && spec.checks.iter().all(|name| self.get(*name) == Some(true))
    }

    fn belongs_to(&self, spec: &CaseSpec) -> bool {
        self.0.keys().all(|name| spec.checks.contains(name))
    }
}

impl<'de> Deserialize<'de> for Assertions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        bounded_map(deserializer).map(Self)
    }
}

struct CaseSpec {
    id: &'static str,
    package: &'static str,
    requirements: &'static str,
    successes: &'static str,
    fixture: &'static str,
    checks: &'static [CheckName],
}

macro_rules! case_catalog {
    ($(($id:literal, $package:literal, $requirements:literal, $successes:literal, $fixture:literal, [$($check:ident),+])),+ $(,)?) => {
        const CASES: &[CaseSpec] = &[$(CaseSpec {
            id: $id, package: $package, requirements: $requirements, successes: $successes,
            fixture: concat!("fixtures/scenarios/", $fixture, ".json"),
            checks: &[$(CheckName::$check),+],
        }),+];
    };
}

case_catalog! {
    ("CON-01", "R0-01", "FR-002,FR-017", "SC-001", "contracts", [RoundTrip, StableReferences, EvidenceVariants]),
    ("CON-02", "R0-01", "FR-002,FR-004", "SC-001,SC-002", "contracts", [InvalidRejected, FramingFuzz, TypedFuzz, CompleteBudget, Replayable]),
    ("CON-03", "R0-01", "FR-002,FR-004", "SC-002", "contracts", [StaleRejected, ForeignRejected, OriginalUnchanged]),
    ("CON-04", "R0-01", "FR-004,FR-017", "SC-002", "contracts", [ConsumerEquivalence, RevocationEnforced, ChildScopeBounded, AggregateQuota]),
    ("CON-05", "R0-01", "FR-003", "SC-001,SC-002", "contracts", [GraphsDistinct, OwnershipFiltered, TwoMemoryLevels, PromotionBounded]),
    ("NET-01", "R0-02", "FR-005,FR-017", "SC-003", "transport", [Forwarded, HeadersPreserved, BodyExact, CaptureReferenced]),
    ("NET-02", "R0-02", "FR-005,FR-006", "SC-003", "transport", [Forwarded, BodyExact, OpaqueTunnel]),
    ("NET-03", "R0-02", "FR-005,FR-006", "SC-002,SC-003", "transport", [Forwarded, UpstreamVerified, IsolatedTrust, TrustUnchanged]),
    ("NET-04", "R0-02", "FR-005", "SC-003", "transport", [Forwarded, H2BothLegs, ConcurrentStreams, BodyExact]),
    ("NET-05", "R0-02", "FR-004,FR-005", "SC-002,SC-003", "transport", [ScopeRechecked, PivotsDenied, HealthyObserver, ZeroForbiddenArrivals]),
    ("NET-06", "R0-02", "FR-005,FR-006,FR-017", "SC-002,SC-003", "transport", [InvalidTlsRejected, AuthoritiesMatch, TrustUnchanged, SecretsAbsent]),
    ("NET-07", "R0-02", "FR-005,FR-018", "SC-003", "transport", [BodyBounded, RepresentationExplicit, InvalidRejected, NoPartialReplacement]),
    ("NET-08", "R0-02", "FR-005,FR-014", "SC-003", "transport", [StreamReset, ValidStreamSurvives, ErrorsAttributed]),
    ("CMP-01", "R0-03", "FR-007,FR-017", "SC-001,SC-004", "components", [PublicWit, BoundedRead, ValidProposal, OriginalUnchanged]),
    ("CMP-02", "R0-03", "FR-008", "SC-004", "components", [ExecutionInterrupted, DeadlineMet]),
    ("CMP-03", "R0-03", "FR-008,FR-014", "SC-004", "components", [MemoryBounded, AggregateInvocationsBounded, ControlAck, RssObserved]),
    ("CMP-04", "R0-03", "FR-007,FR-008", "SC-002,SC-004", "components", [InvalidRejected, StaleRejected, ForeignRejected, OutputBounded]),
    ("CMP-05", "R0-03", "FR-008", "SC-004", "components", [HostCallDeadline, AggregateHostCallsBounded, ControlAck]),
    ("CMP-06", "R0-03", "FR-006,FR-007,FR-008", "SC-002,SC-004", "components", [UngrantedAccessDenied, SecretsAbsent]),
    ("CMP-07", "R0-03", "FR-008,FR-017", "SC-004", "components", [AllVariantsObserved, SlotsReleased, FreshSuccess, ErrorsAttributed]),
    ("RUN-01", "R0-04", "FR-009,FR-017", "SC-001,SC-002", "runtime", [RuntimeLifecycle, BrokeredCalls, ModelSeparate, ZeroModelEgress]),
    ("RUN-02", "R0-04", "FR-010,FR-018", "SC-002,SC-004", "runtime", [EffectiveConfigAttested, MandatoryIsolation, ContaminationRejected, NoFallback]),
    ("RUN-03", "R0-04", "FR-006,FR-010", "SC-002,SC-004", "runtime", [ActualAttempts, DescendantsRestricted, GrantedRead, SecretsAbsent]),
    ("RUN-04", "R0-04", "FR-004,FR-010", "SC-002,SC-004", "runtime", [ActualAttempts, DescendantsRestricted, HealthyObserver, ZeroForbiddenArrivals, DescriptorsClosed]),
    ("RUN-05", "R0-04", "FR-010,FR-014", "SC-004", "runtime", [ActualAttempts, DescendantsRestricted, ResourceLimits, FreshSuccess]),
    ("RUN-06", "R0-04", "FR-011,FR-017", "SC-004,SC-005", "runtime", [TenControlSamples, ControlAck, NoStaleAdmissions, Contained]),
    ("RUN-07", "R0-04", "FR-004,FR-011,FR-012", "SC-002,SC-005", "runtime", [EventsDeduplicated, CausalityPreserved, LateWorkDenied, AggregateQuota]),
    ("RUN-08", "R0-04", "FR-010,FR-011,FR-012", "SC-004,SC-005", "runtime", [HostTransportLost, LeaseExpired, DescendantsTerminated, Contained]),
    ("REC-01", "R0-04", "FR-012", "SC-005", "runtime", [ReservationSeams, ConsumptionPreserved, ReservationReconciled, ZeroResends]),
    ("REC-02", "R0-04", "FR-012,FR-017", "SC-005", "runtime", [SendingSeams, UnknownRestored, ConsumptionPreserved, ReadOnlyReconciliation, ZeroResends]),
    ("REC-03", "R0-04", "FR-012,FR-017", "SC-005", "runtime", [CompletionRestored, EventsDeduplicated, ConsumptionPreserved, ZeroResends]),
    ("REC-04", "R0-04", "FR-004,FR-011,FR-012", "SC-002,SC-005", "runtime", [CurrentAuthority, CurrentVersions, StaleWorkDenied]),
    ("REC-05", "R0-04", "FR-012,FR-016,FR-018", "SC-005,SC-007", "runtime", [StorageFaults, AdmissionClosed, PartialEvidence, ZeroResends]),
    ("EXIT-01", "R0-05", "FR-013,FR-014,FR-015,FR-016", "SC-006", "manifest", [StablePins, Provenance, LicensesRecorded, DecisionsRecorded, RawMeasurements]),
    ("EXIT-02", "R0-05", "FR-001,FR-016,FR-018", "SC-001,SC-007", "manifest", [CompleteInventory, PacketIntegrity, FailureBlocksExit, ApprovalRequired, R0Only]),
}

struct PackageSpec {
    id: &'static str,
    requires: &'static str,
    requirements: &'static str,
}

// This catalog is topologically ordered; each required edge is checked exactly.
const PACKAGES: &[PackageSpec] = &[
    PackageSpec {
        id: "R0-01",
        requires: "",
        requirements: "FR-002,FR-003,FR-004,FR-017",
    },
    PackageSpec {
        id: "R0-02",
        requires: "R0-01",
        requirements: "FR-004,FR-005,FR-006,FR-014,FR-017,FR-018",
    },
    PackageSpec {
        id: "R0-03",
        requires: "R0-01",
        requirements: "FR-006,FR-007,FR-008,FR-014,FR-017",
    },
    PackageSpec {
        id: "R0-04",
        requires: "R0-01",
        requirements: "FR-004,FR-006,FR-009,FR-010,FR-011,FR-012,FR-014,FR-016,FR-017,FR-018",
    },
    PackageSpec {
        id: "R0-05",
        requires: "R0-01,R0-02,R0-03,R0-04",
        requirements: "FR-001,FR-013,FR-014,FR-015,FR-016,FR-018",
    },
];

fn case_spec(id: &CatalogId) -> ModelResult<&'static CaseSpec> {
    CASES
        .iter()
        .find(|case| case.id == id.as_str())
        .ok_or_else(|| invalid("Unknown proof case"))
}

/// Resolves the fixed, versioned case catalog without duplicating its inventory.
pub fn package_for_case(id: &CatalogId) -> ModelResult<&'static str> {
    Ok(case_spec(id)?.package)
}

fn matches_ids(values: &[CatalogId], expected: &str) -> bool {
    if expected.is_empty() {
        return values.is_empty();
    }
    values.len() == expected.split(',').count()
        && expected
            .split(',')
            .all(|id| values.iter().any(|value| value.as_str() == id))
}

fn text_valid(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WorkPackageWire")]
pub struct WorkPackage {
    pub package_id: CatalogId,
    pub title: String,
    pub requires: Vec<CatalogId>,
    pub requirement_ids: Vec<CatalogId>,
    pub case_ids: Vec<CatalogId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkPackageWire {
    package_id: CatalogId,
    #[serde(deserialize_with = "bounded_text")]
    title: String,
    #[serde(deserialize_with = "bounded_vec")]
    requires: Vec<CatalogId>,
    #[serde(deserialize_with = "bounded_vec")]
    requirement_ids: Vec<CatalogId>,
    #[serde(deserialize_with = "bounded_vec")]
    case_ids: Vec<CatalogId>,
}

impl TryFrom<WorkPackageWire> for WorkPackage {
    type Error = ProofError;
    fn try_from(value: WorkPackageWire) -> ModelResult<Self> {
        let record = Self {
            package_id: value.package_id,
            title: value.title,
            requires: value.requires,
            requirement_ids: value.requirement_ids,
            case_ids: value.case_ids,
        };
        record.validate()?;
        Ok(record)
    }
}

impl WorkPackage {
    pub fn validate(&self) -> ModelResult<()> {
        let spec = PACKAGES
            .iter()
            .find(|package| package.id == self.package_id.as_str())
            .ok_or_else(|| invalid("Unknown work package"))?;
        let mut cases = CASES.iter().filter(|case| case.package == spec.id);
        if !text_valid(&self.title, 256)
            || !matches_ids(&self.requires, spec.requires)
            || !matches_ids(&self.requirement_ids, spec.requirements)
            || self.case_ids.len() != cases.clone().count()
            || !cases.all(|case| self.case_ids.iter().any(|id| id.as_str() == case.id))
        {
            return Err(invalid(
                "Work package does not match the required catalog DAG",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ProofCaseWire")]
pub struct ProofCase {
    pub case_id: CatalogId,
    pub package_id: CatalogId,
    pub description: String,
    pub fixture_refs: Vec<String>,
    pub expected: Assertions,
    pub mandatory: bool,
    pub requirement_ids: Vec<CatalogId>,
    pub success_ids: Vec<CatalogId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofCaseWire {
    case_id: CatalogId,
    package_id: CatalogId,
    #[serde(deserialize_with = "bounded_text")]
    description: String,
    #[serde(deserialize_with = "bounded_vec")]
    fixture_refs: Vec<FixturePath>,
    expected: Assertions,
    mandatory: bool,
    #[serde(deserialize_with = "bounded_vec")]
    requirement_ids: Vec<CatalogId>,
    #[serde(deserialize_with = "bounded_vec")]
    success_ids: Vec<CatalogId>,
}

#[derive(Deserialize)]
struct FixturePath(#[serde(deserialize_with = "bounded_text")] String);

impl TryFrom<ProofCaseWire> for ProofCase {
    type Error = ProofError;
    fn try_from(value: ProofCaseWire) -> ModelResult<Self> {
        let record = Self {
            case_id: value.case_id,
            package_id: value.package_id,
            description: value.description,
            fixture_refs: value.fixture_refs.into_iter().map(|path| path.0).collect(),
            expected: value.expected,
            mandatory: value.mandatory,
            requirement_ids: value.requirement_ids,
            success_ids: value.success_ids,
        };
        record.validate()?;
        Ok(record)
    }
}

impl ProofCase {
    pub fn validate(&self) -> ModelResult<()> {
        let spec = case_spec(&self.case_id)?;
        if self.package_id.as_str() != spec.package
            || !text_valid(&self.description, MAX_TEXT_BYTES)
            || self.fixture_refs.len() != 1
            || self.fixture_refs[0] != spec.fixture
            || !self.mandatory
            || !matches_ids(&self.requirement_ids, spec.requirements)
            || !matches_ids(&self.success_ids, spec.successes)
            || !self.expected.matches_expected(spec)
        {
            return Err(invalid(
                "Proof case does not match the required verification inventory",
            ));
        }
        Ok(())
    }
}

/// Exact version spelling, not a floating selector or an arbitrary tool-output blob.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct VersionPin(String);

impl VersionPin {
    pub fn parse(value: &str) -> ModelResult<Self> {
        Self::validate_pin(value)?;
        Ok(Self(value.to_owned()))
    }

    fn validate_pin(value: &str) -> ModelResult<()> {
        if value.len() > 128
            || !value.as_bytes().first().is_some_and(u8::is_ascii_digit)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-+_".contains(&byte))
        {
            return Err(invalid(
                "Dependency version must be an exact bounded version pin",
            ));
        }
        Ok(())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for VersionPin {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = bounded_text(deserializer)?;
        Self::validate_pin(&value).map_err(de::Error::custom)?;
        Ok(Self(value))
    }
}

/// The profile's upstream raw-image pin is SHA-512, unlike all record SHA-256 fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ImageDigest(String);

impl ImageDigest {
    pub fn from_sha512(bytes: [u8; 64]) -> Self {
        let mut encoded = vec![0; 135];
        encoded[..7].copy_from_slice(b"sha512:");
        hex::encode_to_slice(bytes, &mut encoded[7..]).expect("fixed SHA-512 output length");
        Self(String::from_utf8(encoded).expect("hexadecimal encoding is ASCII"))
    }

    pub fn matches_sha512(&self, bytes: &[u8; 64]) -> bool {
        let mut expected = [0; 64];
        hex::decode_to_slice(&self.0.as_bytes()[7..], &mut expected)
            .expect("validated SHA-512 pin");
        expected == *bytes
    }

    pub fn parse(value: &str) -> ModelResult<Self> {
        Self::validate_pin(value)?;
        Ok(Self(value.to_owned()))
    }

    fn validate_pin(value: &str) -> ModelResult<()> {
        let hex = value
            .strip_prefix("sha512:")
            .ok_or_else(|| invalid("Image pin must identify SHA-512"))?;
        if hex.len() != 128
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid("Invalid upstream image SHA-512 pin"));
        }
        Ok(())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ImageDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = bounded_text(deserializer)?;
        Self::validate_pin(&value).map_err(de::Error::custom)?;
        Ok(Self(value))
    }
}

/// Whether this run required isolation and whether its setup was actually observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationStatus {
    NotRequired,
    Unavailable,
    Prepared,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "RunEnvironmentWire")]
pub struct RunEnvironment {
    pub hardware_model: String,
    pub logical_cpus: WireInt,
    pub memory_mib: WireInt,
    pub os: String,
    pub os_version: String,
    pub arch: String,
    pub os_build: String,
    pub kernel: String,
    pub filesystem: String,
    pub storage: String,
    pub component_target: String,
    pub backend: String,
    pub isolation_status: IsolationStatus,
    pub guest_os: String,
    pub image_digest: ImageDigest,
    pub dependency_versions: BTreeMap<CatalogId, VersionPin>,
    pub fixture_digests: BTreeMap<CatalogId, Digest>,
    pub binary_digests: BTreeMap<CatalogId, Digest>,
    pub lockfile_sha256: Digest,
    pub component_lockfile_sha256: Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_package_manifest_sha256: Option<Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioning_sha256: Option<Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_config_sha256: Option<Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp_sha256: Option<Digest>,
    pub wit_sha256: Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunEnvironmentWire {
    #[serde(deserialize_with = "bounded_text")]
    hardware_model: String,
    logical_cpus: WireInt,
    memory_mib: WireInt,
    #[serde(deserialize_with = "bounded_text")]
    os: String,
    #[serde(deserialize_with = "bounded_text")]
    os_version: String,
    #[serde(deserialize_with = "bounded_text")]
    arch: String,
    #[serde(deserialize_with = "bounded_text")]
    os_build: String,
    #[serde(deserialize_with = "bounded_text")]
    kernel: String,
    #[serde(deserialize_with = "bounded_text")]
    filesystem: String,
    #[serde(deserialize_with = "bounded_text")]
    storage: String,
    #[serde(deserialize_with = "bounded_text")]
    component_target: String,
    #[serde(deserialize_with = "bounded_text")]
    backend: String,
    isolation_status: IsolationStatus,
    #[serde(deserialize_with = "bounded_text")]
    guest_os: String,
    image_digest: ImageDigest,
    #[serde(deserialize_with = "bounded_map")]
    dependency_versions: BTreeMap<CatalogId, VersionPin>,
    #[serde(deserialize_with = "bounded_map")]
    fixture_digests: BTreeMap<CatalogId, Digest>,
    #[serde(deserialize_with = "bounded_map")]
    binary_digests: BTreeMap<CatalogId, Digest>,
    lockfile_sha256: Digest,
    component_lockfile_sha256: Digest,
    #[serde(default, deserialize_with = "non_null_optional")]
    guest_package_manifest_sha256: Option<Digest>,
    #[serde(default, deserialize_with = "non_null_optional")]
    provisioning_sha256: Option<Digest>,
    #[serde(default, deserialize_with = "non_null_optional")]
    effective_config_sha256: Option<Digest>,
    #[serde(default, deserialize_with = "non_null_optional")]
    seccomp_sha256: Option<Digest>,
    wit_sha256: Digest,
}

impl TryFrom<RunEnvironmentWire> for RunEnvironment {
    type Error = ProofError;
    fn try_from(value: RunEnvironmentWire) -> ModelResult<Self> {
        let record = Self {
            hardware_model: value.hardware_model,
            logical_cpus: value.logical_cpus,
            memory_mib: value.memory_mib,
            os: value.os,
            os_version: value.os_version,
            arch: value.arch,
            os_build: value.os_build,
            kernel: value.kernel,
            filesystem: value.filesystem,
            storage: value.storage,
            component_target: value.component_target,
            backend: value.backend,
            guest_os: value.guest_os,
            isolation_status: value.isolation_status,
            image_digest: value.image_digest,
            dependency_versions: value.dependency_versions,
            fixture_digests: value.fixture_digests,
            binary_digests: value.binary_digests,
            lockfile_sha256: value.lockfile_sha256,
            component_lockfile_sha256: value.component_lockfile_sha256,
            guest_package_manifest_sha256: value.guest_package_manifest_sha256,
            provisioning_sha256: value.provisioning_sha256,
            effective_config_sha256: value.effective_config_sha256,
            seccomp_sha256: value.seccomp_sha256,
            wit_sha256: value.wit_sha256,
        };
        record.validate()?;
        Ok(record)
    }
}

impl RunEnvironment {
    pub fn validate(&self) -> ModelResult<()> {
        for value in [
            &self.hardware_model,
            &self.os,
            &self.os_version,
            &self.arch,
            &self.os_build,
            &self.kernel,
            &self.filesystem,
            &self.storage,
            &self.component_target,
            &self.backend,
            &self.guest_os,
        ] {
            if !text_valid(value, 256) {
                return Err(invalid("Run environment contains invalid bounded metadata"));
            }
        }
        let required_versions: &[&str] = match self.isolation_status {
            IsolationStatus::Prepared => &["rust", "lima", "bubblewrap"],
            IsolationStatus::NotRequired | IsolationStatus::Unavailable => &["rust"],
        };
        let observations = [
            self.guest_package_manifest_sha256,
            self.provisioning_sha256,
            self.effective_config_sha256,
            self.seccomp_sha256,
        ];
        let valid_observations = match self.isolation_status {
            IsolationStatus::Prepared => observations.iter().all(Option::is_some),
            IsolationStatus::NotRequired | IsolationStatus::Unavailable => {
                observations.iter().all(Option::is_none)
            }
        };
        if self.logical_cpus == WireInt::ZERO
            || self.memory_mib == WireInt::ZERO
            || self.dependency_versions.len() > MAX_ITEMS
            || self.fixture_digests.is_empty()
            || self.fixture_digests.len() > MAX_ITEMS
            || self.binary_digests.is_empty()
            || self.binary_digests.len() > MAX_ITEMS
            || !required_versions.iter().all(|name| {
                self.dependency_versions
                    .keys()
                    .any(|key| key.as_str() == *name)
            })
            || !valid_observations
        {
            return Err(invalid(
                "Run environment has missing or incompatible bounded provenance",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "RunWire")]
pub struct Run {
    pub run_id: EntityId,
    pub contract_version: ContractVersion,
    pub profile_id: CatalogId,
    pub profile_sha256: Digest,
    pub clock_epoch_id: EntityId,
    pub started_at: AuditTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<AuditTime>,
    pub environment: RunEnvironment,
    pub dependency_record_refs: Vec<EntityId>,
    pub fixture_manifest_sha256: Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunWire {
    run_id: EntityId,
    contract_version: ContractVersion,
    profile_id: CatalogId,
    profile_sha256: Digest,
    clock_epoch_id: EntityId,
    started_at: AuditTime,
    #[serde(default, deserialize_with = "non_null_optional")]
    finished_at: Option<AuditTime>,
    environment: RunEnvironment,
    #[serde(deserialize_with = "bounded_vec")]
    dependency_record_refs: Vec<EntityId>,
    fixture_manifest_sha256: Digest,
}

impl TryFrom<RunWire> for Run {
    type Error = ProofError;
    fn try_from(value: RunWire) -> ModelResult<Self> {
        let record = Self {
            run_id: value.run_id,
            contract_version: value.contract_version,
            profile_id: value.profile_id,
            profile_sha256: value.profile_sha256,
            clock_epoch_id: value.clock_epoch_id,
            started_at: value.started_at,
            finished_at: value.finished_at,
            environment: value.environment,
            dependency_record_refs: value.dependency_record_refs,
            fixture_manifest_sha256: value.fixture_manifest_sha256,
        };
        record.validate()?;
        Ok(record)
    }
}

impl Run {
    pub fn validate(&self) -> ModelResult<()> {
        if self.profile_id.as_str() != "macos-arm64-proof"
            || self
                .finished_at
                .is_some_and(|finished| finished < self.started_at)
            || self.dependency_record_refs.len() > MAX_ITEMS
            || self
                .dependency_record_refs
                .iter()
                .enumerate()
                .any(|(index, id)| self.dependency_record_refs[..index].contains(id))
        {
            return Err(invalid(
                "Run identity, profile, chronology, or references are invalid",
            ));
        }
        self.environment.validate()
    }

    /// Completion may add a finish time, but cannot rebind or reopen the same run.
    pub fn validate_continuation(&self, next: &Self) -> ModelResult<()> {
        self.validate()?;
        next.validate()?;
        if self.run_id != next.run_id
            || self.contract_version != next.contract_version
            || self.profile_id != next.profile_id
            || self.profile_sha256 != next.profile_sha256
            || self.clock_epoch_id != next.clock_epoch_id
            || self.started_at != next.started_at
            || self.environment != next.environment
            || self.dependency_record_refs != next.dependency_record_refs
            || self.fixture_manifest_sha256 != next.fixture_manifest_sha256
            || self
                .finished_at
                .is_some_and(|finished| next.finished_at != Some(finished))
        {
            return Err(ProofError::new(
                ErrorCode::IntegrityError,
                "Immutable run bindings changed; create a new run",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Passed,
    Failed,
    Blocked,
    Unexecuted,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ProofResultWire")]
pub struct ProofResult {
    pub run_id: EntityId,
    pub case_id: CatalogId,
    pub status: CaseStatus,
    pub expected: Assertions,
    pub observed: Assertions,
    pub evidence_refs: Vec<EvidenceRef>,
    pub elapsed_us: WireInt,
    pub usage: Usage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ProofError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofResultWire {
    run_id: EntityId,
    case_id: CatalogId,
    status: CaseStatus,
    expected: Assertions,
    observed: Assertions,
    #[serde(deserialize_with = "bounded_vec")]
    evidence_refs: Vec<EvidenceRef>,
    elapsed_us: WireInt,
    usage: Usage,
    #[serde(default, deserialize_with = "non_null_optional")]
    error: Option<ProofError>,
}

impl TryFrom<ProofResultWire> for ProofResult {
    type Error = ProofError;
    fn try_from(value: ProofResultWire) -> ModelResult<Self> {
        let record = Self {
            run_id: value.run_id,
            case_id: value.case_id,
            status: value.status,
            expected: value.expected,
            observed: value.observed,
            evidence_refs: value.evidence_refs,
            elapsed_us: value.elapsed_us,
            usage: value.usage,
            error: value.error,
        };
        record.validate()?;
        Ok(record)
    }
}

impl ProofResult {
    pub fn validate(&self) -> ModelResult<()> {
        let spec = case_spec(&self.case_id)?;
        if !self.expected.matches_expected(spec)
            || !self.observed.belongs_to(spec)
            || self.evidence_refs.len() > MAX_ITEMS
            || (self.status == CaseStatus::Passed
                && (self.evidence_refs.is_empty() || !self.observed.matches_expected(spec)))
        {
            return Err(invalid(
                "Proof result lacks case-specific observations or required evidence",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageStatus {
    Passed,
    Incomplete,
    Blocked,
    Failed,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(try_from = "ProofInventoryWire")]
pub struct ProofInventory {
    packages: Vec<WorkPackage>,
    cases: Vec<ProofCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofInventoryWire {
    #[serde(deserialize_with = "bounded_vec")]
    packages: Vec<WorkPackage>,
    #[serde(deserialize_with = "bounded_vec")]
    cases: Vec<ProofCase>,
}

impl TryFrom<ProofInventoryWire> for ProofInventory {
    type Error = ProofError;
    fn try_from(value: ProofInventoryWire) -> ModelResult<Self> {
        Self::new(value.packages, value.cases)
    }
}

impl ProofInventory {
    pub fn new(packages: Vec<WorkPackage>, cases: Vec<ProofCase>) -> ModelResult<Self> {
        if packages.len() != PACKAGES.len() || cases.len() != CASES.len() {
            return Err(invalid(
                "Proof inventory does not contain the full required catalog",
            ));
        }
        for (index, package) in packages.iter().enumerate() {
            package.validate()?;
            if packages[..index]
                .iter()
                .any(|prior| prior.package_id == package.package_id)
            {
                return Err(invalid("Proof inventory repeats a package"));
            }
        }
        for (index, case) in cases.iter().enumerate() {
            case.validate()?;
            if cases[..index]
                .iter()
                .any(|prior| prior.case_id == case.case_id)
            {
                return Err(invalid("Proof inventory repeats a case"));
            }
        }
        Ok(Self { packages, cases })
    }

    pub fn packages(&self) -> &[WorkPackage] {
        &self.packages
    }

    pub fn cases(&self) -> &[ProofCase] {
        &self.cases
    }

    /// Computes only the record/coverage gate, never external evidence integrity or approval.
    /// Missing mandatory results remain incomplete; every prerequisite participates.
    pub fn package_status(
        &self,
        run: &Run,
        results: &[ProofResult],
        package: &CatalogId,
    ) -> ModelResult<PackageStatus> {
        run.validate()?;
        let selected = PACKAGES
            .iter()
            .position(|spec| spec.id == package.as_str())
            .ok_or_else(|| invalid("Unknown work package"))?;
        if results.len() > CASES.len() {
            return Err(invalid("Proof results exceed the required inventory"));
        }
        let mut outcomes = [None; CASES.len()];
        for result in results {
            result.validate()?;
            if result.run_id != run.run_id {
                return Err(ProofError::new(
                    ErrorCode::IntegrityError,
                    "Proof result belongs to another run",
                ));
            }
            let index = CASES
                .iter()
                .position(|spec| spec.id == result.case_id.as_str())
                .ok_or_else(|| invalid("Unknown proof case"))?;
            if outcomes[index].replace(result.status).is_some() {
                return Err(invalid("Proof results repeat a run and case identity"));
            }
        }
        let mut statuses = [PackageStatus::Passed; PACKAGES.len()];
        for (index, spec) in PACKAGES.iter().enumerate() {
            for (case_index, _) in CASES
                .iter()
                .enumerate()
                .filter(|(_, case)| case.package == spec.id)
            {
                let outcome = match outcomes[case_index] {
                    Some(CaseStatus::Passed) => PackageStatus::Passed,
                    Some(CaseStatus::Failed) => PackageStatus::Failed,
                    Some(CaseStatus::Blocked) => PackageStatus::Blocked,
                    Some(CaseStatus::Unexecuted) | None => PackageStatus::Incomplete,
                };
                statuses[index] = statuses[index].max(outcome);
            }
            for (prior, dependency) in PACKAGES[..index].iter().enumerate() {
                if spec.requires.split(',').any(|id| id == dependency.id) {
                    statuses[index] = statuses[index].max(statuses[prior]);
                }
            }
        }
        Ok(statuses[selected])
    }
}

#[cfg(test)]
mod image_digest_tests {
    use super::ImageDigest;
    use sha2::{Digest as _, Sha512};

    #[test]
    fn sha512_image_pins_match_the_standard_abc_vector_and_reject_other_archive_bytes() {
        let expected = "sha512:ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        let digest: [u8; 64] = Sha512::digest(b"abc").into();
        let pin = ImageDigest::from_sha512(digest);
        assert_eq!(pin.as_str(), expected);
        let parsed = ImageDigest::parse(expected).unwrap();
        assert!(parsed.matches_sha512(&digest));
        assert!(!parsed.matches_sha512(&Sha512::digest(b"abd").into()));
    }
}
