//! Bounded host-owned SQLite state. The sidecar lock, not a directory or SQLite inode,
//! owns the writer lifetime. Callbacks must not perform runtime, network, or termination waits.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use rustix::fs::{self, FileType, FlockOperation, Mode, OFlags, Stat};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::workspace::OwnedDirectory;
use crate::application::profile::LoadedProfile;
use crate::domain::authority::{
    ApprovalGrant, Budget, FixtureProject, IdentityProfile, ScopePolicy, ToolDescriptor,
};
use crate::domain::execution::{Checkpoint, ControlMode, ControlState, Event};
use crate::domain::invocation::{Invocation, InvocationHistory};
use crate::domain::knowledge::InvestigationSession;
use crate::domain::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, InvocationState, Usage, WireInt,
};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

const APP_ID: u32 = 0x525A4C47;
const SCHEMA_VERSION: u32 = 3;
const MAX_RECORD_BYTES: usize = 1_048_576;
const MAX_DATABASE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_BUDGETS: i64 = 256;
const MAX_INVOCATIONS: i64 = 4096;
const MAX_CONTROLS: i64 = 64;
const MAX_EVENTS: i64 = 16_384;
// Every admitted canonical event can require a transactionally paired checkpoint.
const MAX_CHECKPOINTS: i64 = MAX_EVENTS;
const MAX_PROJECTS: i64 = 256;
const MAX_SCOPES: i64 = 1024;
const MAX_IDENTITIES: i64 = 1024;
const MAX_TOOLS: i64 = 256;
const MAX_GRANTS: i64 = 4096;
const MAX_SESSIONS: i64 = 64;
const MAX_DEPTH: usize = 32;
const DB_NAME: &str = "ledger.sqlite";
const LOCK_NAME: &str = "ledger.lock";
const TABLES: [(&str, &str); 12] = [
    (
        "ledger_meta",
        "CREATE TABLE ledger_meta(id INTEGER PRIMARY KEY CHECK(id=1),schema_version TEXT NOT NULL,run_id TEXT NOT NULL,profile_sha256 TEXT NOT NULL)",
    ),
    (
        "budgets",
        "CREATE TABLE budgets(budget_id TEXT PRIMARY KEY NOT NULL CHECK(length(budget_id)=36),parent_budget_id TEXT REFERENCES budgets(budget_id),quota_limit INTEGER NOT NULL CHECK(quota_limit BETWEEN 0 AND 9007199254740991),consumed INTEGER NOT NULL CHECK(consumed BETWEEN 0 AND 9007199254740991),reserved INTEGER NOT NULL CHECK(reserved BETWEEN 0 AND 9007199254740991),revision INTEGER NOT NULL CHECK(revision BETWEEN 0 AND 9007199254740991),CHECK(consumed+reserved<=quota_limit),CHECK(parent_budget_id IS NULL OR parent_budget_id<>budget_id))",
    ),
    (
        "controls",
        "CREATE TABLE controls(investigation_id TEXT PRIMARY KEY NOT NULL CHECK(length(investigation_id)=36),revision INTEGER NOT NULL CHECK(revision BETWEEN 0 AND 9007199254740991),project_id TEXT NOT NULL CHECK(length(project_id)=36),scope_revision INTEGER NOT NULL CHECK(scope_revision BETWEEN 0 AND 9007199254740991),data BLOB NOT NULL CHECK(length(data)<=1048576))",
    ),
    (
        "invocations",
        "CREATE TABLE invocations(invocation_id TEXT PRIMARY KEY NOT NULL CHECK(length(invocation_id)=36),run_id TEXT NOT NULL CHECK(length(run_id)=36),deduplication_key TEXT NOT NULL CHECK(length(deduplication_key)<=256),investigation_id TEXT NOT NULL REFERENCES controls(investigation_id),budget_id TEXT NOT NULL REFERENCES budgets(budget_id),state TEXT NOT NULL CHECK(state IN ('proposed','rejected','waiting_approval','reserved','sending','completed','failed','outcome_unknown','cancelled')),control_revision INTEGER NOT NULL CHECK(control_revision BETWEEN 0 AND 9007199254740991),reserved_units INTEGER NOT NULL CHECK(reserved_units BETWEEN 0 AND 9007199254740991),data BLOB NOT NULL CHECK(length(data)<=1048576),history BLOB NOT NULL CHECK(length(history)<=1048576),requested BLOB NOT NULL CHECK(length(requested)<=1024),source_control_revision INTEGER NOT NULL CHECK(source_control_revision BETWEEN 0 AND 9007199254740991),UNIQUE(run_id,deduplication_key))",
    ),
    (
        "events",
        "CREATE TABLE events(position INTEGER PRIMARY KEY,event_id TEXT UNIQUE NOT NULL CHECK(length(event_id)=36),aggregate_id TEXT NOT NULL CHECK(length(aggregate_id)=36),aggregate_sequence INTEGER NOT NULL CHECK(aggregate_sequence BETWEEN 1 AND 9007199254740991),data BLOB NOT NULL CHECK(length(data)<=1048576),UNIQUE(aggregate_id,aggregate_sequence))",
    ),
    (
        "checkpoints",
        "CREATE TABLE checkpoints(position INTEGER PRIMARY KEY,checkpoint_id TEXT UNIQUE NOT NULL CHECK(length(checkpoint_id)=36),data BLOB NOT NULL CHECK(length(data)<=1048576))",
    ),
    (
        "projects",
        "CREATE TABLE projects(project_id TEXT PRIMARY KEY NOT NULL CHECK(length(project_id)=36),user_id TEXT NOT NULL CHECK(length(user_id)=36),scope_policy_id TEXT NOT NULL CHECK(length(scope_policy_id)=36),revision INTEGER NOT NULL CHECK(revision BETWEEN 0 AND 9007199254740991),data BLOB NOT NULL CHECK(length(data)<=1048576),FOREIGN KEY(scope_policy_id,project_id) REFERENCES scopes(scope_policy_id,project_id) DEFERRABLE INITIALLY DEFERRED)",
    ),
    (
        "scopes",
        "CREATE TABLE scopes(scope_policy_id TEXT PRIMARY KEY NOT NULL CHECK(length(scope_policy_id)=36),project_id TEXT NOT NULL REFERENCES projects(project_id) DEFERRABLE INITIALLY DEFERRED,revision INTEGER NOT NULL CHECK(revision BETWEEN 0 AND 9007199254740991),data BLOB NOT NULL CHECK(length(data)<=1048576),UNIQUE(scope_policy_id,project_id))",
    ),
    (
        "identities",
        "CREATE TABLE identities(identity_id TEXT PRIMARY KEY NOT NULL CHECK(length(identity_id)=36),project_id TEXT NOT NULL REFERENCES projects(project_id),data BLOB NOT NULL CHECK(length(data)<=1048576))",
    ),
    (
        "tools",
        "CREATE TABLE tools(tool_id TEXT PRIMARY KEY NOT NULL CHECK(length(tool_id) BETWEEN 1 AND 128),version TEXT NOT NULL CHECK(version='0.1.0'),provider_digest TEXT NOT NULL CHECK(length(provider_digest)=64),data BLOB NOT NULL CHECK(length(data)<=1048576))",
    ),
    (
        "grants",
        "CREATE TABLE grants(grant_id TEXT PRIMARY KEY NOT NULL CHECK(length(grant_id)=36),project_id TEXT NOT NULL REFERENCES projects(project_id),tool_id TEXT NOT NULL REFERENCES tools(tool_id),tool_version TEXT NOT NULL CHECK(tool_version='0.1.0'),provider_digest TEXT NOT NULL CHECK(length(provider_digest)=64),scope_revision INTEGER NOT NULL CHECK(scope_revision BETWEEN 0 AND 9007199254740991),identity_id TEXT NOT NULL REFERENCES identities(identity_id),input_sha256 TEXT NOT NULL CHECK(length(input_sha256)=64),revoked INTEGER NOT NULL CHECK(revoked IN (0,1)),data BLOB NOT NULL CHECK(length(data)<=1048576))",
    ),
    (
        "sessions",
        "CREATE TABLE sessions(session_id TEXT PRIMARY KEY NOT NULL CHECK(length(session_id)=36),project_id TEXT NOT NULL REFERENCES projects(project_id),investigation_id TEXT UNIQUE NOT NULL CHECK(length(investigation_id)=36),user_id TEXT NOT NULL CHECK(length(user_id)=36),control_revision INTEGER NOT NULL CHECK(control_revision BETWEEN 0 AND 9007199254740991),data BLOB NOT NULL CHECK(length(data)<=1048576))",
    ),
];
const INDEXES: [(&str, &str); 1] = [(
    "grants_binding",
    "CREATE INDEX grants_binding ON grants(project_id,tool_id,tool_version,provider_digest,scope_revision,identity_id,input_sha256,grant_id)",
)];

#[derive(Debug)]
pub struct LedgerSettings {
    pub journal_mode: String,
    pub synchronous: i64,
    pub fullfsync: bool,
    pub foreign_keys: bool,
    pub busy_timeout_ms: u64,
}

#[derive(Clone, Debug)]
pub struct StoredInvocation {
    pub invocation: Invocation,
    pub history: InvocationHistory,
    pub reserved_units: WireInt,
    pub requested: Usage,
    /// Original peer claim, retained for deduplication; never an authority revision.
    pub source_control_revision: WireInt,
}

#[derive(Debug)]
pub struct EventPage {
    pub events: Vec<Event>,
    pub last_position: WireInt,
}

/// Host-reviewed tool/provider binding. Replacing a provider requires a new run and review.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredTool {
    pub descriptor: ToolDescriptor,
    pub provider_digest: Digest,
}

/// Product state belongs to the host, never to a runtime/model conversation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredSession {
    pub project_id: EntityId,
    pub session: InvestigationSession,
}

pub struct Ledger {
    connection: Mutex<Connection>,
    run_id: EntityId,
    writable: bool,
    _lock: File,
}

pub struct LedgerTransaction<'a> {
    transaction: &'a Transaction<'a>,
    run_id: EntityId,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockMarker {
    schema_version: ContractVersion,
    run_id: EntityId,
}

impl Ledger {
    pub fn run_id(&self) -> EntityId {
        self.run_id
    }

    /// A host binding-scoped dedup key selects only from this ledger's owned run.
    pub fn invocation_for_dedup(&self, key: &str) -> ProofResult<Option<StoredInvocation>> {
        let connection = self.connection()?;
        invocation_for_dedup(&connection, self.run_id, key)
    }

    // Project/root-scope bootstrap is transaction-only because their ownership links are mutual.
    pub fn read_project(&self, id: EntityId) -> ProofResult<FixtureProject> {
        let connection = self.connection()?;
        read_project(&connection, id)
    }

    pub fn insert_scope(&self, scope: &ScopePolicy) -> ProofResult<()> {
        self.transaction(|tx| tx.insert_scope(scope))
    }

    pub fn read_scope(&self, id: EntityId) -> ProofResult<ScopePolicy> {
        let connection = self.connection()?;
        read_scope(&connection, id)
    }

    pub fn replace_scope(
        &self,
        scope: &ScopePolicy,
        expected_revision: WireInt,
    ) -> ProofResult<()> {
        self.transaction(|tx| tx.replace_scope(scope, expected_revision))
    }

    pub fn insert_identity(&self, identity: &IdentityProfile) -> ProofResult<()> {
        self.transaction(|tx| tx.insert_identity(identity))
    }

    pub fn read_identity(&self, id: EntityId) -> ProofResult<IdentityProfile> {
        let connection = self.connection()?;
        read_identity(&connection, id)
    }

    pub fn insert_tool(&self, tool: &RegisteredTool) -> ProofResult<()> {
        self.transaction(|tx| tx.insert_tool(tool))
    }

    pub fn read_tool(&self, id: &CatalogId) -> ProofResult<RegisteredTool> {
        let connection = self.connection()?;
        read_tool(&connection, id)
    }

    pub fn find_tool(&self, id: &CatalogId) -> ProofResult<Option<RegisteredTool>> {
        let connection = self.connection()?;
        find_tool(&connection, id)
    }

    pub fn insert_grant(&self, grant: &ApprovalGrant) -> ProofResult<()> {
        self.transaction(|tx| tx.insert_grant(grant))
    }

    pub fn read_grant(&self, id: EntityId) -> ProofResult<ApprovalGrant> {
        let connection = self.connection()?;
        read_grant(&connection, id)
    }

    pub fn revoke_grant(&self, id: EntityId) -> ProofResult<()> {
        self.transaction(|tx| tx.revoke_grant(id))
    }

    /// Complete bounded trusted inspection; admission should use the indexed binding lookup.
    pub fn grants(&self) -> ProofResult<Vec<ApprovalGrant>> {
        let connection = self.connection()?;
        grants(&connection)
    }

    /// Descriptive candidates only. The caller must check expiry, revocation and requested usage.
    pub fn matching_grants(&self, invocation: &Invocation) -> ProofResult<Vec<ApprovalGrant>> {
        let connection = self.connection()?;
        matching_grants(&connection, invocation)
    }

    pub fn insert_session(
        &self,
        session: &InvestigationSession,
        project_id: EntityId,
    ) -> ProofResult<()> {
        self.transaction(|tx| tx.insert_session(session, project_id))
    }

    pub fn read_session(&self, id: EntityId) -> ProofResult<RegisteredSession> {
        let connection = self.connection()?;
        read_session(&connection, id)
    }

    pub fn create(directory: &OwnedDirectory, profile: &LoadedProfile) -> ProofResult<Self> {
        Self::start(directory, profile, true)
    }

    pub fn open(directory: &OwnedDirectory, profile: &LoadedProfile) -> ProofResult<Self> {
        Self::start(directory, profile, false)
    }

    /// Inspect a quiescent existing ledger without repairing, creating, or updating it.
    /// A shared sidecar lease excludes the writer while allowing other inspectors.
    pub fn open_readonly(directory: &OwnedDirectory, profile: &LoadedProfile) -> ProofResult<Self> {
        let guard = directory.lock_directory()?;
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let mut database =
            File::from(fs::openat(&guard, DB_NAME, flags, Mode::empty()).map_err(storage_error)?);
        let database_stat = private_file(&database)?;
        if u64::try_from(database_stat.st_size).map_err(storage_error)? > MAX_DATABASE_BYTES {
            return Err(integrity());
        }
        let lock = open_lock(&guard, directory.run_id(), false, OFlags::RDONLY)?;
        check_header(&mut database)?;
        let path = canonical_database(directory.path(), &guard)?;
        for name in [
            "ledger.sqlite-journal",
            "ledger.sqlite-wal",
            "ledger.sqlite-shm",
        ] {
            match fs::openat(&guard, name, flags, Mode::empty()) {
                Ok(_) => return Err(integrity()),
                Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(storage_error(error)),
            }
        }
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage_error)?;
        connection
            .busy_timeout(Duration::from_millis(250))
            .map_err(storage_error)?;
        connection
            .execute_batch(
                "PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; PRAGMA foreign_keys=ON;",
            )
            .map_err(storage_error)?;
        validate_store(&connection, directory.run_id(), profile)?;
        same_named_file(&guard, DB_NAME, &database_stat)?;
        drop(guard);
        Ok(Self {
            connection: Mutex::new(connection),
            run_id: directory.run_id(),
            writable: false,
            _lock: lock,
        })
    }

    fn start(
        directory: &OwnedDirectory,
        profile: &LoadedProfile,
        create: bool,
    ) -> ProofResult<Self> {
        let guard = directory.lock_directory()?;
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        // EXCL means create never adopts an existing file, even a valid ledger.
        let mut database = File::from(
            fs::openat(
                &guard,
                DB_NAME,
                if create {
                    flags | OFlags::CREATE | OFlags::EXCL
                } else {
                    flags
                },
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(storage_error)?,
        );
        let database_stat = private_file(&database)?;
        if u64::try_from(database_stat.st_size).map_err(storage_error)? > MAX_DATABASE_BYTES {
            return Err(integrity());
        }
        let path = canonical_database(directory.path(), &guard)?;
        // SQLite side files must never follow an attacker-provided symlink or hardlink.
        for name in [
            "ledger.sqlite-journal",
            "ledger.sqlite-wal",
            "ledger.sqlite-shm",
        ] {
            match fs::openat(&guard, name, flags, Mode::empty()) {
                Ok(fd) => {
                    private_file(&File::from(fd))?;
                }
                Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(storage_error(error)),
            }
        }
        if !create {
            check_header(&mut database)?;
        }
        let lock = open_lock(&guard, directory.run_id(), create, OFlags::RDWR)?;
        same_named_file(&guard, DB_NAME, &database_stat)?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage_error)?;
        same_named_file(&guard, DB_NAME, &database_stat)?;
        connection
            .busy_timeout(Duration::from_millis(250))
            .map_err(storage_error)?;
        connection
            .execute_batch("PRAGMA trusted_schema=OFF;")
            .map_err(storage_error)?;
        if !create {
            // The owned writer lease permits SQLite's hot-journal rollback before
            // canonical validation; a read-only connection cannot recover a crash.
            validate_store(&connection, directory.run_id(), profile)?;
        }
        connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA foreign_keys=ON;")
            .map_err(storage_error)?;
        let page_size: i64 = connection
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .map_err(storage_error)?;
        let page_size = u64::try_from(page_size).map_err(storage_error)?;
        if page_size == 0 {
            return Err(integrity());
        }
        let page_limit = i64::try_from(MAX_DATABASE_BYTES / page_size).map_err(storage_error)?;
        let actual_page_limit: i64 = connection
            .pragma_update_and_check(None, "max_page_count", page_limit, |row| row.get(0))
            .map_err(storage_error)?;
        if actual_page_limit != page_limit {
            return Err(integrity());
        }
        if create {
            let transaction = connection.unchecked_transaction().map_err(storage_error)?;
            let setup = (|| {
                transaction
                    .execute_batch(&format!(
                        "PRAGMA application_id={APP_ID}; PRAGMA user_version={SCHEMA_VERSION};"
                    ))
                    .map_err(storage_error)?;
                for (_, sql) in TABLES.iter().chain(INDEXES.iter()) {
                    transaction.execute_batch(sql).map_err(storage_error)?;
                }
                transaction
                    .execute(
                        "INSERT INTO ledger_meta VALUES(1,'0.1.0',?1,?2)",
                        params![directory.run_id().to_string(), profile.sha256().to_string()],
                    )
                    .map_err(storage_error)?;
                Ok(())
            })();
            finish_transaction(transaction, setup)?;
            database.sync_all().map_err(storage_error)?;
            guard.sync_all().map_err(storage_error)?;
        }
        if create {
            validate_store(&connection, directory.run_id(), profile)?;
        }
        let settings = read_settings(&connection)?;
        if settings.journal_mode != "delete"
            || settings.synchronous != 2
            || !settings.fullfsync
            || !settings.foreign_keys
            || settings.busy_timeout_ms != 250
        {
            return Err(integrity());
        }
        // Drop the directory flock before returning; workspace I/O uses the same short lock.
        drop(guard);
        Ok(Self {
            connection: Mutex::new(connection),
            run_id: directory.run_id(),
            writable: true,
            _lock: lock,
        })
    }

    fn connection(&self) -> ProofResult<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| integrity())
    }

    pub fn settings(&self) -> ProofResult<LedgerSettings> {
        let connection = self.connection()?;
        read_settings(&connection)
    }

    /// Compiled trusted fault orchestration only; never a peer or repository-config hook.
    /// SQLite invokes this before a writing commit; true requests actual rollback.
    pub(crate) fn install_fixture_commit_hook<F>(&self, hook: F) -> ProofResult<()>
    where
        F: FnMut() -> bool + Send + 'static,
    {
        if !self.writable {
            return Err(denied());
        }
        self.connection()?
            .commit_hook(Some(hook))
            .map_err(storage_error)
    }

    /// Bound only this owned fixture database, never the host filesystem.
    pub(crate) fn fixture_limit_pages(&self) -> ProofResult<u64> {
        if !self.writable {
            return Err(denied());
        }
        let connection = self.connection()?;
        let pages: u32 = connection
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .map_err(storage_error)?;
        connection
            .pragma_update(None, "max_page_count", pages)
            .map_err(storage_error)?;
        let effective: u32 = connection
            .pragma_query_value(None, "max_page_count", |row| row.get(0))
            .map_err(storage_error)?;
        if pages == 0 || effective != pages {
            return Err(integrity());
        }
        Ok(u64::from(effective))
    }

    pub fn transaction<T>(
        &self,
        operation: impl FnOnce(&mut LedgerTransaction<'_>) -> ProofResult<T>,
    ) -> ProofResult<T> {
        if !self.writable {
            return Err(denied());
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let outcome = operation(&mut LedgerTransaction {
            transaction: &transaction,
            run_id: self.run_id,
        });
        finish_transaction(transaction, outcome)
    }

    pub fn insert_budget(&self, budget: &Budget) -> ProofResult<()> {
        if budget.parent_budget_id.is_some() {
            return Err(denied());
        }
        budget.validate()?;
        if budget.consumed != WireInt::ZERO
            || budget.reserved != WireInt::ZERO
            || budget.revision != WireInt::ZERO
        {
            return Err(denied());
        }
        self.transaction(|tx| insert_budget(tx.transaction, budget))
    }

    pub fn read_budget(&self, id: EntityId) -> ProofResult<Budget> {
        let connection = self.connection()?;
        read_budget(&connection, id)
    }

    /// Complete inspection includes unused child escrows, not only invocation-referenced budgets.
    pub fn budgets(&self) -> ProofResult<Vec<Budget>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare_cached(
            "SELECT budget_id,parent_budget_id,quota_limit,consumed,reserved,revision FROM budgets ORDER BY budget_id LIMIT ?1")
            .map_err(storage_error)?;
        let mut rows = statement.query([MAX_BUDGETS + 1]).map_err(storage_error)?;
        let Some(first) = rows.next().map_err(storage_error)? else {
            return Ok(Vec::new());
        };
        let mut budgets = Vec::with_capacity(MAX_BUDGETS as usize);
        budgets.push(budget_row(first)?);
        while let Some(row) = rows.next().map_err(storage_error)? {
            if budgets.len() == MAX_BUDGETS as usize {
                return Err(integrity());
            }
            budgets.push(budget_row(row)?);
        }
        Ok(budgets)
    }

    pub fn insert_control(
        &self,
        state: &ControlState,
        project_id: EntityId,
        scope_revision: WireInt,
    ) -> ProofResult<()> {
        state.validate()?;
        if state.revision != WireInt::ZERO
            || state.mode != ControlMode::Running
            || !state.admission_open
        {
            return Err(denied());
        }
        let bytes = encode(state)?;
        self.transaction(|tx| {
            validate_control_catalog(tx.transaction, state, project_id, scope_revision)?;
            ensure_capacity(tx.transaction, "controls", MAX_CONTROLS)?;
            tx.transaction
                .execute(
                    "INSERT INTO controls VALUES(?1,?2,?3,?4,?5)",
                    params![
                        state.investigation_id.to_string(),
                        signed(state.revision)?,
                        project_id.to_string(),
                        signed(scope_revision)?,
                        bytes
                    ],
                )
                .map_err(storage_error)?;
            Ok(())
        })
    }

    pub fn read_control(&self, id: EntityId) -> ProofResult<ControlState> {
        let connection = self.connection()?;
        read_control(&connection, id)
    }

    pub fn controls(&self) -> ProofResult<Vec<ControlState>> {
        let connection = self.connection()?;
        controls(&connection)
    }

    pub fn read_invocation(&self, id: EntityId) -> ProofResult<StoredInvocation> {
        let connection = self.connection()?;
        read_invocation(&connection, id, self.run_id)
    }

    /// Complete canonical run history, bounded to 4096 records; never silently truncated.
    pub fn invocations(&self) -> ProofResult<Vec<StoredInvocation>> {
        let connection = self.connection()?;
        invocations(&connection, self.run_id, None)
    }

    pub fn latest_checkpoint(&self) -> ProofResult<Option<Checkpoint>> {
        let connection = self.connection()?;
        let bytes: Option<Vec<u8>> = connection.query_row(
            "SELECT CASE WHEN length(data)<=1048576 THEN data END FROM checkpoints ORDER BY position DESC LIMIT 1",
            [], |row| row.get(0)).optional().map_err(storage_error)?;
        bytes
            .map(|bytes| {
                let checkpoint: Checkpoint = decode(&bytes)?;
                if checkpoint.run_id != self.run_id {
                    return Err(integrity());
                }
                Ok(checkpoint)
            })
            .transpose()
    }

    pub fn outbox(&self, max_items: usize) -> ProofResult<Vec<Event>> {
        if !(1..=256).contains(&max_items) {
            return Err(invalid());
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT CASE WHEN length(data)<=1048576 THEN data END,event_id,aggregate_id,aggregate_sequence FROM events ORDER BY position LIMIT ?1")
            .map_err(storage_error)?;
        let mut rows = statement
            .query([i64::try_from(max_items).map_err(|_| invalid())?])
            .map_err(storage_error)?;
        let mut events = Vec::new();
        while let Some(row) = rows.next().map_err(storage_error)? {
            events.push(event_row(row)?);
        }
        Ok(events)
    }

    /// Historical export is paged independently of the bounded delivery queue.
    /// The cursor is ledger-local position data, never an authority reference.
    pub fn event_page(&self, after_position: WireInt, max_items: usize) -> ProofResult<EventPage> {
        if !(1..=256).contains(&max_items) {
            return Err(invalid());
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare_cached(
            "SELECT CASE WHEN length(data)<=1048576 THEN data END,event_id,aggregate_id,aggregate_sequence,position FROM events WHERE position>?1 ORDER BY position LIMIT ?2")
            .map_err(storage_error)?;
        let mut rows = statement
            .query(params![signed(after_position)?, max_items as i64])
            .map_err(storage_error)?;
        let mut next = rows.next().map_err(storage_error)?;
        if next.is_none() {
            return Ok(EventPage {
                events: Vec::new(),
                last_position: after_position,
            });
        }
        let mut events = Vec::with_capacity(max_items);
        let mut last_position = after_position;
        while let Some(row) = next {
            let position = wire(row.get(4).map_err(storage_error)?)?;
            if position <= last_position {
                return Err(integrity());
            }
            events.push(event_row(row)?);
            last_position = position;
            next = rows.next().map_err(storage_error)?;
        }
        Ok(EventPage {
            events,
            last_position,
        })
    }
}

impl LedgerTransaction<'_> {
    pub fn invocation_for_dedup(&self, key: &str) -> ProofResult<Option<StoredInvocation>> {
        invocation_for_dedup(self.transaction, self.run_id, key)
    }

    pub fn insert_project(&mut self, project: &FixtureProject) -> ProofResult<()> {
        self.ensure_active()?;
        let bytes = encode(project)?;
        ensure_capacity(self.transaction, "projects", MAX_PROJECTS)?;
        self.transaction
            .execute(
                "INSERT INTO projects VALUES(?1,?2,?3,?4,?5)",
                params![
                    project.project_id.to_string(),
                    project.user_id.to_string(),
                    project.scope_policy_id.to_string(),
                    signed(project.revision)?,
                    bytes
                ],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    pub fn read_project(&self, id: EntityId) -> ProofResult<FixtureProject> {
        read_project(self.transaction, id)
    }

    pub fn insert_scope(&mut self, scope: &ScopePolicy) -> ProofResult<()> {
        self.ensure_active()?;
        let bytes = encode(scope)?;
        let project = self.read_project(scope.project_id)?;
        if project.scope_policy_id == scope.scope_policy_id {
            require_control_scope(self.transaction, scope.project_id, scope.revision)?;
        }
        ensure_capacity(self.transaction, "scopes", MAX_SCOPES)?;
        self.transaction
            .execute(
                "INSERT INTO scopes VALUES(?1,?2,?3,?4)",
                params![
                    scope.scope_policy_id.to_string(),
                    scope.project_id.to_string(),
                    signed(scope.revision)?,
                    bytes
                ],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    pub fn read_scope(&self, id: EntityId) -> ProofResult<ScopePolicy> {
        read_scope(self.transaction, id)
    }

    pub fn replace_scope(
        &mut self,
        scope: &ScopePolicy,
        expected_revision: WireInt,
    ) -> ProofResult<()> {
        self.atomic(|tx| {
            let bytes = encode(scope)?;
            let previous = tx.read_scope(scope.scope_policy_id)?;
            require_revision(previous.revision, expected_revision)?;
            if previous.project_id != scope.project_id { return Err(denied()); }
            if scope.revision != expected_revision.checked_add(one())? { return Err(stale()); }
            let project = tx.read_project(scope.project_id)?;
            let changed = tx.transaction.execute(
                "UPDATE scopes SET revision=?1,data=?2 WHERE scope_policy_id=?3 AND revision=?4",
                params![signed(scope.revision)?, bytes, scope.scope_policy_id.to_string(), signed(expected_revision)?])
                .map_err(storage_error)?;
            if changed != 1 { return Err(stale()); }
            if project.scope_policy_id == scope.scope_policy_id {
                require_control_scope(tx.transaction, scope.project_id, expected_revision)?;
                tx.transaction.execute("UPDATE controls SET scope_revision=?1 WHERE project_id=?2",
                    params![signed(scope.revision)?, scope.project_id.to_string()]).map_err(storage_error)?;
            }
            Ok(())
        })
    }

    pub fn insert_identity(&mut self, identity: &IdentityProfile) -> ProofResult<()> {
        self.ensure_active()?;
        let bytes = encode(identity)?;
        self.read_project(identity.project_id)?;
        ensure_capacity(self.transaction, "identities", MAX_IDENTITIES)?;
        self.transaction
            .execute(
                "INSERT INTO identities VALUES(?1,?2,?3)",
                params![
                    identity.identity_id.to_string(),
                    identity.project_id.to_string(),
                    bytes
                ],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    pub fn read_identity(&self, id: EntityId) -> ProofResult<IdentityProfile> {
        read_identity(self.transaction, id)
    }

    pub fn insert_tool(&mut self, tool: &RegisteredTool) -> ProofResult<()> {
        self.ensure_active()?;
        let bytes = encode(tool)?;
        ensure_capacity(self.transaction, "tools", MAX_TOOLS)?;
        self.transaction
            .execute(
                "INSERT INTO tools VALUES(?1,?2,?3,?4)",
                params![
                    tool.descriptor.tool_id.to_string(),
                    tool.descriptor.version.to_string(),
                    tool.provider_digest.to_string(),
                    bytes
                ],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    pub fn read_tool(&self, id: &CatalogId) -> ProofResult<RegisteredTool> {
        read_tool(self.transaction, id)
    }

    pub fn find_tool(&self, id: &CatalogId) -> ProofResult<Option<RegisteredTool>> {
        find_tool(self.transaction, id)
    }

    pub fn insert_grant(&mut self, grant: &ApprovalGrant) -> ProofResult<()> {
        self.ensure_active()?;
        let bytes = encode(grant)?;
        validate_grant_links(self.transaction, grant)?;
        ensure_capacity(self.transaction, "grants", MAX_GRANTS)?;
        self.transaction
            .execute(
                "INSERT INTO grants VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    grant.grant_id.to_string(),
                    grant.project_id.to_string(),
                    grant.tool_id.to_string(),
                    grant.tool_version.to_string(),
                    grant.provider_digest.to_string(),
                    signed(grant.scope_revision)?,
                    grant.identity_id.to_string(),
                    grant.bounded_input_sha256.to_string(),
                    i64::from(grant.revoked),
                    bytes
                ],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    pub fn read_grant(&self, id: EntityId) -> ProofResult<ApprovalGrant> {
        read_grant(self.transaction, id)
    }

    pub fn grants(&self) -> ProofResult<Vec<ApprovalGrant>> {
        grants(self.transaction)
    }

    pub fn matching_grants(&self, invocation: &Invocation) -> ProofResult<Vec<ApprovalGrant>> {
        matching_grants(self.transaction, invocation)
    }

    pub fn revoke_grant(&mut self, id: EntityId) -> ProofResult<()> {
        self.ensure_active()?;
        let mut grant = self.read_grant(id)?;
        if grant.revoked {
            return Ok(());
        }
        grant.revoked = true;
        let changed = self
            .transaction
            .execute(
                "UPDATE grants SET revoked=1,data=?1 WHERE grant_id=?2 AND revoked=0",
                params![encode(&grant)?, id.to_string()],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(integrity());
        }
        Ok(())
    }

    pub fn insert_session(
        &mut self,
        session: &InvestigationSession,
        project_id: EntityId,
    ) -> ProofResult<()> {
        self.ensure_active()?;
        session.validate()?;
        let bytes = bounded_json(&SessionRecord {
            project_id,
            session,
        })?;
        validate_session_links(self.transaction, project_id, session)?;
        ensure_capacity(self.transaction, "sessions", MAX_SESSIONS)?;
        self.transaction
            .execute(
                "INSERT INTO sessions VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    session.session_id.to_string(),
                    project_id.to_string(),
                    session.investigation_id.to_string(),
                    session.user_id.to_string(),
                    signed(session.control_revision)?,
                    bytes
                ],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    pub fn read_session(&self, id: EntityId) -> ProofResult<RegisteredSession> {
        read_session(self.transaction, id)
    }

    fn ensure_active(&self) -> ProofResult<()> {
        if self.transaction.is_autocommit() {
            return Err(integrity());
        }
        Ok(())
    }

    /// Each multi-write operation is a savepoint, including when a caller handles its error.
    fn atomic<T>(&mut self, operation: impl FnOnce(&mut Self) -> ProofResult<T>) -> ProofResult<T> {
        self.ensure_active()?;
        self.transaction
            .execute_batch("SAVEPOINT ledger_operation")
            .map_err(storage_error)?;
        match operation(self) {
            Ok(value) => {
                self.transaction
                    .execute_batch("RELEASE ledger_operation")
                    .map_err(storage_error)?;
                Ok(value)
            }
            Err(error) => {
                // SQLite can discard the whole transaction and every savepoint on FULL/IOERR.
                if !self.transaction.is_autocommit() {
                    self.transaction
                        .execute_batch("ROLLBACK TO ledger_operation; RELEASE ledger_operation;")
                        .map_err(storage_error)?;
                }
                Err(error)
            }
        }
    }

    pub fn read_budget(&self, id: EntityId) -> ProofResult<Budget> {
        read_budget(self.transaction, id)
    }

    pub fn reserve_budget(
        &mut self,
        id: EntityId,
        amount: WireInt,
        expected_revision: WireInt,
    ) -> ProofResult<()> {
        self.atomic(|tx| {
            let mut lineage = budget_lineage(tx.transaction, id)?;
            let budget = lineage.first_mut().ok_or_else(integrity)?;
            require_revision(budget.revision, expected_revision)?;
            budget.reserve(amount, expected_revision)?;
            // Its parent already escrows the entire child limit. Do not debit it again.
            write_budget(tx.transaction, budget, expected_revision)
        })
    }

    pub fn allocate_child(
        &mut self,
        parent_id: EntityId,
        child_id: EntityId,
        limit: WireInt,
        parent_expected_revision: WireInt,
    ) -> ProofResult<Budget> {
        self.atomic(|tx| {
            let mut lineage = budget_lineage(tx.transaction, parent_id)?;
            if lineage.len() >= MAX_DEPTH
                || lineage.iter().any(|budget| budget.budget_id == child_id)
            {
                return Err(invalid());
            }
            let parent = lineage.first_mut().ok_or_else(integrity)?;
            require_revision(parent.revision, parent_expected_revision)?;
            let child = parent.allocate_child(child_id, limit, parent_expected_revision)?;
            insert_budget(tx.transaction, &child)?;
            write_budget(tx.transaction, parent, parent_expected_revision)?;
            Ok(child)
        })
    }

    pub fn settle_budget(
        &mut self,
        id: EntityId,
        reserved_amount: WireInt,
        actual_consumed: WireInt,
        expected_revision: WireInt,
    ) -> ProofResult<()> {
        self.atomic(|tx| {
            tx.settle_budget_inner(id, reserved_amount, actual_consumed, expected_revision)
        })
    }

    fn settle_budget_inner(
        &mut self,
        id: EntityId,
        reserved_amount: WireInt,
        actual_consumed: WireInt,
        expected_revision: WireInt,
    ) -> ProofResult<()> {
        let mut lineage = budget_lineage(self.transaction, id)?;
        require_revision(lineage[0].revision, expected_revision)?;
        let revisions: Vec<WireInt> = lineage.iter().map(|budget| budget.revision).collect();
        let own_reservation = lineage[0]
            .reserved
            .checked_sub(child_backing(self.transaction, id)?)
            .map_err(storage_error)?;
        if reserved_amount > own_reservation {
            return Err(integrity());
        }
        lineage[0].settle(reserved_amount, actual_consumed, expected_revision)?;
        // Only actual usage consumes ancestor escrow. Unused child allocation stays backed.
        // Cancellation (zero usage) therefore does not release or revise its ancestors.
        if actual_consumed != WireInt::ZERO {
            for budget in lineage.iter_mut().skip(1) {
                budget.consume(actual_consumed, budget.revision)?;
            }
        }
        for (budget, revision) in lineage.iter().zip(revisions) {
            if budget.revision != revision {
                write_budget(self.transaction, budget, revision)?;
            }
        }
        Ok(())
    }

    pub fn append_event(&mut self, event: &Event) -> ProofResult<()> {
        self.ensure_active()?;
        let bytes = encode(event)?;
        if event.published
            || event.aggregate_sequence
                != next_event_sequence(self.transaction, event.aggregate_id)?
        {
            return Err(integrity());
        }
        ensure_capacity(self.transaction, "events", MAX_EVENTS)?;
        self.transaction.execute("INSERT INTO events(event_id,aggregate_id,aggregate_sequence,data) VALUES(?1,?2,?3,?4)",
            params![event.event_id.to_string(), event.aggregate_id.to_string(), signed(event.aggregate_sequence)?, bytes])
            .map_err(storage_error)?;
        Ok(())
    }

    pub fn write_checkpoint(&mut self, checkpoint: &Checkpoint) -> ProofResult<()> {
        self.ensure_active()?;
        if checkpoint.run_id != self.run_id {
            return Err(denied());
        }
        let bytes = encode(checkpoint)?;
        for (aggregate, sequence) in &checkpoint.event_cursors {
            let next = next_event_sequence(self.transaction, *aggregate)?;
            if sequence.checked_add(one())? != next {
                return Err(integrity());
            }
        }
        ensure_capacity(self.transaction, "checkpoints", MAX_CHECKPOINTS)?;
        self.transaction
            .execute(
                "INSERT INTO checkpoints(checkpoint_id,data) VALUES(?1,?2)",
                params![checkpoint.checkpoint_id.to_string(), bytes],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    pub fn read_control(&self, id: EntityId) -> ProofResult<ControlState> {
        read_control(self.transaction, id)
    }

    pub fn apply_control(
        &mut self,
        state: &ControlState,
        expected_revision: WireInt,
    ) -> ProofResult<()> {
        self.atomic(|tx| tx.apply_control_inner(state, expected_revision))
    }

    fn apply_control_inner(
        &mut self,
        state: &ControlState,
        expected_revision: WireInt,
    ) -> ProofResult<()> {
        state.validate()?;
        let previous = self.read_control(state.investigation_id)?;
        require_revision(previous.revision, expected_revision)?;
        if state.revision != expected_revision.checked_add(one())? {
            return Err(stale());
        }
        let legal = match (previous.mode, state.mode) {
            (ControlMode::Cancelled, _) => false,
            (ControlMode::Running, ControlMode::Paused | ControlMode::Cancelled) => {
                !state.admission_open
            }
            (ControlMode::Paused, ControlMode::Running) => state.admission_open,
            (ControlMode::Paused, ControlMode::Cancelled) => !state.admission_open,
            _ => false,
        };
        if !legal || state.instruction_ref != previous.instruction_ref {
            return Err(denied());
        }
        let (project, scope) = control_context(self.transaction, state.investigation_id)?;
        let pending = invocations(self.transaction, self.run_id, Some(state.investigation_id))?;
        let now = AuditTime::now();
        let cause = EntityId::new();
        let mut budget_refs = BTreeSet::new();
        let mut invocation_refs = Vec::new();
        let mut cursors = BTreeMap::new();
        for mut stored in pending {
            if stored.invocation.state != InvocationState::Reserved
                || stored.invocation.control_revision >= state.revision
            {
                continue;
            }
            if stored.invocation.project_id != project {
                return Err(integrity());
            }
            let budget_id = stored.invocation.budget_id;
            let budget = self.read_budget(budget_id)?;
            self.settle_budget_inner(
                budget_id,
                stored.reserved_units,
                WireInt::ZERO,
                budget.revision,
            )?;
            stored.invocation.state = InvocationState::Cancelled;
            stored.invocation.error = Some(ProofError::new(
                ErrorCode::Cancelled,
                "Invocation invalidated by the control barrier",
            ));
            stored.history.record(&stored.invocation, None, now)?;
            stored.reserved_units = WireInt::ZERO;
            self.update_invocation_inner(&stored, InvocationState::Reserved)?;
            let event = self.control_event(
                project,
                stored.invocation.invocation_id,
                "invocation.cancelled",
                stored.invocation.control_revision,
                cause,
                now,
            )?;
            self.append_event(&event)?;
            budget_refs.insert(budget_id);
            invocation_refs.push(stored.invocation.invocation_id);
        }
        let changed = self
            .transaction
            .execute(
                "UPDATE controls SET revision=?1,data=?2 WHERE investigation_id=?3 AND revision=?4",
                params![
                    signed(state.revision)?,
                    encode(state)?,
                    state.investigation_id.to_string(),
                    signed(expected_revision)?
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(stale());
        }
        advance_session_control(self.transaction, state, expected_revision)?;
        let event = self.control_event(
            project,
            state.investigation_id,
            match state.mode {
                ControlMode::Running => "control.resumed",
                ControlMode::Paused => "control.paused",
                ControlMode::Cancelled => "control.cancelled",
            },
            state.revision,
            cause,
            now,
        )?;
        // The checkpoint cursor belongs to this control aggregate. Affected invocation
        // identities are recorded separately; their outbox entries remain independently ordered.
        cursors.insert(event.aggregate_id, event.aggregate_sequence);
        self.append_event(&event)?;
        self.write_checkpoint(&Checkpoint {
            checkpoint_id: EntityId::new(),
            run_id: self.run_id,
            schema_version: ContractVersion::V0_1_0,
            control_revision: state.revision,
            scope_revision: scope,
            budget_refs: budget_refs.into_iter().collect(),
            invocation_refs,
            lease_refs: Vec::new(),
            event_cursors: cursors,
            created_at: now,
        })
    }

    fn control_event(
        &self,
        project_id: EntityId,
        aggregate_id: EntityId,
        kind: &str,
        revision: WireInt,
        cause: EntityId,
        at: AuditTime,
    ) -> ProofResult<Event> {
        Ok(Event {
            event_id: EntityId::new(),
            schema_version: ContractVersion::V0_1_0,
            project_id,
            aggregate_id,
            aggregate_sequence: next_event_sequence(self.transaction, aggregate_id)?,
            event_type: CatalogId::parse(kind)?,
            timestamp: at,
            correlation_id: cause,
            causation_id: cause,
            control_revision: Some(revision),
            data_refs: vec![aggregate_id],
            published: false,
        })
    }

    pub fn read_invocation(&self, id: EntityId) -> ProofResult<StoredInvocation> {
        read_invocation(self.transaction, id, self.run_id)
    }

    pub fn insert_invocation(&mut self, stored: &StoredInvocation) -> ProofResult<()> {
        self.atomic(|tx| {
            let (data, history) = validate_invocation(stored, tx.run_id)?;
            validate_invocation_context(tx.transaction, stored, true)?;
            ensure_pending_capacity(tx.transaction, stored)?;
            ensure_capacity(tx.transaction, "invocations", MAX_INVOCATIONS)?;
            let invocation = &stored.invocation;
            tx.transaction
                .execute(
                    "INSERT INTO invocations VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                    params![
                        invocation.invocation_id.to_string(),
                        invocation.run_id.to_string(),
                        invocation.deduplication_key,
                        invocation.investigation_id.to_string(),
                        invocation.budget_id.to_string(),
                        state_name(invocation.state),
                        signed(invocation.control_revision)?,
                        signed(stored.reserved_units)?,
                        data,
                        history,
                        encode(&stored.requested)?,
                        signed(stored.source_control_revision)?
                    ],
                )
                .map_err(storage_error)?;
            Ok(())
        })
    }

    pub fn update_invocation(
        &mut self,
        stored: &StoredInvocation,
        expected_state: InvocationState,
    ) -> ProofResult<()> {
        self.atomic(|tx| tx.update_invocation_inner(stored, expected_state))
    }

    fn update_invocation_inner(
        &mut self,
        stored: &StoredInvocation,
        expected_state: InvocationState,
    ) -> ProofResult<()> {
        let (data, history) = validate_invocation(stored, self.run_id)?;
        let previous = self.read_invocation(stored.invocation.invocation_id)?;
        if previous.invocation.state != expected_state {
            return Err(stale());
        }
        if previous.requested != stored.requested
            || previous.source_control_revision != stored.source_control_revision
        {
            return Err(denied());
        }
        require_history_extension(&previous.history, &stored.history)?;
        validate_invocation_context(self.transaction, stored, true)?;
        ensure_pending_capacity(self.transaction, stored)?;
        let changed = self.transaction.execute("UPDATE invocations SET state=?1,reserved_units=?2,data=?3,history=?4 WHERE invocation_id=?5 AND state=?6",
            params![state_name(stored.invocation.state), signed(stored.reserved_units)?, data, history,
                stored.invocation.invocation_id.to_string(), state_name(expected_state)]).map_err(storage_error)?;
        if changed != 1 {
            return Err(stale());
        }
        Ok(())
    }
}

fn finish_transaction<T>(transaction: Transaction<'_>, result: ProofResult<T>) -> ProofResult<T> {
    match result {
        Ok(value) => {
            // FULL/IOERR/commit-hook failures can already roll back; preserve their native cause.
            if let Err(error) = transaction.execute_batch("COMMIT") {
                if !transaction.is_autocommit() {
                    transaction.rollback().map_err(storage_error)?;
                }
                return Err(storage_error(error));
            }
            // rusqlite observes autocommit and does not issue another COMMIT on drop.
            Ok(value)
        }
        Err(error) => {
            if !transaction.is_autocommit() {
                transaction.rollback().map_err(storage_error)?;
            }
            Err(error)
        }
    }
}

fn one() -> WireInt {
    WireInt::new(1).expect("one is a valid wire integer")
}
fn signed(value: WireInt) -> ProofResult<i64> {
    i64::try_from(value.get()).map_err(|_| integrity())
}
fn wire(value: i64) -> ProofResult<WireInt> {
    WireInt::new(u64::try_from(value).map_err(|_| integrity())?).map_err(|_| integrity())
}
fn require_revision(actual: WireInt, expected: WireInt) -> ProofResult<()> {
    if actual != expected {
        return Err(stale());
    }
    Ok(())
}
fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Ledger ownership, schema, or state integrity is invalid",
    )
}
fn storage_error<E: 'static>(error: E) -> ProofError {
    let mapped = integrity();
    if let Some(rusqlite::Error::SqliteFailure(native, _)) =
        (&error as &dyn std::any::Any).downcast_ref::<rusqlite::Error>()
    {
        mapped.with_storage_fault(native.extended_code)
    } else {
        mapped
    }
}
fn denied() -> ProofError {
    ProofError::new(
        ErrorCode::PermissionDenied,
        "Ledger operation does not match trusted host authority",
    )
}
fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Ledger request exceeds its bounded contract",
    )
}
fn stale() -> ProofError {
    ProofError::new(
        ErrorCode::StaleSnapshot,
        "Ledger state revision or invocation state is stale",
    )
}
fn exhausted() -> ProofError {
    ProofError::new(
        ErrorCode::BudgetExhausted,
        "Ledger bounded storage capacity is exhausted",
    )
}

struct BoundedRecord(Vec<u8>);

impl Write for BoundedRecord {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_RECORD_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("Ledger record exceeds its bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bounded_json<T: Serialize>(record: &T) -> ProofResult<Vec<u8>> {
    let mut buffer = BoundedRecord(Vec::new());
    serde_json::to_writer(&mut buffer, record).map_err(storage_error)?;
    Ok(buffer.0)
}

fn encode<T: Serialize + DeserializeOwned>(record: &T) -> ProofResult<Vec<u8>> {
    let bytes = bounded_json(record)?;
    // Public host structs still pass the exact bounded wire validators before persistence.
    let _: T = serde_json::from_slice(&bytes).map_err(storage_error)?;
    Ok(bytes)
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> ProofResult<T> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(integrity());
    }
    serde_json::from_slice(bytes).map_err(storage_error)
}

fn private_file(file: &File) -> ProofResult<Stat> {
    let stat = fs::fstat(file).map_err(storage_error)?;
    if stat.st_uid != rustix::process::geteuid().as_raw()
        || u32::from(stat.st_mode) & 0o7777 != 0o600
        || stat.st_nlink != 1
        || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
    {
        return Err(integrity());
    }
    Ok(stat)
}
fn same_named_file(directory: &File, name: &str, expected: &Stat) -> ProofResult<()> {
    let file = File::from(
        fs::openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(storage_error)?,
    );
    let actual = private_file(&file)?;
    if actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino {
        return Err(integrity());
    }
    Ok(())
}
fn canonical_database(path: &Path, directory: &File) -> ProofResult<PathBuf> {
    let canonical = path.canonicalize().map_err(storage_error)?;
    let named = fs::open(
        &canonical,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(storage_error)?;
    let expected = fs::fstat(directory).map_err(storage_error)?;
    let actual = fs::fstat(named).map_err(storage_error)?;
    if actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino {
        return Err(integrity());
    }
    Ok(canonical.join(DB_NAME))
}
fn check_header(file: &mut File) -> ProofResult<()> {
    let mut header = [0; 100];
    file.read_exact(&mut header).map_err(storage_error)?;
    if !header.starts_with(b"SQLite format 3\0")
        || header[18] != 1
        || header[19] != 1
        || u32::from_be_bytes(header[68..72].try_into().map_err(storage_error)?) != APP_ID
        || u32::from_be_bytes(header[60..64].try_into().map_err(storage_error)?) != SCHEMA_VERSION
    {
        return Err(integrity());
    }
    Ok(())
}
fn open_lock(
    directory: &File,
    run_id: EntityId,
    create: bool,
    access: OFlags,
) -> ProofResult<File> {
    let flags = access | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let mut file = File::from(
        fs::openat(
            directory,
            LOCK_NAME,
            if create {
                flags | OFlags::CREATE | OFlags::EXCL
            } else {
                flags
            },
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(storage_error)?,
    );
    private_file(&file)?;
    fs::flock(
        &file,
        if access == OFlags::RDONLY {
            FlockOperation::NonBlockingLockShared
        } else {
            FlockOperation::NonBlockingLockExclusive
        },
    )
    .map_err(storage_error)?;
    if create {
        let bytes = serde_json::to_vec(&LockMarker {
            schema_version: ContractVersion::V0_1_0,
            run_id,
        })
        .map_err(storage_error)?;
        file.write_all(&bytes).map_err(storage_error)?;
        file.sync_all().map_err(storage_error)?;
        directory.sync_all().map_err(storage_error)?;
    } else {
        let mut bytes = Vec::new();
        (&mut file)
            .take(257)
            .read_to_end(&mut bytes)
            .map_err(storage_error)?;
        if bytes.len() > 256 {
            return Err(integrity());
        }
        let marker: LockMarker = decode(&bytes)?;
        if marker.run_id != run_id {
            return Err(integrity());
        }
    }
    Ok(file)
}

fn read_settings(connection: &Connection) -> ProofResult<LedgerSettings> {
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(storage_error)?;
    let synchronous = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(storage_error)?;
    let fullfsync: i64 = connection
        .query_row("PRAGMA fullfsync", [], |row| row.get(0))
        .map_err(storage_error)?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(storage_error)?;
    let timeout: i64 = connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .map_err(storage_error)?;
    Ok(LedgerSettings {
        journal_mode,
        synchronous,
        fullfsync: fullfsync == 1,
        foreign_keys: foreign_keys == 1,
        busy_timeout_ms: u64::try_from(timeout).map_err(|_| integrity())?,
    })
}
fn ensure_capacity(connection: &Connection, table: &str, max: i64) -> ProofResult<()> {
    // table is always an internal fixed schema name, never user input.
    let count: i64 = connection
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .map_err(storage_error)?;
    if count < 0 || count >= max {
        return Err(exhausted());
    }
    Ok(())
}

fn insert_budget(connection: &Connection, budget: &Budget) -> ProofResult<()> {
    budget.validate()?;
    ensure_capacity(connection, "budgets", MAX_BUDGETS)?;
    connection
        .execute(
            "INSERT INTO budgets VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                budget.budget_id.to_string(),
                budget.parent_budget_id.map(|id| id.to_string()),
                signed(budget.limit)?,
                signed(budget.consumed)?,
                signed(budget.reserved)?,
                signed(budget.revision)?
            ],
        )
        .map_err(storage_error)?;
    Ok(())
}
fn read_budget(connection: &Connection, id: EntityId) -> ProofResult<Budget> {
    let mut statement = connection.prepare_cached(
        "SELECT budget_id,parent_budget_id,quota_limit,consumed,reserved,revision FROM budgets WHERE budget_id=?1")
        .map_err(storage_error)?;
    let mut rows = statement.query([id.to_string()]).map_err(storage_error)?;
    budget_row(rows.next().map_err(storage_error)?.ok_or_else(integrity)?)
}
fn budget_row(row: &rusqlite::Row<'_>) -> ProofResult<Budget> {
    let parent_budget_id = match row.get_ref(1).map_err(storage_error)? {
        rusqlite::types::ValueRef::Null => None,
        text => {
            Some(EntityId::parse(text.as_str().map_err(storage_error)?).map_err(storage_error)?)
        }
    };
    let budget = Budget {
        budget_id: EntityId::parse(
            row.get_ref(0)
                .map_err(storage_error)?
                .as_str()
                .map_err(storage_error)?,
        )
        .map_err(storage_error)?,
        parent_budget_id,
        limit: wire(row.get(2).map_err(storage_error)?)?,
        consumed: wire(row.get(3).map_err(storage_error)?)?,
        reserved: wire(row.get(4).map_err(storage_error)?)?,
        revision: wire(row.get(5).map_err(storage_error)?)?,
    };
    budget.validate().map_err(storage_error)?;
    Ok(budget)
}
fn write_budget(connection: &Connection, budget: &Budget, expected: WireInt) -> ProofResult<()> {
    budget.validate()?;
    if budget.revision != expected.checked_add(one())? {
        return Err(stale());
    }
    let changed = connection.execute("UPDATE budgets SET consumed=?1,reserved=?2,revision=?3 WHERE budget_id=?4 AND revision=?5",
        params![signed(budget.consumed)?, signed(budget.reserved)?, signed(budget.revision)?, budget.budget_id.to_string(),
            signed(expected)?]).map_err(storage_error)?;
    if changed != 1 {
        return Err(stale());
    }
    Ok(())
}
fn budget_lineage(connection: &Connection, id: EntityId) -> ProofResult<Vec<Budget>> {
    let mut lineage: Vec<Budget> = Vec::new();
    let mut next = Some(id);
    while let Some(id) = next {
        if lineage.len() == MAX_DEPTH || lineage.iter().any(|budget| budget.budget_id == id) {
            return Err(integrity());
        }
        let budget = read_budget(connection, id)?;
        next = budget.parent_budget_id;
        lineage.push(budget);
    }
    for budget in &lineage {
        if child_backing(connection, budget.budget_id)? > budget.reserved {
            return Err(integrity());
        }
    }
    Ok(lineage)
}
fn child_backing(connection: &Connection, id: EntityId) -> ProofResult<WireInt> {
    let total: i64 = connection
        .query_row(
            "SELECT coalesce(sum(quota_limit-consumed),0) FROM budgets WHERE parent_budget_id=?1",
            [id.to_string()],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    wire(total)
}

fn read_control(connection: &Connection, id: EntityId) -> ProofResult<ControlState> {
    let (bytes, revision): (Vec<u8>, i64) = connection.query_row(
        "SELECT CASE WHEN length(data)<=1048576 THEN data END,revision FROM controls WHERE investigation_id=?1",
        [id.to_string()], |row| Ok((row.get(0)?, row.get(1)?))).map_err(storage_error)?;
    let state: ControlState = decode(&bytes)?;
    if state.investigation_id != id || state.revision != wire(revision)? {
        return Err(integrity());
    }
    Ok(state)
}
fn controls(connection: &Connection) -> ProofResult<Vec<ControlState>> {
    let mut statement = connection
        .prepare("SELECT investigation_id FROM controls ORDER BY investigation_id LIMIT 65")
        .map_err(storage_error)?;
    let mut rows = statement.query([]).map_err(storage_error)?;
    let mut result = Vec::new();
    while let Some(row) = rows.next().map_err(storage_error)? {
        if result.len() == MAX_CONTROLS as usize {
            return Err(integrity());
        }
        let id: String = row.get(0).map_err(storage_error)?;
        result.push(read_control(
            connection,
            EntityId::parse(&id).map_err(storage_error)?,
        )?);
    }
    Ok(result)
}
fn control_context(connection: &Connection, id: EntityId) -> ProofResult<(EntityId, WireInt)> {
    let (project, scope): (String, i64) = connection
        .query_row(
            "SELECT project_id,scope_revision FROM controls WHERE investigation_id=?1",
            [id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(storage_error)?;
    Ok((
        EntityId::parse(&project).map_err(storage_error)?,
        wire(scope)?,
    ))
}

fn state_name(state: InvocationState) -> &'static str {
    match state {
        InvocationState::Proposed => "proposed",
        InvocationState::Rejected => "rejected",
        InvocationState::WaitingApproval => "waiting_approval",
        InvocationState::Reserved => "reserved",
        InvocationState::Sending => "sending",
        InvocationState::Completed => "completed",
        InvocationState::Failed => "failed",
        InvocationState::OutcomeUnknown => "outcome_unknown",
        InvocationState::Cancelled => "cancelled",
    }
}
fn validate_invocation(
    stored: &StoredInvocation,
    run_id: EntityId,
) -> ProofResult<(Vec<u8>, Vec<u8>)> {
    if stored.invocation.run_id != run_id || stored.history.last() != &stored.invocation {
        return Err(denied());
    }
    if !matches!(
        stored.invocation.state,
        InvocationState::Reserved | InvocationState::Sending | InvocationState::OutcomeUnknown
    ) && stored.reserved_units != WireInt::ZERO
    {
        return Err(integrity());
    }
    if stored.reserved_units > stored.requested.units
        || stored.invocation.usage.units > stored.requested.units
    {
        return Err(integrity());
    }
    let history = stored.history.export_json()?;
    let data = bounded_json(&stored.invocation)?;
    let decoded = Invocation::parse_json(&data, Some(&stored.history)).map_err(storage_error)?;
    if decoded != stored.invocation {
        return Err(integrity());
    }
    Ok((data, history))
}
fn require_history_extension(
    previous: &InvocationHistory,
    next: &InvocationHistory,
) -> ProofResult<()> {
    let previous: serde_json::Value = decode(&previous.export_json()?)?;
    let next: serde_json::Value = decode(&next.export_json()?)?;
    let old = previous["transitions"].as_array().ok_or_else(integrity)?;
    let new = next["transitions"].as_array().ok_or_else(integrity)?;
    if previous["initial"] != next["initial"] || new.len() != old.len() + 1 || !new.starts_with(old)
    {
        return Err(denied());
    }
    Ok(())
}
fn validate_invocation_context(
    connection: &Connection,
    stored: &StoredInvocation,
    current_admission: bool,
) -> ProofResult<()> {
    let invocation = &stored.invocation;
    let (control, scope, grant) = invocation_origin(connection, invocation)?;
    let budget = read_budget(connection, invocation.budget_id)?;
    let own_reservation = budget
        .reserved
        .checked_sub(child_backing(connection, budget.budget_id)?)
        .map_err(storage_error)?;
    let other_held: i64 = connection.query_row(
        "SELECT coalesce(sum(reserved_units),0) FROM invocations WHERE budget_id=?1 AND invocation_id<>?2",
        params![budget.budget_id.to_string(), invocation.invocation_id.to_string()], |row| row.get(0))
        .map_err(storage_error)?;
    if wire(other_held)?
        .checked_add(stored.reserved_units)
        .map_err(storage_error)?
        > own_reservation
    {
        return Err(integrity());
    }
    if current_admission
        && matches!(
            invocation.state,
            InvocationState::Reserved | InvocationState::Sending
        )
    {
        if !control.admission_open
            || control.mode != ControlMode::Running
            || invocation.control_revision != control.revision
            || invocation.scope_revision != scope
        {
            return Err(stale());
        }
        if let Some(grant) = grant {
            grant.validate_current(invocation, &stored.requested, AuditTime::now())?;
        }
    }
    Ok(())
}
fn ensure_pending_capacity(connection: &Connection, stored: &StoredInvocation) -> ProofResult<()> {
    if stored.invocation.state != InvocationState::Reserved {
        return Ok(());
    }
    // Pending work is bounded independently from retained terminal history.
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM invocations WHERE investigation_id=?1 AND state='reserved' AND invocation_id<>?2",
        params![stored.invocation.investigation_id.to_string(), stored.invocation.invocation_id.to_string()],
        |row| row.get(0)).map_err(storage_error)?;
    if !(0..256).contains(&count) {
        return Err(exhausted());
    }
    Ok(())
}
fn read_invocation(
    connection: &Connection,
    id: EntityId,
    run_id: EntityId,
) -> ProofResult<StoredInvocation> {
    let mut statement = connection.prepare("SELECT CASE WHEN length(data)<=1048576 THEN data END,CASE WHEN length(history)<=1048576 THEN history END,reserved_units,run_id,deduplication_key,investigation_id,budget_id,state,control_revision,CASE WHEN length(requested)<=1024 THEN requested END,source_control_revision FROM invocations WHERE invocation_id=?1")
        .map_err(storage_error)?;
    let mut rows = statement.query([id.to_string()]).map_err(storage_error)?;
    let row = rows.next().map_err(storage_error)?.ok_or_else(integrity)?;
    let data = row
        .get_ref(0)
        .map_err(storage_error)?
        .as_blob()
        .map_err(storage_error)?;
    let history = row
        .get_ref(1)
        .map_err(storage_error)?
        .as_blob()
        .map_err(storage_error)?;
    let history = InvocationHistory::restore_json(history).map_err(storage_error)?;
    let invocation = Invocation::parse_json(data, Some(&history)).map_err(storage_error)?;
    let requested = decode(
        row.get_ref(9)
            .map_err(storage_error)?
            .as_blob()
            .map_err(storage_error)?,
    )?;
    let stored = StoredInvocation {
        invocation,
        history,
        reserved_units: wire(row.get(2).map_err(storage_error)?)?,
        requested,
        source_control_revision: wire(row.get(10).map_err(storage_error)?)?,
    };
    let value = &stored.invocation;
    if value.invocation_id != id
        || value.run_id != run_id
        || stored.history.last() != value
        || row.get::<_, String>(3).map_err(storage_error)? != value.run_id.to_string()
        || row.get::<_, String>(4).map_err(storage_error)? != value.deduplication_key
        || row.get::<_, String>(5).map_err(storage_error)? != value.investigation_id.to_string()
        || row.get::<_, String>(6).map_err(storage_error)? != value.budget_id.to_string()
        || row.get::<_, String>(7).map_err(storage_error)? != state_name(value.state)
        || wire(row.get(8).map_err(storage_error)?)? != value.control_revision
    {
        return Err(integrity());
    }
    if !matches!(
        value.state,
        InvocationState::Reserved | InvocationState::Sending | InvocationState::OutcomeUnknown
    ) && stored.reserved_units != WireInt::ZERO
    {
        return Err(integrity());
    }
    if stored.reserved_units > stored.requested.units
        || stored.invocation.usage.units > stored.requested.units
    {
        return Err(integrity());
    }
    invocation_origin(connection, value)?;
    Ok(stored)
}

fn invocation_for_dedup(
    connection: &Connection,
    run_id: EntityId,
    key: &str,
) -> ProofResult<Option<StoredInvocation>> {
    if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
        return Err(invalid());
    }
    // The existing UNIQUE(run_id,deduplication_key) index bounds this lookup to one record.
    let id: Option<String> = connection.prepare_cached(
        "SELECT CASE WHEN length(invocation_id)=36 THEN invocation_id END FROM invocations WHERE run_id=?1 AND deduplication_key=?2")
        .map_err(storage_error)?
        .query_row(params![run_id.to_string(), key], |row| row.get(0)).optional().map_err(storage_error)?;
    id.map(|id| {
        read_invocation(
            connection,
            EntityId::parse(&id).map_err(storage_error)?,
            run_id,
        )
    })
    .transpose()
}
fn invocations(
    connection: &Connection,
    run_id: EntityId,
    investigation: Option<EntityId>,
) -> ProofResult<Vec<StoredInvocation>> {
    // Control invalidation needs only pending reservations, not all terminal history.
    let maximum = if investigation.is_some() {
        256
    } else {
        MAX_INVOCATIONS
    };
    let mut statement = connection.prepare("SELECT invocation_id FROM invocations WHERE (?1 IS NULL OR (investigation_id=?1 AND state='reserved')) ORDER BY invocation_id LIMIT ?2")
        .map_err(storage_error)?;
    let mut rows = statement
        .query(params![investigation.map(|id| id.to_string()), maximum + 1])
        .map_err(storage_error)?;
    let mut result = Vec::new();
    while let Some(row) = rows.next().map_err(storage_error)? {
        if i64::try_from(result.len()).map_err(|_| integrity())? == maximum {
            return Err(integrity());
        }
        let id: String = row.get(0).map_err(storage_error)?;
        result.push(read_invocation(
            connection,
            EntityId::parse(&id).map_err(storage_error)?,
            run_id,
        )?);
    }
    Ok(result)
}

fn next_event_sequence(connection: &Connection, aggregate: EntityId) -> ProofResult<WireInt> {
    let last: Option<i64> = connection
        .query_row(
            "SELECT max(aggregate_sequence) FROM events WHERE aggregate_id=?1",
            [aggregate.to_string()],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    wire(last.unwrap_or(0))?
        .checked_add(one())
        .map_err(Into::into)
}
fn event_row(row: &rusqlite::Row<'_>) -> ProofResult<Event> {
    let bytes: Vec<u8> = row.get(0).map_err(storage_error)?;
    let event: Event = decode(&bytes)?;
    if row.get::<_, String>(1).map_err(storage_error)? != event.event_id.to_string()
        || row.get::<_, String>(2).map_err(storage_error)? != event.aggregate_id.to_string()
        || wire(row.get(3).map_err(storage_error)?)? != event.aggregate_sequence
    {
        return Err(integrity());
    }
    Ok(event)
}

fn validate_store(
    connection: &Connection,
    run_id: EntityId,
    profile: &LoadedProfile,
) -> ProofResult<()> {
    let journal: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(storage_error)?;
    if journal != "delete" {
        return Err(integrity());
    }
    let integrity_result: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(storage_error)?;
    if integrity_result != "ok" {
        return Err(integrity());
    }
    let mut foreign_keys = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(storage_error)?;
    if foreign_keys
        .query([])
        .map_err(storage_error)?
        .next()
        .map_err(storage_error)?
        .is_some()
    {
        return Err(integrity());
    }
    let app: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(storage_error)?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(storage_error)?;
    if app != i64::from(APP_ID) || version != i64::from(SCHEMA_VERSION) {
        return Err(integrity());
    }
    let mut schema = connection.prepare("SELECT CASE WHEN length(name)<=128 THEN name END,CASE WHEN length(sql)<=4096 THEN sql END FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY name LIMIT ?1")
        .map_err(storage_error)?;
    let mut rows = schema
        .query([i64::try_from(TABLES.len() + INDEXES.len() + 1).map_err(storage_error)?])
        .map_err(storage_error)?;
    let mut seen = BTreeSet::new();
    while let Some(row) = rows.next().map_err(storage_error)? {
        let name: String = row.get(0).map_err(storage_error)?;
        let sql: String = row.get(1).map_err(storage_error)?;
        if !TABLES
            .iter()
            .chain(INDEXES.iter())
            .any(|(expected_name, expected_sql)| name == *expected_name && sql == *expected_sql)
            || !seen.insert(name)
        {
            return Err(integrity());
        }
    }
    if seen.len() != TABLES.len() + INDEXES.len() {
        return Err(integrity());
    }
    let metadata: (String, String, String) = connection.query_row("SELECT CASE WHEN length(schema_version)=5 THEN schema_version END,CASE WHEN length(run_id)=36 THEN run_id END,CASE WHEN length(profile_sha256)=64 THEN profile_sha256 END FROM ledger_meta WHERE id=1",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).map_err(storage_error)?;
    if metadata
        != (
            "0.1.0".to_owned(),
            run_id.to_string(),
            profile.sha256().to_string(),
        )
    {
        return Err(integrity());
    }
    for (table, maximum) in [
        ("budgets", MAX_BUDGETS),
        ("controls", MAX_CONTROLS),
        ("invocations", MAX_INVOCATIONS),
        ("events", MAX_EVENTS),
        ("checkpoints", MAX_CHECKPOINTS),
    ] {
        ensure_capacity(connection, table, maximum + 1).map_err(storage_error)?;
    }
    let mut budgets = connection
        .prepare("SELECT budget_id FROM budgets LIMIT 257")
        .map_err(storage_error)?;
    let mut rows = budgets.query([]).map_err(storage_error)?;
    while let Some(row) = rows.next().map_err(storage_error)? {
        let id: String = row.get(0).map_err(storage_error)?;
        let id = EntityId::parse(&id).map_err(storage_error)?;
        budget_lineage(connection, id)?;
    }
    validate_catalog(connection)?;
    for control in controls(connection)? {
        let (project, scope) = control_context(connection, control.investigation_id)?;
        validate_control_catalog(connection, &control, project, scope).map_err(storage_error)?;
    }
    for stored in invocations(connection, run_id, None)? {
        validate_invocation_context(connection, &stored, false)?;
    }
    let mut events = connection.prepare("SELECT CASE WHEN length(data)<=1048576 THEN data END,event_id,aggregate_id,aggregate_sequence FROM events ORDER BY position LIMIT 16385")
        .map_err(storage_error)?;
    let mut rows = events.query([]).map_err(storage_error)?;
    let mut sequences = BTreeMap::new();
    while let Some(row) = rows.next().map_err(storage_error)? {
        let event = event_row(row)?;
        let previous = sequences
            .get(&event.aggregate_id)
            .copied()
            .unwrap_or(WireInt::ZERO);
        if event.aggregate_sequence != previous.checked_add(one())? {
            return Err(integrity());
        }
        sequences.insert(event.aggregate_id, event.aggregate_sequence);
    }
    let mut checkpoints = connection.prepare("SELECT CASE WHEN length(data)<=1048576 THEN data END,checkpoint_id FROM checkpoints ORDER BY position LIMIT 4097")
        .map_err(storage_error)?;
    let mut rows = checkpoints.query([]).map_err(storage_error)?;
    while let Some(row) = rows.next().map_err(storage_error)? {
        let bytes: Vec<u8> = row.get(0).map_err(storage_error)?;
        let checkpoint: Checkpoint = decode(&bytes)?;
        if checkpoint.run_id != run_id
            || row.get::<_, String>(1).map_err(storage_error)?
                != checkpoint.checkpoint_id.to_string()
        {
            return Err(integrity());
        }
    }
    Ok(())
}

// Catalog reads validate both strict wire data and the indexed columns used for host selection.
fn catalog_record<T: DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    key: &str,
    validate: impl FnOnce(&T, &rusqlite::Row<'_>) -> ProofResult<()>,
) -> ProofResult<T> {
    optional_catalog_record(connection, sql, key, validate)?.ok_or_else(integrity)
}

fn optional_catalog_record<T: DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    key: &str,
    validate: impl FnOnce(&T, &rusqlite::Row<'_>) -> ProofResult<()>,
) -> ProofResult<Option<T>> {
    let mut statement = connection.prepare_cached(sql).map_err(storage_error)?;
    let mut rows = statement.query([key]).map_err(storage_error)?;
    let Some(row) = rows.next().map_err(storage_error)? else {
        return Ok(None);
    };
    let bytes = row
        .get_ref(0)
        .map_err(storage_error)?
        .as_blob()
        .map_err(storage_error)?;
    let record = decode(bytes)?;
    validate(&record, row)?;
    Ok(Some(record))
}

fn column_text(row: &rusqlite::Row<'_>, index: usize, expected: &str) -> ProofResult<()> {
    let value = row
        .get_ref(index)
        .map_err(storage_error)?
        .as_str()
        .map_err(storage_error)?;
    if value != expected {
        return Err(integrity());
    }
    Ok(())
}

fn column_wire(row: &rusqlite::Row<'_>, index: usize, expected: WireInt) -> ProofResult<()> {
    if wire(row.get(index).map_err(storage_error)?)? != expected {
        return Err(integrity());
    }
    Ok(())
}

fn read_project(connection: &Connection, id: EntityId) -> ProofResult<FixtureProject> {
    catalog_record(
        connection,
        "SELECT CASE WHEN length(data)<=1048576 THEN data END,user_id,scope_policy_id,revision FROM projects WHERE project_id=?1",
        &id.to_string(),
        |project: &FixtureProject, row| {
            if project.project_id != id {
                return Err(integrity());
            }
            column_text(row, 1, &project.user_id.to_string())?;
            column_text(row, 2, &project.scope_policy_id.to_string())?;
            column_wire(row, 3, project.revision)
        },
    )
}

fn read_scope(connection: &Connection, id: EntityId) -> ProofResult<ScopePolicy> {
    catalog_record(
        connection,
        "SELECT CASE WHEN length(data)<=1048576 THEN data END,project_id,revision FROM scopes WHERE scope_policy_id=?1",
        &id.to_string(),
        |scope: &ScopePolicy, row| {
            if scope.scope_policy_id != id {
                return Err(integrity());
            }
            column_text(row, 1, &scope.project_id.to_string())?;
            column_wire(row, 2, scope.revision)
        },
    )
}

fn read_identity(connection: &Connection, id: EntityId) -> ProofResult<IdentityProfile> {
    catalog_record(
        connection,
        "SELECT CASE WHEN length(data)<=1048576 THEN data END,project_id FROM identities WHERE identity_id=?1",
        &id.to_string(),
        |identity: &IdentityProfile, row| {
            if identity.identity_id != id {
                return Err(integrity());
            }
            column_text(row, 1, &identity.project_id.to_string())
        },
    )
}

fn read_tool(connection: &Connection, id: &CatalogId) -> ProofResult<RegisteredTool> {
    find_tool(connection, id)?.ok_or_else(integrity)
}

fn find_tool(connection: &Connection, id: &CatalogId) -> ProofResult<Option<RegisteredTool>> {
    optional_catalog_record(
        connection,
        "SELECT CASE WHEN length(data)<=1048576 THEN data END,version,provider_digest FROM tools WHERE tool_id=?1",
        id.as_str(),
        |tool: &RegisteredTool, row| {
            if tool.descriptor.tool_id != *id {
                return Err(integrity());
            }
            column_text(row, 1, &tool.descriptor.version.to_string())?;
            column_text(row, 2, &tool.provider_digest.to_string())
        },
    )
}

fn read_grant(connection: &Connection, id: EntityId) -> ProofResult<ApprovalGrant> {
    catalog_record(
        connection,
        "SELECT CASE WHEN length(data)<=1048576 THEN data END,project_id,tool_id,tool_version,provider_digest,scope_revision,identity_id,input_sha256,revoked,grant_id FROM grants WHERE grant_id=?1",
        &id.to_string(),
        |grant: &ApprovalGrant, row| {
            if grant.grant_id != id {
                return Err(integrity());
            }
            validate_grant_columns(grant, row)
        },
    )
}

fn validate_grant_columns(grant: &ApprovalGrant, row: &rusqlite::Row<'_>) -> ProofResult<()> {
    column_text(row, 1, &grant.project_id.to_string())?;
    column_text(row, 2, &grant.tool_id.to_string())?;
    column_text(row, 3, &grant.tool_version.to_string())?;
    column_text(row, 4, &grant.provider_digest.to_string())?;
    column_wire(row, 5, grant.scope_revision)?;
    column_text(row, 6, &grant.identity_id.to_string())?;
    column_text(row, 7, &grant.bounded_input_sha256.to_string())?;
    if row.get::<_, i64>(8).map_err(storage_error)? != i64::from(grant.revoked) {
        return Err(integrity());
    }
    column_text(row, 9, &grant.grant_id.to_string())
}

fn read_session(connection: &Connection, id: EntityId) -> ProofResult<RegisteredSession> {
    catalog_record(
        connection,
        "SELECT CASE WHEN length(data)<=1048576 THEN data END,project_id,investigation_id,user_id,control_revision FROM sessions WHERE session_id=?1",
        &id.to_string(),
        |registered: &RegisteredSession, row| {
            let session = &registered.session;
            if session.session_id != id {
                return Err(integrity());
            }
            column_text(row, 1, &registered.project_id.to_string())?;
            column_text(row, 2, &session.investigation_id.to_string())?;
            column_text(row, 3, &session.user_id.to_string())?;
            column_wire(row, 4, session.control_revision)
        },
    )
}

fn record_exists(
    connection: &Connection,
    table: &str,
    column: &str,
    id: EntityId,
) -> ProofResult<bool> {
    // All schema identifiers are fixed internal call-site constants.
    connection
        .query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {column}=?1)"),
            [id.to_string()],
            |row| row.get(0),
        )
        .map_err(storage_error)
}

fn session_for_investigation(
    connection: &Connection,
    investigation: EntityId,
) -> ProofResult<Option<RegisteredSession>> {
    let id: Option<String> = connection.query_row(
        "SELECT CASE WHEN length(session_id)=36 THEN session_id END FROM sessions WHERE investigation_id=?1",
        [investigation.to_string()], |row| row.get(0)).optional().map_err(storage_error)?;
    id.map(|id| read_session(connection, EntityId::parse(&id).map_err(storage_error)?))
        .transpose()
}

fn validate_grant_links(connection: &Connection, grant: &ApprovalGrant) -> ProofResult<()> {
    read_project(connection, grant.project_id)?;
    let identity = read_identity(connection, grant.identity_id)?;
    let tool = read_tool(connection, &grant.tool_id)?;
    if identity.project_id != grant.project_id
        || tool.descriptor.version != grant.tool_version
        || tool.provider_digest != grant.provider_digest
    {
        return Err(denied());
    }
    // A grant records its selected scope epoch; current admission, not insertion, compares it to policy.
    Ok(())
}

fn validate_session_links(
    connection: &Connection,
    project_id: EntityId,
    session: &InvestigationSession,
) -> ProofResult<()> {
    let project = read_project(connection, project_id)?;
    if session.user_id != project.user_id {
        return Err(denied());
    }
    if record_exists(
        connection,
        "controls",
        "investigation_id",
        session.investigation_id,
    )? {
        let state = read_control(connection, session.investigation_id)?;
        let (owner, _) = control_context(connection, session.investigation_id)?;
        if owner != project_id || state.revision != session.control_revision {
            return Err(denied());
        }
    } else if session.control_revision != WireInt::ZERO {
        return Err(denied());
    }
    Ok(())
}

fn validate_control_catalog(
    connection: &Connection,
    state: &ControlState,
    project_id: EntityId,
    scope_revision: WireInt,
) -> ProofResult<()> {
    // Core ledger-only controls remain valid without a catalog fixture. They confer no catalog authority.
    if record_exists(connection, "projects", "project_id", project_id)? {
        let project = read_project(connection, project_id)?;
        let scope = read_scope(connection, project.scope_policy_id)?;
        if scope.project_id != project_id || scope.revision != scope_revision {
            return Err(denied());
        }
    }
    if let Some(registered) = session_for_investigation(connection, state.investigation_id)? {
        if registered.project_id != project_id
            || registered.session.control_revision != state.revision
        {
            return Err(denied());
        }
        validate_session_links(connection, registered.project_id, &registered.session)?;
    }
    Ok(())
}

fn require_control_scope(
    connection: &Connection,
    project_id: EntityId,
    revision: WireInt,
) -> ProofResult<()> {
    let mismatches: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM controls WHERE project_id=?1 AND scope_revision<>?2)",
            params![project_id.to_string(), signed(revision)?],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    if mismatches {
        return Err(integrity());
    }
    Ok(())
}

fn advance_session_control(
    connection: &Connection,
    state: &ControlState,
    expected: WireInt,
) -> ProofResult<()> {
    let Some(mut registered) = session_for_investigation(connection, state.investigation_id)?
    else {
        return Ok(());
    };
    let (project_id, _) = control_context(connection, state.investigation_id)?;
    if registered.project_id != project_id || registered.session.control_revision != expected {
        return Err(integrity());
    }
    registered.session.control_revision = state.revision;
    let changed = connection.execute(
        "UPDATE sessions SET control_revision=?1,data=?2 WHERE session_id=?3 AND control_revision=?4",
        params![signed(state.revision)?, encode(&registered)?, registered.session.session_id.to_string(), signed(expected)?])
        .map_err(storage_error)?;
    if changed != 1 {
        return Err(integrity());
    }
    Ok(())
}

fn validate_invocation_catalog(
    connection: &Connection,
    invocation: &Invocation,
) -> ProofResult<Option<ApprovalGrant>> {
    // Existing core ledger fixtures intentionally omit the authority catalog. Admission integrations
    // must resolve canonical project/session/grant records; this path supplies no missing authority.
    if !record_exists(connection, "projects", "project_id", invocation.project_id)? {
        let catalogued: bool = connection
            .query_row("SELECT EXISTS(SELECT 1 FROM projects)", [], |row| {
                row.get(0)
            })
            .map_err(storage_error)?;
        return if catalogued { Err(denied()) } else { Ok(None) };
    }
    let session = read_session(connection, invocation.session_id)?;
    let identity = read_identity(connection, invocation.identity_id)?;
    if session.project_id != invocation.project_id
        || session.session.investigation_id != invocation.investigation_id
        || identity.project_id != invocation.project_id
    {
        return Err(denied());
    }
    match find_tool(connection, &invocation.tool_id)? {
        Some(tool)
            if tool.descriptor.version == invocation.tool_version
                && tool.provider_digest == invocation.provider_digest => {}
        None if invocation.grant_id.is_none()
            && matches!(
                invocation.state,
                InvocationState::Proposed | InvocationState::Rejected
            ) => {}
        _ => return Err(denied()),
    }
    if let Some(id) = invocation.grant_id {
        let grant = read_grant(connection, id)?;
        if grant.project_id != invocation.project_id
            || grant.tool_id != invocation.tool_id
            || grant.tool_version != invocation.tool_version
            || grant.provider_digest != invocation.provider_digest
            || grant.scope_revision != invocation.scope_revision
            || grant.identity_id != invocation.identity_id
            || grant.bounded_input_sha256 != invocation.input_sha256
        {
            return Err(denied());
        }
        return Ok(Some(grant));
    }
    Ok(None)
}

fn grants(connection: &Connection) -> ProofResult<Vec<ApprovalGrant>> {
    let mut statement = connection.prepare_cached(
        "SELECT CASE WHEN length(data)<=1048576 THEN data END,project_id,tool_id,tool_version,provider_digest,scope_revision,identity_id,input_sha256,revoked,grant_id FROM grants ORDER BY grant_id LIMIT 4097")
        .map_err(storage_error)?;
    let mut rows = statement.query([]).map_err(storage_error)?;
    collect_grants(&mut rows)
}

fn matching_grants(
    connection: &Connection,
    invocation: &Invocation,
) -> ProofResult<Vec<ApprovalGrant>> {
    let mut statement = connection.prepare_cached(
        "SELECT CASE WHEN length(data)<=1048576 THEN data END,project_id,tool_id,tool_version,provider_digest,scope_revision,identity_id,input_sha256,revoked,grant_id FROM grants WHERE project_id=?1 AND tool_id=?2 AND tool_version=?3 AND provider_digest=?4 AND scope_revision=?5 AND identity_id=?6 AND input_sha256=?7 ORDER BY grant_id LIMIT 4097")
        .map_err(storage_error)?;
    let mut rows = statement
        .query(params![
            invocation.project_id.to_string(),
            invocation.tool_id.to_string(),
            invocation.tool_version.to_string(),
            invocation.provider_digest.to_string(),
            signed(invocation.scope_revision)?,
            invocation.identity_id.to_string(),
            invocation.input_sha256.to_string()
        ])
        .map_err(storage_error)?;
    collect_grants(&mut rows)
}

fn collect_grants(rows: &mut rusqlite::Rows<'_>) -> ProofResult<Vec<ApprovalGrant>> {
    let mut result = Vec::new();
    while let Some(row) = rows.next().map_err(storage_error)? {
        if result.len() == MAX_GRANTS as usize {
            return Err(integrity());
        }
        let bytes = row
            .get_ref(0)
            .map_err(storage_error)?
            .as_blob()
            .map_err(storage_error)?;
        let grant = decode(bytes)?;
        validate_grant_columns(&grant, row)?;
        result.push(grant);
    }
    Ok(result)
}

fn validate_catalog(connection: &Connection) -> ProofResult<()> {
    for (table, key, max) in [
        ("projects", "project_id", MAX_PROJECTS),
        ("scopes", "scope_policy_id", MAX_SCOPES),
        ("identities", "identity_id", MAX_IDENTITIES),
        ("tools", "tool_id", MAX_TOOLS),
        ("grants", "grant_id", MAX_GRANTS),
        ("sessions", "session_id", MAX_SESSIONS),
    ] {
        ensure_capacity(connection, table, max + 1)?;
        let mut statement = connection
            .prepare(&format!(
                "SELECT CASE WHEN length({key})<=128 THEN {key} END FROM {table} LIMIT ?1"
            ))
            .map_err(storage_error)?;
        let mut rows = statement.query([max + 1]).map_err(storage_error)?;
        while let Some(row) = rows.next().map_err(storage_error)? {
            let key: String = row.get(0).map_err(storage_error)?;
            if table == "tools" {
                read_tool(connection, &CatalogId::parse(&key).map_err(storage_error)?)?;
                continue;
            }
            let id = EntityId::parse(&key).map_err(storage_error)?;
            match table {
                "projects" => {
                    let project = read_project(connection, id)?;
                    if read_scope(connection, project.scope_policy_id)?.project_id != id {
                        return Err(integrity());
                    }
                }
                "scopes" => {
                    read_project(connection, read_scope(connection, id)?.project_id)?;
                }
                "identities" => {
                    read_project(connection, read_identity(connection, id)?.project_id)?;
                }
                "grants" => {
                    validate_grant_links(connection, &read_grant(connection, id)?)
                        .map_err(storage_error)?;
                }
                "sessions" => {
                    let registered = read_session(connection, id)?;
                    validate_session_links(connection, registered.project_id, &registered.session)
                        .map_err(storage_error)?;
                }
                _ => return Err(integrity()),
            }
        }
    }
    Ok(())
}

fn invocation_origin(
    connection: &Connection,
    invocation: &Invocation,
) -> ProofResult<(ControlState, WireInt, Option<ApprovalGrant>)> {
    let (project, scope) = control_context(connection, invocation.investigation_id)?;
    let control = read_control(connection, invocation.investigation_id)?;
    if project != invocation.project_id
        || invocation.scope_revision > scope
        || invocation.control_revision > control.revision
    {
        return Err(denied());
    }
    let grant = validate_invocation_catalog(connection, invocation)?;
    Ok((control, scope, grant))
}

// A borrowed serialization view avoids copying canonical session content on insertion.
#[derive(Serialize)]
struct SessionRecord<'a> {
    project_id: EntityId,
    session: &'a InvestigationSession,
}

#[cfg(test)]
mod proof_fault_tests {
    use super::*;
    use crate::application::proof_host::ProofHost;
    use crate::protocol::contracts::CanonicalFixtures;
    use crate::protocol::messages::ToolRequest;

    mod private_root {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/private_root.rs"
        ));
    }

    #[test]
    fn actual_sqlite_commit_rejection_rolls_back_reservation_events_checkpoint_and_closes_admission()
     {
        let root = private_root::PrivateRoot::new();
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let profile = LoadedProfile::load(
            &repo.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        let examples = std::fs::read(repo.join("fixtures/scenarios/contracts.json")).unwrap();
        let workspace = std::sync::Arc::new(
            OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap(),
        );
        let host = ProofHost::create(
            workspace.clone(),
            &profile,
            CanonicalFixtures::from_bytes(&examples).unwrap(),
            Digest::of(&examples),
            crate::adapters::native_files::executable_digest().unwrap(),
        )
        .unwrap();
        let binding = host.bind_local().unwrap();
        let input = serde_json::value::RawValue::from_string(
            serde_json::json!({
            "kind":"investigation","record_id":host.session.investigation_id})
            .to_string(),
        )
        .unwrap();
        let request = ToolRequest {
            call_id: EntityId::new(),
            tool_id: CatalogId::parse("context.read").unwrap(),
            tool_version: ContractVersion::V0_1_0,
            input: &input,
            source_control_revision: WireInt::ZERO,
        };
        let prepared = host.registry.prepare(&binding, &request).unwrap();
        host.approve(&binding, prepared.call()).unwrap();
        let invocation_before = host
            .ledger
            .read_invocation(prepared.call().invocation_id)
            .unwrap()
            .invocation;
        let budget_before = host.ledger.read_budget(host.budget_id).unwrap();
        let events_before = host.ledger.event_page(WireInt::ZERO, 256).unwrap().events;
        let checkpoint_before = host.ledger.latest_checkpoint().unwrap();
        host.ledger.install_fixture_commit_hook(|| true).unwrap();
        let error = host
            .admission
            .reserve(&binding, prepared.call())
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::IntegrityError);
        assert_eq!(
            host.admission.check_integrity().unwrap_err().code,
            ErrorCode::IntegrityError
        );
        assert_eq!(
            host.ledger
                .read_invocation(prepared.call().invocation_id)
                .unwrap()
                .invocation,
            invocation_before
        );
        assert_eq!(
            host.ledger.read_budget(host.budget_id).unwrap(),
            budget_before
        );
        assert_eq!(
            host.ledger.event_page(WireInt::ZERO, 256).unwrap().events,
            events_before
        );
        assert_eq!(host.ledger.latest_checkpoint().unwrap(), checkpoint_before);
        drop(host);
        let restored = Ledger::open_readonly(&workspace, &profile).unwrap();
        assert_eq!(
            restored
                .read_invocation(invocation_before.invocation_id)
                .unwrap()
                .invocation,
            invocation_before
        );
        assert_eq!(
            restored.read_budget(budget_before.budget_id).unwrap(),
            budget_before
        );
    }

    #[test]
    fn actual_sqlite_full_retains_native_fault_and_closes_admission_without_dispatch() {
        let root = private_root::PrivateRoot::new();
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let profile = LoadedProfile::load(
            &repo.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        let examples = std::fs::read(repo.join("fixtures/scenarios/contracts.json")).unwrap();
        let workspace = std::sync::Arc::new(
            OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap(),
        );
        let host = ProofHost::create(
            workspace,
            &profile,
            CanonicalFixtures::from_bytes(&examples).unwrap(),
            Digest::of(&examples),
            crate::adapters::native_files::executable_digest().unwrap(),
        )
        .unwrap();
        let binding = host.bind_local().unwrap();
        let pages = host.ledger.fixture_limit_pages().unwrap();
        assert!(pages > 0);
        let input = serde_json::value::RawValue::from_string(
            serde_json::json!({
            "kind":"investigation","record_id":host.session.investigation_id})
            .to_string(),
        )
        .unwrap();
        let mut observed = None;
        for _ in 0..256 {
            let request = ToolRequest {
                call_id: EntityId::new(),
                tool_id: CatalogId::parse("context.read").unwrap(),
                tool_version: ContractVersion::V0_1_0,
                input: &input,
                source_control_revision: WireInt::ZERO,
            };
            let attempted = (|| {
                let prepared = host.registry.prepare(&binding, &request)?;
                host.approve(&binding, prepared.call())?;
                host.admission
                    .reserve(&binding, prepared.call())
                    .map(|_| ())
            })();
            if let Err(error) = attempted {
                observed = Some(error);
                break;
            }
        }
        let error =
            observed.expect("finite canonical database page capacity must reject actual writes");
        assert_eq!(error.code, ErrorCode::IntegrityError);
        let fault = error
            .storage_fault()
            .expect("native SQLite cause must survive fail-closed mapping");
        assert_eq!(fault.primary_code, 13);
        assert_eq!(fault.extended_code & 0xff, 13);
        assert_eq!(
            host.admission.check_integrity().unwrap_err().code,
            ErrorCode::IntegrityError
        );

        let grant = host
            .ledger
            .grants()
            .unwrap()
            .into_iter()
            .find(|grant| !grant.revoked)
            .unwrap();
        let swallowed = host.ledger.transaction(|tx| {
            for _ in 0..64 {
                let mut identity = host.identity.clone();
                identity.identity_id = EntityId::new();
                if let Err(native) = tx.insert_identity(&identity) {
                    assert_eq!(native.storage_fault().unwrap().primary_code, 13);
                    // A caller handling an aborted write must not escape into autocommit.
                    let _ = tx.revoke_grant(grant.grant_id);
                    return Ok(());
                }
            }
            panic!("bounded canonical identity writes must encounter database capacity");
        });
        assert_eq!(swallowed.unwrap_err().code, ErrorCode::IntegrityError);
        assert_eq!(host.ledger.read_grant(grant.grant_id).unwrap(), grant);
    }
}
