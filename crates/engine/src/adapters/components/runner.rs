//! Native child protocol. Guest imports never receive this private supervisor channel.
use super::{
    bindings::{self, InvocationContext, Observation, SnapshotReference},
    error, invalid,
};
use crate::application::profile::ComponentProfile;
use crate::domain::values::Digest;
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use wasmtime::component::{Component, HasSelf, Linker, ResourceTable};
use wasmtime::{Config, Engine, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerInput {
    pub component: PathBuf,
    pub component_sha256: Digest,
    pub context: InvocationContext,
    pub limits: ComponentProfile,
    pub output_limit: usize,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreFacts {
    pub fuel_remaining: u64,
    pub memory_peak_bytes: usize,
    pub memory_denied_bytes: usize,
    pub table_peak_elements: usize,
    pub table_denied_elements: usize,
    pub instance_limit: usize,
    pub memory_limit: usize,
    pub table_limit: usize,
    pub resource_probes: Vec<ResourceProbe>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceProbe {
    pub resource: String,
    pub requested: u64,
    pub limit: u64,
    pub denied: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunnerFrame {
    Ready,
    Read {
        snapshot: SnapshotReference,
        offset: u64,
        max_bytes: u32,
    },
    Done {
        observations: Vec<Observation>,
        facts: StoreFacts,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<ProofError>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadReply {
    pub bytes: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ProofError>,
}

struct Limits {
    inner: StoreLimits,
    facts: StoreFacts,
}
impl ResourceLimiter for Limits {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let result = self.inner.memory_growing(current, desired, maximum);
        if matches!(result, Ok(true)) {
            self.facts.memory_peak_bytes = self.facts.memory_peak_bytes.max(desired);
        } else {
            self.facts.memory_denied_bytes = self.facts.memory_denied_bytes.max(desired);
        }
        result
    }
    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let result = self.inner.table_growing(current, desired, maximum);
        if matches!(result, Ok(true)) {
            self.facts.table_peak_elements = self.facts.table_peak_elements.max(desired);
        } else {
            self.facts.table_denied_elements = self.facts.table_denied_elements.max(desired);
        }
        result
    }
    fn instances(&self) -> usize {
        self.inner.instances()
    }
    fn memories(&self) -> usize {
        self.inner.memories()
    }
    fn tables(&self) -> usize {
        self.inner.tables()
    }
}
struct State {
    table: ResourceTable,
    wasi: WasiCtx,
    limits: Limits,
    output_limit: usize,
}
impl WasiView for State {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}
impl bindings::razen::component_proof::types::Host for State {}
impl bindings::razen::component_proof::snapshot_reader::Host for State {
    fn read_body(
        &mut self,
        snapshot: SnapshotReference,
        offset: u64,
        max_bytes: u32,
    ) -> Result<Vec<u8>, bindings::razen::component_proof::types::SdkError> {
        let result = (|| {
            send(
                &RunnerFrame::Read {
                    snapshot,
                    offset,
                    max_bytes,
                },
                self.output_limit,
            )?;
            let reply: ReadReply = receive(400_000)?;
            if let Some(error) = reply.error {
                return Err(error);
            }
            if reply.bytes.len() > max_bytes as usize {
                return Err(invalid());
            }
            Ok(reply.bytes)
        })();
        result.map_err(sdk_error)
    }
}
fn sdk_error(cause: ProofError) -> bindings::razen::component_proof::types::SdkError {
    use bindings::razen::component_proof::types::{ErrorCode as Code, SdkError};
    let code = match cause.code {
        ErrorCode::PermissionDenied => Code::PermissionDenied,
        ErrorCode::BudgetExhausted => Code::BudgetExhausted,
        ErrorCode::StaleSnapshot => Code::StaleSnapshot,
        ErrorCode::Timeout => Code::Timeout,
        ErrorCode::Cancelled => Code::Cancelled,
        ErrorCode::OutputInvalid => Code::OutputInvalid,
        _ => Code::InvalidInput,
    };
    SdkError {
        code,
        message: cause.message.to_string(),
    }
}
fn host_error(cause: bindings::razen::component_proof::types::SdkError) -> ProofError {
    use bindings::razen::component_proof::types::ErrorCode as Code;
    let code = match cause.code {
        Code::InvalidInput => ErrorCode::InvalidInput,
        Code::PermissionDenied => ErrorCode::PermissionDenied,
        Code::BudgetExhausted => ErrorCode::BudgetExhausted,
        Code::StaleSnapshot => ErrorCode::StaleSnapshot,
        Code::Timeout => ErrorCode::Timeout,
        Code::Cancelled => ErrorCode::Cancelled,
        Code::OutputInvalid => ErrorCode::OutputInvalid,
    };
    error(code, "Guest returned a structured component failure")
}
fn execute(input: RunnerInput) -> ProofResult<RunnerFrame> {
    let mut config = Config::new();
    config
        .wasm_component_model(true)
        .consume_fuel(true)
        .epoch_interruption(true);
    let engine = Engine::new(&config).map_err(|_| invalid())?;
    let descriptor = rustix::fs::open(
        &input.component,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| invalid())?;
    let file = std::fs::File::from(descriptor);
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 {
        return Err(invalid());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() > 16 * 1024 * 1024 || Digest::of(&bytes) != input.component_sha256 {
        return Err(invalid());
    }
    let component = Component::new(&engine, &bytes).map_err(|_| {
        error(
            ErrorCode::OutputInvalid,
            "Approved component could not be compiled",
        )
    })?;
    let limits = &input.limits;
    let inner = StoreLimitsBuilder::new()
        .memory_size(limits.linear_memory_bytes.get() as usize)
        .instances(limits.instances.get() as usize)
        .memories(limits.memories.get() as usize)
        .tables(limits.tables.get() as usize)
        .table_elements(limits.table_elements.get() as usize)
        .trap_on_grow_failure(true)
        .build();
    let mut wasi = WasiCtxBuilder::new();
    wasi.allow_tcp(false)
        .allow_udp(false)
        .allow_ip_name_lookup(false);
    let state = State {
        table: ResourceTable::new(),
        wasi: wasi.build(),
        output_limit: input.output_limit,
        limits: Limits {
            inner,
            facts: StoreFacts {
                instance_limit: limits.instances.get() as usize,
                memory_limit: limits.memories.get() as usize,
                table_limit: limits.tables.get() as usize,
                ..StoreFacts::default()
            },
        },
    };
    let mut store = Store::new(&engine, state);
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(limits.fuel_per_invocation.get())
        .map_err(|_| invalid())?;
    store.set_epoch_deadline(
        limits
            .invocation_deadline_ms
            .get()
            .div_ceil(limits.epoch_interval_ms.get()),
    );
    store.epoch_deadline_trap();
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker).map_err(|_| invalid())?;
    bindings::PassiveProof::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
        .map_err(|_| invalid())?;
    let instance =
        bindings::PassiveProof::instantiate(&mut store, &component, &linker).map_err(|_| {
            error(
                ErrorCode::OutputInvalid,
                "Component instantiation exceeded its public contract or Store limits",
            )
        })?;
    send(&RunnerFrame::Ready, input.output_limit)?;
    let stop = Arc::new(AtomicBool::new(false));
    let epoch_engine = engine.clone();
    let epoch_stop = Arc::clone(&stop);
    let interval = Duration::from_millis(limits.epoch_interval_ms.get());
    let ticker = std::thread::spawn(move || {
        while !epoch_stop.load(Ordering::SeqCst) {
            std::thread::sleep(interval);
            epoch_engine.increment_epoch();
        }
    });
    let result = instance
        .razen_component_proof_passive_check()
        .call_analyze(&mut store, &input.context);
    stop.store(true, Ordering::SeqCst);
    ticker.join().map_err(|_| invalid())?;
    let mut facts = store.data().limits.facts.clone();
    facts.fuel_remaining = store.get_fuel().map_err(|_| invalid())?;
    facts.resource_probes = super::resource_checks::probe(&engine, limits)?;
    let (observations, failure) = match result {
        Ok(Ok(observations)) => (observations, None),
        Ok(Err(cause)) => (Vec::new(), Some(host_error(cause))),
        Err(cause) => {
            let code = if cause.downcast_ref::<wasmtime::Trap>().is_some_and(|trap| {
                matches!(trap, wasmtime::Trap::OutOfFuel | wasmtime::Trap::Interrupt)
            }) {
                ErrorCode::Timeout
            } else {
                ErrorCode::OutputInvalid
            };
            (
                Vec::new(),
                Some(error(
                    code,
                    "Wasmtime interrupted or trapped the guest; no successful result",
                )),
            )
        }
    };
    if observations.len() > 128 {
        return Ok(RunnerFrame::Done {
            observations: Vec::new(),
            facts,
            error: Some(error(
                ErrorCode::OutputInvalid,
                "Guest observation count exceeded the host output limit",
            )),
        });
    }
    Ok(RunnerFrame::Done {
        observations,
        facts,
        error: failure,
    })
}
struct BoundedFrame {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for BoundedFrame {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("component frame limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub fn send(value: &impl Serialize, cap: usize) -> ProofResult<()> {
    let mut frame = BoundedFrame {
        bytes: Vec::new(),
        limit: cap,
    };
    serde_json::to_writer(&mut frame, value).map_err(|_| {
        error(
            ErrorCode::OutputInvalid,
            "Component native output frame exceeds limit",
        )
    })?;
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&frame.bytes)
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|_| invalid())
}
pub fn receive<T: serde::de::DeserializeOwned>(cap: usize) -> ProofResult<T> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(cap as u64 + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() > cap || bytes.last() != Some(&b'\n') {
        return Err(invalid());
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}
pub fn main_entry() -> i32 {
    let result = receive::<RunnerInput>(128 * 1024).and_then(execute);
    let frame = result.unwrap_or_else(|cause| RunnerFrame::Done {
        observations: Vec::new(),
        facts: StoreFacts::default(),
        error: Some(cause),
    });
    if send(&frame, 2 * 1024 * 1024).is_ok() {
        0
    } else {
        1
    }
}
