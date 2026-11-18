use super::{invalid, runner::ResourceProbe};
use crate::application::profile::ComponentProfile;
use crate::protocol::error::ProofResult;
use wasmtime::{
    Engine, Instance, Memory, MemoryType, Module, Ref, RefType, Store, StoreLimitsBuilder, Table,
    TableType,
};

/// Trusted native probes exercise Wasmtime's actual per-Store allocation paths;
/// they run inside the already admitted native runner, never as proof substitutes
/// for the separately executed hostile guest.
pub(super) fn probe(engine: &Engine, limits: &ComponentProfile) -> ProofResult<Vec<ResourceProbe>> {
    // Tiny reviewed modules, not a custom Wasm encoder: the real engine validates them.
    const EMPTY: &[u8] = b"\0asm\x01\0\0\0";
    const MEMORY: &[u8] = b"\0asm\x01\0\0\0\x05\x03\x01\x00\x00";
    const TABLE: &[u8] = b"\0asm\x01\0\0\0\x04\x04\x01\x70\x00\x00";
    let mut probes = Vec::with_capacity(5);
    for resource in [
        "linear_memory_bytes",
        "table_elements",
        "instances",
        "memories",
        "tables",
    ] {
        let configured = StoreLimitsBuilder::new()
            .memory_size(limits.linear_memory_bytes.get() as usize)
            .table_elements(limits.table_elements.get() as usize)
            .instances(limits.instances.get() as usize)
            .memories(limits.memories.get() as usize)
            .tables(limits.tables.get() as usize)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(engine, configured);
        store.limiter(|state| state);
        let (limit, requested, denied) = match resource {
            "linear_memory_bytes" => {
                let pages = limits.linear_memory_bytes.get() / 65536 + 1;
                (
                    limits.linear_memory_bytes.get(),
                    pages * 65536,
                    Memory::new(&mut store, MemoryType::new(pages as u32, None)).is_err(),
                )
            }
            "table_elements" => (
                limits.table_elements.get(),
                limits.table_elements.get() + 1,
                Table::new(
                    &mut store,
                    TableType::new(
                        RefType::FUNCREF,
                        limits.table_elements.get() as u32 + 1,
                        None,
                    ),
                    Ref::Func(None),
                )
                .is_err(),
            ),
            _ => {
                // Host-created Memory/Table handles do not consume guest module counts.
                let (limit, bytes) = match resource {
                    "instances" => (limits.instances.get(), EMPTY),
                    "memories" => (limits.memories.get(), MEMORY),
                    _ => (limits.tables.get(), TABLE),
                };
                let module = Module::new(engine, bytes).map_err(|_| invalid())?;
                for _ in 0..limit {
                    Instance::new(&mut store, &module, &[]).map_err(|_| invalid())?;
                }
                (
                    limit,
                    limit + 1,
                    Instance::new(&mut store, &module, &[]).is_err(),
                )
            }
        };
        probes.push(ResourceProbe {
            resource: resource.into(),
            requested,
            limit,
            denied,
        });
    }
    Ok(probes)
}
