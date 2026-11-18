wasmtime::component::bindgen!({
    path: "../../specs/001-r0-feasibility/contracts/plugin-sdk.wit",
    world: "passive-proof",
    require_store_data_send: true,
    additional_derives: [serde::Serialize, serde::Deserialize],
});
pub use razen::component_proof::types::{InvocationContext, Observation, SnapshotReference};
