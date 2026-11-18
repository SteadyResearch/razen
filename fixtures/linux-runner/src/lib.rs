#![cfg(all(target_os = "linux", target_arch = "aarch64"))]
//! Linux-only trusted syscall boundary. Unsafe calls are confined to reviewed syscall wrappers.
pub mod adversaries;
pub mod attestation;
pub mod lifecycle;
pub mod sandbox;
pub mod wire;
pub type Result<T, E = Box<dyn std::error::Error + Send + Sync>> = std::result::Result<T, E>;
pub fn fail(message: &str) -> Box<dyn std::error::Error + Send + Sync> {
    std::io::Error::other(message.to_owned()).into()
}
