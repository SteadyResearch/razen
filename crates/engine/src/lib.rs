pub mod adapters;
pub mod application;
pub mod domain;
pub mod ports;
pub mod protocol;

#[cfg(test)]
use adapters::transport::io as transport_io;

#[cfg(test)]
pub mod transport_test_fixtures {
    use crate as razen_engine;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/support/transport_fixtures.rs"
    ));
}
