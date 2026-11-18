mod bindings;
#[cfg(any(feature = "fixture-valid", feature = "fixture-host-call"))]
use bindings::razen::component_proof::snapshot_reader;
#[cfg(any(feature = "fixture-valid", feature = "fixture-denied-access"))]
use bindings::razen::component_proof::types::ErrorCode;
use bindings::razen::component_proof::types::{InvocationContext, Observation, SdkError};

const _: () = assert!(
    (cfg!(feature = "fixture-valid") as u8
        + cfg!(feature = "fixture-loop") as u8
        + cfg!(feature = "fixture-grow") as u8
        + cfg!(feature = "fixture-output") as u8
        + cfg!(feature = "fixture-host-call") as u8
        + cfg!(feature = "fixture-denied-access") as u8)
        == 1,
    "select exactly one reviewed component fixture feature"
);

struct Fixture;
impl bindings::exports::razen::component_proof::passive_check::Guest for Fixture {
    fn analyze(context: InvocationContext) -> Result<Vec<Observation>, SdkError> {
        #[cfg(any(feature = "fixture-loop", feature = "fixture-grow"))]
        drop(context);
        #[cfg(feature = "fixture-loop")]
        {
            let mut counter = 0_u64;
            loop {
                counter = std::hint::black_box(counter.wrapping_add(1));
            }
        }
        #[cfg(feature = "fixture-grow")]
        {
            let mut allocations = Vec::new();
            loop {
                // A single allocation requests more than the 64MiB Store ceiling,
                // before the guest can burn its fuel touching smaller blocks.
                let block = vec![std::hint::black_box(42_u8); 128 * 1024 * 1024];
                allocations.push(block);
                std::hint::black_box(&allocations);
            }
        }
        #[cfg(feature = "fixture-output")]
        {
            let invalid = Observation {
                rule_id: "fixture.invalid".into(),
                title: "invalid range".into(),
                snapshot: context.snapshot,
                range_start: u64::MAX,
                range_end: 0,
            };
            return Ok(vec![invalid; 4096]);
        }
        #[cfg(feature = "fixture-denied-access")]
        {
            let outcomes = [
                ("filesystem", std::fs::read("/etc/passwd").is_err()),
                (
                    "socket",
                    std::net::TcpListener::bind("127.0.0.1:0").is_err(),
                ),
                ("environment", std::env::var("HOME").is_err()),
                (
                    "credential",
                    std::env::var("RAZEN_FIXTURE_CREDENTIAL").is_err()
                        && std::fs::read("/razen-private-credential").is_err(),
                ),
            ];
            return outcomes
                .into_iter()
                .map(|(resource, denied)| {
                    if !denied {
                        return Err(SdkError {
                            code: ErrorCode::OutputInvalid,
                            message: "unexpected capability disclosed".into(),
                        });
                    }
                    Ok(Observation {
                        rule_id: format!("fixture.denied.{resource}"),
                        title: "access denied".into(),
                        snapshot: context.snapshot.clone(),
                        range_start: 0,
                        range_end: 0,
                    })
                })
                .collect();
        }
        #[cfg(feature = "fixture-host-call")]
        {
            loop {
                // Withheld trusted body-source bytes exercise the independent
                // host deadline; an unblocked broker must still cap repeats.
                std::hint::black_box(snapshot_reader::read_body(&context.snapshot, 0, 1)?);
            }
        }
        #[cfg(feature = "fixture-valid")]
        {
            let mut offset = 0;
            let mut observed = Vec::new();
            while offset < context.snapshot.length_bytes {
                let count = (context.snapshot.length_bytes - offset).min(16) as u32;
                let chunk = snapshot_reader::read_body(&context.snapshot, offset, count)?;
                if chunk.is_empty() {
                    return Err(SdkError {
                        code: ErrorCode::InvalidInput,
                        message: "unexpected empty snapshot chunk".into(),
                    });
                }
                offset += chunk.len() as u64;
                observed.extend_from_slice(&chunk);
            }
            let title = if observed.windows(5).any(|bytes| bytes == b"Razen") {
                "public passive marker"
            } else {
                "public passive bytes"
            };
            Ok(vec![Observation {
                rule_id: "fixture.passive".into(),
                title: title.into(),
                snapshot: context.snapshot,
                range_start: 0,
                range_end: offset,
            }])
        }
    }
}
bindings::export!(Fixture with_types_in bindings);
