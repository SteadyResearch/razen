use razen_runner_fixtures::{
    Result, adversaries, fail, sandbox,
    wire::{self, Direction, Role},
};
use serde_json::json;
use std::io::{BufRead, Read, Write};
fn main() {
    if let Err(error) = run() {
        eprintln!("sandbox fixture failed: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [mode, variant] if mode == "--gate" => {
            if !sandbox::FIXTURES.contains(&variant.as_str()) {
                return Err(fail("unknown approved workload"));
            }
            let probe = sandbox::probe()?;
            serde_json::to_writer(std::io::stdout(), &json!({"sandbox_probe":probe}))?;
            std::io::stdout().write_all(b"\n")?;
            std::io::stdout().flush()?;
            let mut release = [0u8; 1];
            std::io::stdin().read_exact(&mut release)?;
            if release != *b"R" {
                return Err(fail("sandbox hostile release gate mismatch"));
            }
            match variant.as_str() {
                "runtime" => runtime(false),
                "runtime_blocked" => runtime(true),
                _ => adversaries::parent_and_descendant(variant),
            }
        }
        [mode, variant] if mode == "--descendant" => adversaries::run(variant, "exec_descendant"),
        _ => Err(fail("unapproved workload arguments")),
    }
}
fn read_frame(reader: &mut impl BufRead) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Err(fail("runtime host input closed"));
        }
        let n = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |i| i + 1);
        if bytes.len() + n > wire::FRAME {
            return Err(fail("runtime frame bound"));
        }
        bytes.extend_from_slice(&available[..n]);
        reader.consume(n);
        if bytes.ends_with(b"\n") {
            return Ok(bytes);
        }
    }
}
fn send(kind: &str, payload: serde_json::Value, correlation: Option<&str>) -> Result<String> {
    let id = wire::new_id()?;
    let bytes = wire::encode_with_id(
        &id,
        kind,
        payload,
        correlation,
        Role::Runtime,
        Direction::PeerToHost,
    )?;
    std::io::stdout().write_all(&bytes)?;
    std::io::stdout().flush()?;
    Ok(id)
}
fn runtime(blocked: bool) -> Result<()> {
    let staged = std::fs::read("/inputs/snapshot")?;
    let expected = wire::decode(&staged, Role::Runtime, Direction::HostToPeer)?;
    if expected.kind != "start" {
        return Err(fail(
            "staged runtime program must be the existing public start envelope",
        ));
    }
    let fixture = wire::unique(&std::fs::read("/inputs/fixture.json")?)?;
    let origin = wire::number(&fixture["control_revision"])?;
    let input = std::io::stdin();
    let mut input = input.lock();
    let start_bytes = read_frame(&mut input)?;
    if start_bytes != staged {
        return Err(fail(
            "runtime start differs from the launch's immutable approved artifact",
        ));
    }
    let start = wire::decode(&start_bytes, Role::Runtime, Direction::HostToPeer)?;
    let began = std::time::Instant::now();
    let cpu_start = cpu_us()?;
    send(
        "started",
        json!({"capabilities":["brokered_calls","events","results","usage","cancellation","closure"]}),
        Some(&start.message_id),
    )?;
    let context = start.payload["context_refs"]
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| fail("runtime requires scoped investigation context reference"))?;
    if blocked {
        let references = vec![context.clone(); 128];
        let mut sequence = 0u64;
        loop {
            sequence += 1;
            send(
                "event",
                json!({"event_type":"blocked-runtime-output","source_control_revision":origin,"sequence":sequence,"data_refs":references}),
                Some(&start.message_id),
            )?;
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    if !start.payload["tool_ids"]
        .as_array()
        .is_some_and(|tools| tools.iter().any(|tool| tool == "context.read"))
    {
        return Err(fail(
            "context.read was not in the public start tool catalog",
        ));
    }
    let call = wire::new_id()?;
    let request_id = send(
        "tool_request",
        json!({"call_id":call,"tool_id":"context.read","tool_version":"0.1.0","input":{"kind":"investigation","record_id":context},"source_control_revision":origin}),
        Some(&start.message_id),
    )?;
    let mut completed = false;
    let mut host_messages = std::collections::BTreeMap::new();
    loop {
        let frame = read_frame(&mut input)?;
        let request = wire::decode(&frame, Role::Runtime, Direction::HostToPeer)?;
        let digest = razen_runner_fixtures::sandbox::hash(&frame);
        if let Some(previous) = host_messages.get(&request.message_id) {
            if previous != &digest {
                return Err(fail("host message ID changed immutable facts"));
            }
            continue;
        }
        if host_messages.len() == 256 {
            return Err(fail("bounded runtime host-message history exhausted"));
        }
        host_messages.insert(request.message_id.clone(), digest);
        match request.kind.as_str() {
            "tool_result" => {
                if completed
                    || request.payload["call_id"] != call
                    || request.correlation_id.as_deref() != Some(request_id.as_str())
                {
                    return Err(fail("terminal or cross-binding runtime call result"));
                }
                let usage = json!({"units":1,"bytes":start_bytes.len()+frame.len(),"cpu_us":cpu_us()?.saturating_sub(cpu_start),"elapsed_us":began.elapsed().as_micros()as u64});
                if request.payload["state"] != "completed"
                    || request.payload.get("output_ref").is_none()
                {
                    let mut result = json!({"state":"failed","source_control_revision":origin,"proposal_refs":[],"usage":usage});
                    if let Some(error) = request.payload.get("error") {
                        result["error"] = error.clone();
                    }
                    send("result", result, Some(&request.message_id))?;
                    completed = true;
                    continue;
                }
                send(
                    "event",
                    json!({"event_type":"runtime-context-consumed","source_control_revision":origin,"sequence":1,"data_refs":[request.payload["output_ref"]]}),
                    Some(&request.message_id),
                )?;
                send(
                    "result",
                    json!({"state":"completed","source_control_revision":origin,"proposal_refs":[],"usage":usage}),
                    Some(&request.message_id),
                )?;
                completed = true;
            }
            "cancel" => {
                if !completed {
                    send(
                        "result",
                        json!({"state":"cancelled","source_control_revision":origin,"proposal_refs":[],"usage":{"units":0,"bytes":start_bytes.len()+frame.len(),"cpu_us":cpu_us()?.saturating_sub(cpu_start),"elapsed_us":began.elapsed().as_micros()as u64}}),
                        Some(&request.message_id),
                    )?;
                    completed = true;
                }
            }
            "close" => {
                send("closed", json!({}), Some(&request.message_id))?;
                break;
            }
            _ => return Err(fail("unsupported runtime input lifecycle")),
        }
    }
    Ok(())
}
fn cpu_us() -> Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the timespec pointer is initialized and writable; this queries only this workload's CPU clock.
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut time) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(time.tv_sec as u64 * 1_000_000 + time.tv_nsec as u64 / 1000)
}
