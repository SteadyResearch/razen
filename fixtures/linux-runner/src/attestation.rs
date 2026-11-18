use crate::{
    Result, fail,
    lifecycle::{CGROUP, Cgroup},
    sandbox,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::SystemTime,
};
pub const METADATA: &str = "/usr/local/share/razen/provenance.json";
pub fn inspect() -> Result<Value> {
    // SAFETY: geteuid only reads the current process identity.
    if unsafe { libc::geteuid() } != 0 {
        return Err(fail(
            "trusted supervisor requires root outside workload UID",
        ));
    }
    let provenance = crate::wire::unique(&fs::read(METADATA)?)?;
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")?
        .trim()
        .to_owned();
    let version = fs::read_to_string("/etc/debian_version")?.trim().to_owned();
    let passwd = fs::read_to_string("/etc/passwd")?;
    let groups = fs::read_to_string("/etc/group")?;
    let dedicated = passwd.lines().any(|l| {
        l.starts_with("razen-workload:x:61000:61000:") && l.ends_with(":/usr/sbin/nologin")
    });
    let no_sudo = !groups
        .lines()
        .filter(|l| l.starts_with("sudo:") || l.starts_with("wheel:"))
        .any(|l| {
            l.split(':')
                .next_back()
                .unwrap_or("")
                .split(',')
                .any(|u| u == "razen-workload")
        });
    let checks = crate::wire::unique(&fs::read("/usr/local/share/razen/sudo-checks.json")?)?;
    let no_sudo = no_sudo
        && checks["healthy_exit"] == 0
        && checks["denied_exit"] == 1
        && checks["policy_exit"] == 1
        && checks["sudo_policy_sha256"] == sudo_policy_digest()?;
    let controllers = fs::read_to_string(Path::new(CGROUP).join("cgroup.controllers"))?;
    let subtree = fs::read_to_string(Path::new(CGROUP).join("cgroup.subtree_control"))?;
    let namespaces = fs::read_to_string("/proc/sys/user/max_user_namespaces")?
        .trim()
        .parse::<u64>()?
        > 0;
    let bwrap = std::process::Command::new("/usr/local/bin/bwrap")
        .arg("--version")
        .env_clear()
        .output()?;
    let bwrap_version = std::str::from_utf8(&bwrap.stdout)?.trim();
    let seccomp = fs::read("/usr/local/share/razen/seccomp.bpf")?;
    if seccomp != sandbox::seccomp_bytes()? {
        return Err(fail(
            "installed seccomp bytes differ from reviewed compiler output",
        ));
    }
    let package = sandbox::file_hash(Path::new("/usr/local/share/razen/packages.tsv"))?;
    let actual_status = sandbox::file_hash(Path::new("/var/lib/dpkg/status"))?;
    if fs::read_to_string("/usr/local/share/razen/dpkg-status.sha256")?.trim() != actual_status {
        return Err(fail("installed package database changed after preparation"));
    }
    let mut binaries = BTreeMap::new();
    for (name, path) in [
        ("supervisor", "/usr/local/libexec/razen-tool-supervisor"),
        (
            "adversary",
            "/usr/local/share/razen/runtime/razen-sandbox-adversary",
        ),
        ("bubblewrap", "/usr/local/bin/bwrap"),
    ] {
        binaries.insert(name, sandbox::file_hash(Path::new(path))?);
    }
    binaries.insert(
        "source",
        provenance["source_sha256"]
            .as_str()
            .ok_or_else(|| fail("source digest missing"))?
            .to_owned(),
    );
    let available = version == "13.7"
        && bwrap.status.success()
        && bwrap_version == "bubblewrap 0.13.1"
        && dedicated
        && no_sudo
        && namespaces
        && ["cpu", "memory", "pids"].iter().all(|c| {
            controllers.split_whitespace().any(|x| x == *c)
                && subtree.split_whitespace().any(|x| x == *c)
        });
    Ok(
        json!({"available":available,"owner_id":provenance["owner_id"],"guest_os":format!("Debian {version} arm64"),"gateway_ipv4":gateway()?,"ssh_host_key_sha256":sandbox::hash(fs::read_to_string("/etc/ssh/ssh_host_ed25519_key.pub")?.split_whitespace().take(2).collect::<Vec<_>>().join(" ").as_bytes()),"kernel_version":kernel,"bubblewrap_version":bwrap_version,"binary_digests":binaries,"seccomp_sha256":sandbox::hash(&seccomp),"package_manifest_sha256":package,"source_sha256":provenance["source_sha256"],"provisioning_sha256":provenance["provisioning_sha256"],"effective_config_sha256":provenance["configuration_sha256"],"profile_sha256":provenance["profile_sha256"],"dedicated_uid":dedicated,"no_sudo":no_sudo,"controllers":controllers.trim(),"subtree_control":subtree.trim(),"user_namespaces_available":namespaces}),
    )
}
pub fn gateway() -> Result<String> {
    let routes = fs::read_to_string("/proc/net/route")?;
    let value = routes
        .lines()
        .skip(1)
        .find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.get(1) == Some(&"00000000"))
                .then(|| fields.get(2).copied())
                .flatten()
        })
        .ok_or_else(|| fail("VM default gateway missing"))?;
    let raw = u32::from_str_radix(value, 16)?;
    Ok(std::net::Ipv4Addr::from(raw.to_le_bytes()).to_string())
}
pub fn attest(launch: &crate::wire::Launch, cgroup: &Cgroup, probe: &Value) -> Result<Value> {
    let installed = inspect()?;
    if installed["available"] != true || installed["profile_sha256"] != launch.profile_sha256 {
        return Err(fail(
            "current prepared guest/profile prerequisites unavailable",
        ));
    }
    let mut namespaces = serde_json::Map::new();
    for (name, linux) in [
        ("user", "user"),
        ("mount", "mnt"),
        ("pid", "pid"),
        ("ipc", "ipc"),
        ("uts", "uts"),
        ("network", "net"),
        ("cgroup", "cgroup"),
    ] {
        let manager = fs::read_link(format!("/proc/self/ns/{linux}"))?;
        let measured = probe["namespaces"][linux]
            .as_str()
            .ok_or_else(|| fail("workload namespace observation missing"))?;
        namespaces.insert(name.into(), json!(measured != manager.to_string_lossy()));
    }
    let status = probe["status"]
        .as_str()
        .ok_or_else(|| fail("filtered workload status missing"))?;
    let status_field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .map(str::trim)
    };
    let caps = status_field("CapEff:") == Some("0000000000000000")
        && status_field("CapPrm:") == Some("0000000000000000")
        && status_field("CapAmb:") == Some("0000000000000000");
    let uid = status_field("Uid:").is_some_and(|v| v.split_whitespace().all(|u| u == "61000"));
    let seccomp = status_field("Seccomp:") == Some("2");
    let nnp = status_field("NoNewPrivs:") == Some("1");
    let mountinfo = probe["mountinfo"]
        .as_str()
        .ok_or_else(|| fail("filtered workload mount observations missing"))?;
    let mount_line = |point: &str| {
        mountinfo
            .lines()
            .find(|l| l.split_whitespace().nth(4) == Some(point))
    };
    let readonly = |point: &str| {
        mount_line(point).is_some_and(|l| {
            l.split_whitespace()
                .nth(5)
                .is_some_and(|v| v.split(',').any(|x| x == "ro"))
        })
    };
    let bounded_tmpfs = mount_line("/tmp").is_some_and(|l| {
        l.contains(" - tmpfs ") && (l.contains("size=16384k") || l.contains("size=16777216"))
    });
    let no_management = ["/home", "/run", "/sys", "/var", "/Users", "/private"]
        .iter()
        .all(|point| mount_line(point).is_none());
    let environment = probe["environment"]
        .as_object()
        .is_some_and(|e| e.len() <= 1 && e.keys().all(|k| k == "PWD"));
    let descriptors = probe["descriptors"]
        .as_array()
        .ok_or_else(|| fail("descriptor observations missing"))?;
    let no_sockets = descriptors.iter().all(|d| {
        d["target"].as_str().is_some_and(|s| {
            !s.starts_with("socket:") && !s.contains("/var/lib") && !s.contains("/sys/fs/cgroup")
        })
    });
    let manager_outside = !fs::read_to_string(cgroup.path.join("cgroup.procs"))?
        .split_whitespace()
        .any(|p| p == cgroup.manager_pid.to_string());
    let limits = json!({"memory_max_bytes":read_limit(cgroup,"memory.max")?,"memory_swap_max_bytes":read_limit(cgroup,"memory.swap.max")?,"pids_max":read_limit(cgroup,"pids.max")?,"cpu_quota_us":100000,"cpu_period_us":100000,"tmpfs_max_bytes":if bounded_tmpfs{16777216}else{0},"file_descriptors_max":probe["rlimit_nofile"],"wall_deadline_ms":5000,"orphan_lease_ms":2000,"output_limit_bytes":2097152});
    let created_at = jiff::Timestamp::try_from(SystemTime::now())?;
    let nanos = created_at.subsec_nanosecond();
    let precision = if nanos == 0 {
        0
    } else if nanos % 1_000_000 == 0 {
        3
    } else if nanos % 1_000 == 0 {
        6
    } else {
        9
    };
    let attestation = json!({"attestation_id":launch.attestation_id,"run_id":launch.run_id,"backend":"lima-vz-plain-bubblewrap-cgroup-v2","manager_version":"2.3.0","image_digest":"sha512:255ed35957114b453d72cf021f70542d09dccbb9210640a220a4d0931fa80e1ea956785a7ca88b33d58b55dd4d00f0677b0016a14c99a168b6ed8e239ac98b09","kernel_version":installed["kernel_version"],"effective_config_sha256":installed["effective_config_sha256"],"provisioning_sha256":installed["provisioning_sha256"],"binary_digests":installed["binary_digests"],"seccomp_sha256":installed["seccomp_sha256"],"namespace_checks":namespaces,"controller_checks":{"cgroup_v2":Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),"memory":cgroup.path.join("memory.max").is_file(),"cpu":cgroup.path.join("cpu.max").is_file(),"pids":cgroup.path.join("pids.max").is_file()},"mount_checks":{"readonly_runtime":readonly("/runtime"),"readonly_inputs":readonly("/inputs"),"bounded_tmpfs":bounded_tmpfs,"no_host_mounts":no_management,"no_management":no_management,"private_proc":mount_line("/proc").is_some_and(|l|l.contains(" - proc "))},"socket_checks":{"no_inherited_sockets":no_sockets,"no_agent_forwarding":environment,"seccomp_socket_denied":seccomp},"uid_checks":{"dedicated_uid":uid,"no_sudo":installed["no_sudo"],"caps_empty":caps,"no_new_privileges":nnp,"manager_outside_cgroup":manager_outside,"placement_before_release":cgroup.placed_pid>0&&cgroup.placement_us>0},"observed_limits":limits,"created_at":format!("{:.*}",precision,created_at.display_with_offset(jiff::tz::Offset::UTC))});
    for map in [
        "namespace_checks",
        "controller_checks",
        "mount_checks",
        "socket_checks",
        "uid_checks",
    ] {
        if attestation[map]
            .as_object()
            .unwrap()
            .values()
            .any(|v| v != true)
        {
            return Err(fail("mandatory observed sandbox attestation check failed"));
        }
    }
    Ok(attestation)
}
fn read_limit(cgroup: &Cgroup, name: &str) -> Result<u64> {
    Ok(fs::read_to_string(cgroup.path.join(name))?.trim().parse()?)
}

/// Read only: active sudo controls are run exclusively by explicit preparation.
pub fn sudo_policy_digest() -> Result<String> {
    let mut paths = BTreeSet::new();
    for path in [
        "/etc/sudoers",
        "/etc/sudo.conf",
        "/etc/nsswitch.conf",
        "/etc/passwd",
        "/etc/group",
    ] {
        paths.insert(PathBuf::from(path));
    }
    for entry in fs::read_dir("/etc/sudoers.d")? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(fail("nonregular sudo policy include is forbidden"));
        }
        paths.insert(entry.path());
    }
    let nss = fs::read_to_string("/etc/nsswitch.conf")?;
    if nss
        .lines()
        .filter_map(|line| line.split('#').next())
        .filter_map(|line| line.trim().strip_prefix("sudoers:"))
        .any(|sources| sources.split_whitespace().ne(["files"]))
    {
        return Err(fail("external sudo policy providers are forbidden"));
    }
    if fs::read_to_string("/etc/sudo.conf")?.lines().any(|line| {
        let line = line.trim();
        !line.is_empty() && !line.starts_with('#')
    }) {
        return Err(fail("nondefault sudo plugins are forbidden"));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    for path in paths {
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(fail("sudo policy must be a regular owned file"));
        }
        let path_bytes = path.as_os_str().as_encoded_bytes();
        hash.update((path_bytes.len() as u64).to_le_bytes());
        hash.update(path_bytes);
        hash.update(metadata.uid().to_le_bytes());
        hash.update(metadata.gid().to_le_bytes());
        hash.update(metadata.mode().to_le_bytes());
        hash.update(metadata.len().to_le_bytes());
        if path == Path::new("/etc/sudoers") || path.parent() == Some(Path::new("/etc/sudoers.d")) {
            let policy = fs::read_to_string(&path)?;
            for line in policy.lines() {
                let line = line.trim();
                if (line.starts_with("@include") || line.starts_with("#include"))
                    && line != "@includedir /etc/sudoers.d"
                    && line != "#includedir /etc/sudoers.d"
                {
                    return Err(fail("sudo include escapes the pinned policy tree"));
                }
            }
            hash.update(policy.as_bytes());
        } else {
            let mut file = File::open(&path)?;
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                hash.update(&buffer[..n]);
            }
        }
    }
    Ok(hex::encode(hash.finalize()))
}
