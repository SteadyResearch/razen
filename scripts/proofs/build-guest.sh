#!/bin/bash
# Explicit preparation only. No host sudo, host trust changes, default/shared Lima or repo mounts.
set -euo pipefail
umask 077
[ "$#" = 4 ]
[ "$1" = --confirm-provision ]
repo=$2
home=$3
state=$4
[ -f "$home/.razen-owner.json" ]
[ -f "$state/provenance.json" ]
[ "${#home}" -le 48 ]
export LIMA_HOME="$home" HOME="$home" PATH=/usr/bin:/bin:/usr/sbin:/sbin SSH=/usr/bin/ssh
unset SSH_AUTH_SOCK DISPLAY HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
manager="$repo/target/r0-tools/lima/2.3.0/bin/limactl"
archive="$repo/target/r0-tools/lima-2.3.0-Darwin-arm64.tar.gz"
printf '%s  %s\n' b7af444bd8f91d3c307477e562f2cf3bd7595d62b9429185e4fa841563578cfc "$archive" | shasum -a 256 --check --status
entry=$(tar -tf "$archive" | awk '/(^|\/)bin\/limactl$/ {print}')
[ -n "$entry" ]
[ "$(printf '%s\n' "$entry" | wc -l | tr -d ' ')" = 1 ]
archive_binary=$(tar -xOf "$archive" "$entry" | shasum -a 256 | awk '{print $1}')
installed_binary=$(shasum -a 256 "$manager" | awk '{print $1}')
[ "$archive_binary" = "$installed_binary" ]
[ "$("$manager" --version)" = 'limactl version 2.3.0' ]
[ ! -e "$home/_config/default.yaml" ]
[ ! -L "$home/_config/default.yaml" ]
[ ! -e "$home/_config/override.yaml" ]
[ ! -L "$home/_config/override.yaml" ]
[ ! -e "$home/_config/base.yaml" ]
[ ! -L "$home/_config/base.yaml" ]
image="$state/debian.raw"
if [ ! -f "$image" ]; then
  curl --fail --location --proto '=https' --tlsv1.2 https://cloud.debian.org/images/cloud/trixie/20261111-2659/debian-13-genericcloud-arm64-20261111-2659.raw -o "$image.partial"
  mv "$image.partial" "$image"
fi
printf '%s  %s\n' 255ed35957114b453d72cf021f70542d09dccbb9210640a220a4d0931fa80e1ea956785a7ca88b33d58b55dd4d00f0677b0016a14c99a168b6ed8e239ac98b09 "$image" | shasum -a 512 --check --status
chmod 0600 "$image"
if [ ! -f "$home/razen-r0/lima.yaml" ]; then
  "$manager" --tty=false create --name=razen-r0 --set ".images[0].location = \"$image\"" "$repo/scripts/proofs/lima.yaml"
  shasum -a 256 "$home/razen-r0/lima.yaml" > "$state/instance-yaml.sha256"
fi
[ -f "$state/instance-yaml.sha256" ]
shasum -a 256 --check --status "$state/instance-yaml.sha256"
[ ! -e "$state/preparation-stop.json" ]
[ ! -L "$state/preparation-stop.json" ]
chmod 0600 "$home/razen-r0/lima.yaml"
chmod 0700 "$home/razen-r0"
# The preparation lock is held by the host. Never adopt a previous unrecorded manager.
[ ! -e "$home/razen-r0/ha.pid" ]
[ ! -L "$home/razen-r0/ha.pid" ]
[ ! -e "$home/razen-r0/vz.pid" ]
[ ! -L "$home/razen-r0/vz.pid" ]
capture_preparation_stop() {
  /usr/bin/python3 - "$home" "$state" "$manager" "$installed_binary" <<'PY'
import hashlib,json,os,pathlib,stat,subprocess,sys
home,state,manager=map(pathlib.Path,sys.argv[1:4])
uid=os.geteuid()
def owned(path,cap,private=False):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or info.st_nlink!=1 or info.st_mode&(0o077 if private else 0o022) or info.st_size>cap:
            raise ValueError('Preparation identity is not an owned bounded regular file')
        with os.fdopen(fd,'rb',closefd=False) as source:
            value=source.read(cap+1)
        if len(value)>cap:
            raise ValueError('Preparation identity exceeds its bound')
        return value
    finally:
        os.close(fd)
owner=json.loads(owned(state/'owner.json',4096,True))
provenance=json.loads(owned(state/'provenance.json',4096,True))
home_owner=json.loads(owned(home/'.razen-owner.json',1024,True))
if owner['uid']!=uid or home_owner['uid']!=uid or owner['owner_id']!=home_owner['owner_id'] or owner['owner_id']!=provenance['owner_id'] or owner['profile_sha256']!=provenance['profile_sha256']:
    raise ValueError('Preparation ownership does not match the selected resource')
directory=home/'razen-r0'
def pid(name):
    value=owned(directory/name,32).strip()
    if not value.isdigit() or not 1<int(value)<=2147483647:
        raise ValueError('Preparation manager PID is invalid')
    return int(value)
host=pid('ha.pid')
if host!=pid('vz.pid'):
    raise ValueError('Preparation host agent and VZ driver identities differ')
boot=owned(directory/'boot-session.tmp',128).strip()
current=subprocess.check_output(['/usr/sbin/sysctl','-n','kern.bootsessionuuid'],timeout=1).strip()
if not boot or boot!=current:
    raise ValueError('Preparation manager belongs to another host boot')
process=subprocess.check_output(['/bin/ps','-ww','-p',str(host),'-o','pid=,uid=,lstart=,command='],timeout=1)
fields=process.split()
if len(process)>65536 or len(fields)<3 or fields[0]!=str(host).encode() or fields[1]!=str(uid).encode() or b' hostagent ' not in process or os.fsencode(directory/'ha.pid') not in process:
    raise ValueError('Preparation manager is not the observed dedicated host agent')
digest=hashlib.sha256()
with manager.open('rb') as source:
    for chunk in iter(lambda:source.read(65536),b''):
        digest.update(chunk)
manager_digest=digest.hexdigest()
if manager_digest!=sys.argv[4]:
    raise ValueError('Preparation manager changed after archive verification')
record={key:owner[key] for key in ('owner_id','run_id','uid','profile_sha256')}
record.update({key:provenance[key] for key in ('source_sha256','provisioning_sha256')})
record.update(manager_sha256=manager_digest,instance_yaml_sha256=hashlib.sha256(owned(directory/'lima.yaml',1048576)).hexdigest(),
              manager_identity={'pid':host,'birth_sha256':hashlib.sha256(process).hexdigest(),'boot_session_sha256':hashlib.sha256(boot).hexdigest()})
path=state/'preparation-stop.json'
if path.exists() or path.is_symlink():
    if json.loads(owned(path,16384,True))!=record:
        raise ValueError('A different preparation manager is already recorded')
else:
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as destination:
        destination.write(json.dumps(record,separators=(',',':')).encode())
        destination.flush()
        os.fsync(destination.fileno())
    fd=os.open(state,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
PY
}
preparation_exit() {
  result=$?
  trap - EXIT
  if [ "$result" -ne 0 ]; then
    capture_preparation_stop || printf '%s\n' 'Partial preparation has no verified stop authority; cleanup must fail closed.' >&2
  fi
  exit "$result"
}
trap preparation_exit EXIT
"$manager" --tty=false start razen-r0
capture_preparation_stop
shasum -a 256 "$home/razen-r0/lima.yaml" > "$state/instance-yaml.sha256"
# Explicit closed subset; never archive the repository or executable cargo configuration.
tar -cf "$state/source.tar" -C "$repo" fixtures/linux-runner/Cargo.toml fixtures/linux-runner/Cargo.lock fixtures/linux-runner/src
"$manager" --tty=false copy --backend=scp "$state/source.tar" razen-r0:/tmp/razen-source.tar
"$manager" --tty=false copy --backend=scp "$repo/scripts/proofs/provision-guest.sh" razen-r0:/tmp/razen-provision.sh
# Resolve effective config only after creation; preserve only its digest in guest provenance.
"$manager" template yq "$home/razen-r0/lima.yaml" '. | @json' > "$state/effective.json"
/usr/bin/python3 - "$state" <<'PY'
import hashlib,json,pathlib,sys
state=pathlib.Path(sys.argv[1])
v=json.loads((state/'effective.json').read_bytes())
# Match serde_json's sorted-map compact serialization used by the host.
b=json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
p=json.loads((state/'provenance.json').read_bytes())
p['configuration_sha256']=hashlib.sha256(b).hexdigest()
p['upload_sha256']=hashlib.sha256((state/'source.tar').read_bytes()).hexdigest()
(state/'provenance.json').write_text(json.dumps(p,separators=(',',':')))
PY
"$manager" --tty=false copy --backend=scp "$state/provenance.json" razen-r0:/tmp/razen-provenance.json
if ! "$manager" --tty=false shell --start=false --preserve-env=false --workdir=/ razen-r0 sudo -n /bin/bash /tmp/razen-provision.sh --confirm-provision > "$state/provision.log" 2>&1; then cat "$state/provision.log" >&2; exit 1; fi
"$manager" --tty=false shell --start=false --preserve-env=false --workdir=/ razen-r0 sudo -n /usr/local/libexec/razen-tool-supervisor --inspect > "$state/guest-inspect.json"
"$manager" --tty=false shell --start=false --preserve-env=false --workdir=/ razen-r0 sudo -n /usr/local/libexec/razen-tool-supervisor --host-public-key > "$state/ssh-host-public-key"
# Export only the fixed root-owned package capture tree; no workload/credential/repository paths.
"$manager" --tty=false shell --start=false --preserve-env=false --workdir=/ razen-r0 sudo -n tar -C /var/lib/razen/dependency-captures -cf - guest-packages > "$state/guest-dependency-captures.tar"
/usr/bin/python3 - "$state" <<'PY'
import pathlib,re,shutil,sys,tarfile
state=pathlib.Path(sys.argv[1])
archive=state/'guest-dependency-captures.tar'
if archive.stat().st_size > 128*1024*1024:
    raise SystemExit('Guest package capture archive exceeds its bound')
with tarfile.open(archive,'r:') as source:
    members=source.getmembers()
    if len(members)>4096 or sum(member.size for member in members)>128*1024*1024:
        raise SystemExit('Guest package capture entries exceed their bound')
    seen=set()
    for member in members:
        name=member.name.rstrip('/')
        if name in seen:
            raise SystemExit('Duplicate guest package capture entry')
        seen.add(name)
        if member.isdir() and name=='guest-packages':
            continue
        if not member.isfile() or member.size>16*1024*1024 or not re.fullmatch(
            r'guest-packages/(?:[a-z0-9][a-z0-9+.-]*\.(?:arm64|all)\.(?:copyright|policy|metadata|facts\.json|uri)|packages\.tsv|checked-at\.txt)',name):
            raise SystemExit('Unexpected guest package capture entry')
        if name.endswith('.uri') and not 1 <= member.size <= 4096:
            raise SystemExit('Guest package repository URI capture exceeds its bound')
    if not {'guest-packages/packages.tsv','guest-packages/checked-at.txt'} <= seen:
        raise SystemExit('Required guest package capture metadata is absent')
    target=state/'guest-dependency-captures'
    target.mkdir(mode=0o700)
    (target/'guest-packages').mkdir(mode=0o700)
    for member in members:
        if member.isdir():
            continue
        stream=source.extractfile(member)
        if stream is None:
            raise SystemExit('Guest package capture body is absent')
        with stream, (target/member.name).open('xb') as destination:
            shutil.copyfileobj(stream,destination,16*1024)
PY
