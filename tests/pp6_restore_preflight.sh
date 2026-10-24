#!/usr/bin/env bash
# Disposable process evidence, not installed-release/HSM/independent-host qualification.
set -euo pipefail
if [[ ${PP6_PREFLIGHT_INNER:-0} != 1 ]]; then
    exec env PP6_PREFLIGHT_INNER=1 pg_virtualenv "$0"
fi
[[ ${PGVERSION:-} == 16 ]] || exit 2
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
: "${O3K_D10_TEST_IMAGE:?supply an explicitly provisioned postgres:16 digest pin}"
WORK=$(mktemp -d)
chmod 0700 "$WORK"
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$ROOT/target"}
O3K_D10_TEST_EXPORT_DIR="$WORK" cargo test -p o3k --lib restore_pg_validation::tests::real_pg16_ -- --ignored --nocapture > "$WORK/d10.log" 2>&1
sed -n '/^D10 /p' "$WORK/d10.log"
cargo build -p o3k > "$WORK/build.log" 2>&1
BIN="$CARGO_TARGET_DIR/debug/o3k"
psql -X -q -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE o3k_restore_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE DATABASE o3k_fresh OWNER o3k_restore_owner;
REVOKE ALL ON DATABASE o3k_fresh FROM PUBLIC;
SQL
psql -X -q -v ON_ERROR_STOP=1 -d o3k_fresh -c 'REVOKE ALL ON SCHEMA public FROM PUBLIC'
# Narrow admission on this owned disposable cluster only; no independent D4
# ingress/fencing claim is made by a loopback HBA fixture.
HBA=$(psql -X -qAt -c 'SHOW hba_file')
python3 - "$HBA" <<'HBA_PY'
import sys
p=sys.argv[1]
old=open(p).read()
open(p,'w').write('host o3k_fresh o3k_restore_owner 127.0.0.1/32 trust\n'+old)
HBA_PY
psql -X -qAt -c 'SELECT pg_reload_conf()' > /dev/null
psql -X -qAt -h 127.0.0.1 -U o3k_restore_owner -d o3k_fresh -c 'SELECT 1' > /dev/null
# Only the recovery orchestrator receives the Docker socket. D10 children have
# no socket, network, host mounts, credentials, or target URL.
python3 - "$WORK" "$BIN" "$PGPORT" "$O3K_D10_TEST_IMAGE" <<'PYCODE'
import json,subprocess,sys,uuid,shutil,hashlib,os
work,binary,port,image=sys.argv[1:]
name='o3k-recovery-test-'+str(uuid.uuid4())
volume=name+'-ext4'
def call(args,**kwargs):
 return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,**kwargs).stdout
def execute(*args): return call(['docker','exec',name,*args])
def copy(source,dest): call(['docker','cp',source,name+':'+dest])
try:
 call(['docker','volume','create',volume])
 call(['docker','run','-d','--pull=never','--name',name,'--network=host','--user=0',
       '--mount','type=volume,source='+volume+',target=/recovery',
       '--mount','type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock',
       '--entrypoint=sleep',image,'600'])
 execute('groupadd','-g','985','o3k')
 execute('useradd','-u','994','-g','985','-M','-s','/usr/sbin/nologin','o3k')
 execute('mkdir','-p','/usr/local/etc/o3k','/usr/local/share/o3k','/etc/o3k','/var/lib/o3k',
         '/recovery/target','/recovery/staging')
 execute('chown','994:985','/var/lib/o3k','/recovery/target','/recovery/staging')
 execute('chmod','700','/var/lib/o3k','/recovery/target','/recovery/staging')
 copy(binary,'/usr/local/bin/o3k')
 copy(shutil.which('docker'),'/usr/local/bin/docker')
 copy(work+'/artifact.o3k','/artifact.o3k')
 copy(work+'/recipient.key','/etc/o3k/recipient.key')
 copy(work+'/release-manifest.json','/usr/local/share/o3k/release-manifest.json')
 trust=json.load(open(work+'/backup-trust.json'))
 trust['recipient']['x25519_private_key_file']='/etc/o3k/recipient.key'
 json.dump(trust,open(work+'/trust.json','w'))
 config={'format':'o3k-restore-preflight-v1','backend':'postgresql',
  'target_directory':'/recovery/target','recovery_directory':'/recovery/staging',
  'postgres':{'database_url':f'postgresql://o3k_restore_owner@127.0.0.1:{port}/o3k_fresh',
              'validation_image':image}}
 json.dump(config,open(work+'/restore.json','w'))
 copy(work+'/trust.json','/etc/o3k/backup-trust.json')
 copy(work+'/restore.json','/usr/local/etc/o3k/restore.json')
 execute('chown','0:0','/usr/local/etc/o3k/restore.json','/usr/local/share/o3k/release-manifest.json','/etc/o3k/recipient.key','/usr/local/bin/o3k','/usr/local/bin/docker')
 execute('chown','0:985','/etc/o3k/backup-trust.json')
 execute('chmod','640','/etc/o3k/backup-trust.json')
 execute('chmod','600','/etc/o3k/recipient.key','/usr/local/etc/o3k/restore.json')
 execute('chmod','644','/usr/local/share/o3k/release-manifest.json')
 command=['docker','exec',name,'o3k','restore','preflight','--artifact','/artifact.o3k','--target','/recovery/target']
 def preflight(code,reason=None):
  result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=240)
  assert result.returncode==code,(result.returncode,result.stdout,result.stderr)
  assert len(result.stdout)<4096
  data=json.loads(result.stdout)
  assert data['activation_authorized'] is False
  if reason: assert data['reason']==reason,data
  return data
 # A root-owned manifest is insufficient when an ancestor is replaceable.
 execute('chmod','777','/usr/local/share')
 preflight(2,'expected-release-untrusted')
 execute('chmod','755','/usr/local/share')
 print('PASS writable release ancestor rejected',flush=True)
 before=call(['psql','-X','-qAt','-d','postgres','-c','SELECT oid,datname,datdba,datacl FROM pg_database ORDER BY oid'])
 result=preflight(0)
 assert result['status']=='preflighted' and result['target_mutated'] is False
 assert not execute('ls','-A','/recovery/target').strip()
 assert not execute('ls','-A','/recovery/staging').strip()
 assert call(['psql','-X','-qAt','-d','o3k_fresh','-c',"SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'"]).strip()==b'0'
 print('PASS real CLI signed fixture preflight; selected files/database unchanged; activation denied',flush=True)
 print(json.dumps(result,sort_keys=True),flush=True)
 # Foreign principals must not retain schema-creation authority on the target.
 call(['psql','-X','-q','-v','ON_ERROR_STOP=1','-c','CREATE ROLE foreign_creator; GRANT CREATE ON DATABASE o3k_fresh TO foreign_creator'])
 preflight(2,'target-owner-policy-rejected')
 call(['psql','-X','-q','-v','ON_ERROR_STOP=1','-c','REVOKE CREATE ON DATABASE o3k_fresh FROM foreign_creator; DROP ROLE foreign_creator'])
 print('PASS foreign target CREATE privilege rejected',flush=True)
 # A foreign object in the selected DB must survive rejection unchanged.
 call(['psql','-X','-q','-v','ON_ERROR_STOP=1','-d','o3k_fresh','-c',"CREATE TABLE public.foreign_sentinel(value text); INSERT INTO public.foreign_sentinel VALUES ('unchanged')"])
 preflight(2,'target-database-not-empty')
 assert call(['psql','-X','-qAt','-d','o3k_fresh','-c','SELECT value FROM public.foreign_sentinel']).strip()==b'unchanged'
 call(['psql','-X','-q','-v','ON_ERROR_STOP=1','-d','o3k_fresh','-c','DROP TABLE public.foreign_sentinel'])
 execute('sh','-c','printf pending > /recovery/staging/denial-marker')
 preflight(2,'recovery-state-present')
 assert execute('cat','/recovery/staging/denial-marker')==b'pending'
 execute('rm','/recovery/staging/denial-marker')
 trust['revoked_key_ids']=['test-signing-key']
 json.dump(trust,open(work+'/trust.json','w'))
 copy(work+'/trust.json','/etc/o3k/backup-trust.json')
 execute('chown','0:985','/etc/o3k/backup-trust.json')
 execute('chmod','640','/etc/o3k/backup-trust.json')
 preflight(2,'revoked-signing-key')
 trust['revoked_key_ids']=[]
 json.dump(trust,open(work+'/trust.json','w'))
 copy(work+'/trust.json','/etc/o3k/backup-trust.json')
 execute('chown','0:985','/etc/o3k/backup-trust.json')
 execute('chmod','640','/etc/o3k/backup-trust.json')
 print('PASS foreign selected-DB object, pending recovery state and signer revocation denials',flush=True)
 execute('sh','-c','printf foreign > /recovery/target/sentinel')
 preflight(2,'target-not-empty')
 assert execute('cat','/recovery/target/sentinel')==b'foreign'
 execute('rm','/recovery/target/sentinel')
 execute('sh','-c','printf x >> /artifact.o3k')
 preflight(2,'corrupt-artifact')
 assert not execute('ls','-A','/recovery/target').strip()
 assert not execute('ls','-A','/recovery/staging').strip()
 after=call(['psql','-X','-qAt','-d','postgres','-c','SELECT oid,datname,datdba,datacl FROM pg_database ORDER BY oid'])
 assert before==after
 print('PASS nonempty/corrupt artifact denials; foreign database catalog unchanged',flush=True)
 print('source_sha='+call(['git','rev-parse','HEAD']).decode().strip(),flush=True)
 print('postgres_tools='+call(['pg_restore','--version']).decode().strip(),flush=True)
 print('validation_image='+image,flush=True)
 print('harness_sha256='+hashlib.sha256(open('tests/pp6_restore_preflight.sh','rb').read()).hexdigest(),flush=True)
finally:
 subprocess.run(['docker','rm','-f','-v',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 subprocess.run(['docker','volume','rm',volume],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
PYCODE
