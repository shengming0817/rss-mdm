"""Product CLI seams, kept independent of Rust business matrices."""
import json, os, sys, time, uuid
from t2_processes import subprocess
from pathlib import Path
from build_run import lease_fds
from t2_environment import run
from verification_result import require
ROOT=Path(__file__).resolve().parents[2]

def verify_startup_deadlines(binary, root, env):
    import socket
    config=json.loads((root/'runtime.json').read_text())
    runtime_password = config['runtime_database']['password_file']
    config['runtime_database']['password_file'] = str(root/'missing-runtime-password')
    invalid_runtime = root/'invalid-runtime.json'
    invalid_runtime.write_text(json.dumps(config)); invalid_runtime.chmod(0o600)
    result = subprocess.run([binary, 'serve', '--config', str(invalid_runtime)], pass_fds=lease_fds(), cwd=ROOT, env=env, capture_output=True, text=True, timeout=22)
    require(result.returncode != 0 and 'startup.runtime_database_configuration' in result.stderr,
            'runtime database input lost its startup stage: ' + result.stderr)
    config['runtime_database']['password_file'] = runtime_password
    secrets=['api-fixture','access-fixture','runtime-fixture','identity-runtime-fixture','identity-maintenance-fixture','o'*40]
    def verify(result, start, stage):
        require(result.returncode != 0 and time.monotonic()-start < 21, 'startup dependency stall escaped total budget')
        require(stage in result.stderr, 'startup failure lost safe stage classification: ' + result.stderr)
        require(all(secret not in result.stderr for secret in secrets), 'startup diagnostics exposed credentials')
    with socket.socket() as stalled:
        stalled.bind(('127.0.0.1',0));stalled.listen(8)
        stalled_port=stalled.getsockname()[1]
        for key in ['access_database','runtime_database']:
            config[key]['port']=stalled_port
        for key in ['database','publication_database']:
            config['flow']['storage' if key=='database' else 'publication']['database']['port']=stalled_port
        config['execution']['database']['port']=stalled_port
        config['identity']['database']['port']=stalled_port
        config['identity']['audit_worker']['port']=stalled_port
        path=root/'stalled.json';path.write_text(json.dumps(config));path.chmod(0o600)
        start=time.monotonic()
        result=subprocess.run([binary,'serve','--config',str(path)],pass_fds=lease_fds(), cwd=ROOT,env=env,capture_output=True,text=True,timeout=22)
        verify(result,start,'startup.access_store')
    # Keep the same physical PG identity required by production configuration.
    # This table is probed only by Identity; the earlier product stores remain healthy.
    container=env['MDM_TEST_PG_CONTAINER']
    def sql(statement):
        return run(['docker','exec',container,'psql','-X','-At','-v','ON_ERROR_STOP=1','-U','postgres','-d',config['access_database']['name'],'-c',statement],capture_output=True,timeout=5).stdout.strip()
    holder_name = 't2-holder-' + uuid.uuid4().hex
    holder=subprocess.Popen(['docker','exec','-e','PGAPPNAME='+holder_name,container,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d',config['access_database']['name'],'-c',
        'BEGIN; LOCK TABLE identity_authority.deployment IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(60); ROLLBACK;'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    holder_pid = 0
    child=None
    try:
        end=time.monotonic()+5
        while sql(f"SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING(pid) WHERE a.datname=current_database() AND a.application_name='{holder_name}' AND l.relation='identity_authority.deployment'::regclass AND l.mode='AccessExclusiveLock' AND l.granted") != '1':
            require(holder.poll() is None and time.monotonic()<end,'identity startup lock holder deadline')
            time.sleep(.1)
        holder_pid = int(sql(f"SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name='{holder_name}'"))
        start=time.monotonic()
        child=subprocess.Popen([binary,'serve','--config',str(root/'runtime.json')],pass_fds=lease_fds(), cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        end=time.monotonic()+8
        while sql("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename='mdm_identity_runtime' AND wait_event_type='Lock'") != '1':
            require(child.poll() is None and time.monotonic()<end,'startup did not reach the blocked Identity probe')
            time.sleep(.1)
        output,error=child.communicate(timeout=22)
        verify(subprocess.CompletedProcess(child.args,child.returncode,output,error),start,'startup.identity')
    finally:
        sql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND ({holder_pid}=0 OR pid={holder_pid}) AND application_name='{holder_name}'")
        holder.wait(timeout=5)
        if child is not None and child.poll() is None:
            child.terminate();child.communicate(timeout=10)
    print('database and Identity startup stalls rejected within budget with safe stage diagnostics',flush=True)

def execute(fixture):
    verify_startup_deadlines(fixture.binary, fixture.root, fixture.env)
