"""Product CLI seams, kept independent of Rust business matrices."""
import json, os, sys, time, uuid
from t2_processes import subprocess
from pathlib import Path
from build_run import lease_fds
from t2_environment import run
from verification_result import require
ROOT=Path(__file__).resolve().parents[2]

def verify_migrations(container, binary, config, root, env):
    database=json.loads(config.read_text())["database"]["name"]
    def sql(statement):
        return run(["docker", "exec", "-i", container, "psql", "-At", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database], input=statement, capture_output=True, timeout=10).stdout.strip()
    def migrate(path=config, accepted=True):
        result = subprocess.run([binary,"migrate","--config",str(path)],pass_fds=lease_fds(), cwd=ROOT,env=env,capture_output=True,text=True,timeout=70)
        if (result.returncode == 0) != accepted:
            raise RuntimeError("migration admission/ledger expectation failed: " + result.stderr)
    admin = json.loads(config.read_text())
    (root/"admin-password").write_text("local-fixture"); os.chmod(root/"admin-password",0o600)
    admin["database"].update(user="postgres",password_file=str(root/"admin-password"))
    admin_config=root/"admin-migrate.json";admin_config.write_text(json.dumps(admin));os.chmod(admin_config,0o600)
    migrate(admin_config,accepted=False)
    require(sql("SELECT to_regclass('public.mdm_migrations') IS NULL") == "t", "rejected migrator performed DDL")
    migrate(); migrate()
    require(sql("SELECT to_regclass('mdm_access.audit') IS NULL") == "t", "retired product audit table was installed")
    original = sql("SELECT digest FROM public.mdm_migrations WHERE name='inventory-v1'")
    import hashlib
    require(original == hashlib.sha256((ROOT/'crates/inventory-postgres/migrations/0001_inventory.sql').read_bytes()).hexdigest(), "migration invariant rejected")
    for change in ["complete=false", "digest=repeat('0',64)"]:
        sql("UPDATE public.mdm_migrations SET " + change + " WHERE name='inventory-v1'")
        migrate(accepted=False)
        sql("UPDATE public.mdm_migrations SET complete=true,digest='" + original + "' WHERE name='inventory-v1'")
    # An owned holder makes both independent installers visibly wait before release.
    holder_name = 't2-holder-' + uuid.uuid4().hex
    holder = subprocess.Popen(["docker","exec","-e","PGAPPNAME="+holder_name,container,"psql","-U","postgres","-d",database,"-c","SELECT pg_advisory_lock(2346); SELECT pg_sleep(30)"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    holder_pid = 0
    children=[]
    try:
        deadline=time.monotonic()+5
        while sql("SELECT count(*) FROM pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND locktype='advisory' AND objid=2346 AND granted") != "1":
            if time.monotonic()>deadline: raise RuntimeError("migration lock holder deadline")
            time.sleep(.1)
        holder_pid = int(sql(f"SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name='{holder_name}'"))
        children=[subprocess.Popen([binary,"migrate","--config",str(config)],pass_fds=lease_fds(), cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(2)]
        deadline=time.monotonic()+5
        while sql("SELECT count(*) FROM pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND locktype='advisory' AND objid=2346 AND NOT granted") != "2":
            if time.monotonic()>deadline: raise RuntimeError("concurrent migrators did not serialize")
            time.sleep(.1)
        sql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND ({holder_pid}=0 OR pid={holder_pid}) AND application_name='{holder_name}'")
        for child in children:
            _,error=child.communicate(timeout=15)
            if child.returncode: raise RuntimeError("serialized migration failed: "+error)
        require(sql("SELECT count(*) FROM public.mdm_migrations WHERE complete") == str(len(json.loads(run([binary,"--describe"],capture_output=True).stdout)["units"])), "migration invariant rejected")
    finally:
        sql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND ({holder_pid}=0 OR pid={holder_pid}) AND application_name='{holder_name}'")
        holder.wait(timeout=5)
        for child in children:
            if child.poll() is None: child.terminate();child.wait(timeout=5)
    print("migration admission, immutable digest, interrupted ledger and concurrent installers passed",flush=True)

def execute(fixture):
    verify_migrations(fixture.owner.container(), fixture.binary, fixture.migration_config, fixture.root, fixture.env)
