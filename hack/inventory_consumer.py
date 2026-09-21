#!/usr/bin/env python3
"""Fixed-HEAD Inventory/core and PG adapter consumers, outside both workspaces."""
import importlib.util,json,hashlib,subprocess,tempfile
from pathlib import Path
import ci
from core_consumer import isolated_env,check_ancestors,prepare_output
spec=importlib.util.spec_from_file_location('inventory_pg_fixture',Path(__file__).with_name('backend-t2.py'))
pg=importlib.util.module_from_spec(spec);spec.loader.exec_module(pg)
def run(source,base,kind,head,pin,out,defaults):
    product='rss-mdm-inventory'+('-postgres' if kind=='pg' else '')
    root=base/(kind+('-default' if defaults else '-minimal'));(root/'tests').mkdir(parents=True)
    check_ancestors(root)
    (root/".cargo").mkdir()
    (root/".cargo/config.toml").write_text("[net]\ngit-fetch-with-cli = true\n")
    (root/'rust-toolchain.toml').write_bytes((source/'rust-toolchain.toml').read_bytes())
    (root/'Cargo.lock').write_bytes((source/'Cargo.lock').read_bytes())
    package=f'git = "{source.as_uri()}", rev = "{head}", default-features = {str(defaults).lower()}'
    deps=f'{product} = {{ {package} }}\n'
    if kind=='pg':
        deps+=f'rss-request-context = {{ git="{pin[0]}", rev="{pin[1]}", default-features=false }}\n'
        import tomllib
        shared=tomllib.loads((source/'Cargo.toml').read_text())['workspace']['dependencies']
        deps+='sqlx = '+json.dumps(shared['sqlx']).replace(': ', ' = ')+'\n'
        # TOML inline tables use bare quoted keys and commas; explicit necessary async/JSON test support.
        deps+='tokio = {version="1",features=["macros","rt-multi-thread"]}\nserde_json = "1"\n'
        test=source/'crates/inventory-postgres/tests/consumer.rs'
    else:test=source/'crates/inventory/tests/assets.rs'
    (root/'Cargo.toml').write_text('[workspace]\n[package]\nname="inventory-consumer"\nversion="0.0.0"\nedition="2024"\n[dependencies]\n'+deps)
    (root/'tests/consumer.rs').write_bytes(test.read_bytes())
    env=isolated_env(base)
    log=[]
    def command(args,extra=None):
        result=subprocess.run(args,cwd=root,env={**env,**(extra or {})},text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        log.append('$ '+' '.join(args)+'\n'+result.stdout+result.stderr)
        (out/f'{kind}-{defaults}.log').write_text('\n'.join(log))
        ci.require(result.returncode==0,f'{product} command failed')
        return result.stdout
    data=json.loads(command(['cargo','metadata','--format-version','1']))
    packages={p['id']:p for p in data['packages']};nodes={n['id']:n for n in data['resolve']['nodes']};ident=data['resolve']['root']
    allowed={product,'rss-mdm-inventory'}
    for key,p in packages.items():
        if key==ident:continue
        if p['name'].startswith('rss-mdm-'):
            ci.require(p['name'] in allowed and p['source']==f'git+{source.as_uri()}?rev={head}#{head}','foreign product dependency')
        elif p['name'].startswith('rss-'):
            ci.require(p['source']==f'git+{pin[0]}?rev={pin[1]}#{pin[1]}','RSS pin differs')
        else:ci.require(p['source']=='registry+https://github.com/rust-lang/crates.io-index','unexpected dependency source')
    direct={packages[d['pkg']]['name'] for d in nodes[ident]['deps']}
    ci.require(direct==({product,'rss-request-context','sqlx','tokio','serde_json'} if kind=='pg' else {product}),'consumer supplements product dependency')
    tree=command(['cargo','tree','--locked','-e','features']);(out/f'{kind}-{defaults}-tree.txt').write_text(tree)
    (out/f'{kind}-{defaults}-metadata.json').write_text(json.dumps(data))
    command(['cargo','check','--locked'])
    if kind=='pg':
        with pg.fixture(source=source,app=True) as(fixture,_):
            result=command(['cargo','test','--locked','--test','consumer','--','--ignored'],{'BACKEND_PG_CONFIG':fixture['BACKEND_PG_CONFIG']})
            pg.verify_tests(result,{'public_manual_cas_rollback_and_tenant_isolation'})
    else:
        result=command(['cargo','test','--locked','--test','consumer'])
        ci.require('test result: ok. 3 passed; 0 failed; 0 ignored;' in result,'inventory behavior proof missing')
    return {'head':head,'package':product,'defaultFeatures':defaults,'rssRevision':pin[1],'lockSha256':hashlib.sha256((root/'Cargo.lock').read_bytes()).hexdigest(),'status':'passed'}
def main():
    out=ci.OUT/'inventory-consumers';prepare_output(out)
    ci.require(not ci.command(['/usr/bin/git','status','--porcelain']).stdout.strip(),'commit implementation before isolated proof')
    head=ci.command(['/usr/bin/git','rev-parse','HEAD']).stdout.strip();results=[]
    with tempfile.TemporaryDirectory(prefix='mdm-inventory-consumer-',dir='/tmp') as d:
        base=Path(d);source=base/'source'
        subprocess.run(['/usr/bin/git','clone','--quiet','--no-hardlinks',str(ci.ROOT),str(source)],check=True,env=ci.noninteractive())
        subprocess.run(['/usr/bin/git','-C',str(source),'checkout','--quiet','--detach',head],check=True,env=ci.noninteractive())
        pin=ci.workspace_pin(source)
        for kind in ('core','pg'):
            for defaults in (True,False):
                try:result=run(source,base,kind,head,pin,out,defaults)
                except Exception as error:result={'head':head,'kind':kind,'defaultFeatures':defaults,'status':'failed','error':str(error)}
                results.append(result);print(json.dumps(result),flush=True)
    (out/'result.json').write_text(json.dumps(results,indent=2)+'\n')
    return int(any(r['status']!='passed' for r in results))
if __name__=='__main__':raise SystemExit(main())
