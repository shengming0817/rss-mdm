#!/usr/bin/env python3
"""Three independently resolved adapters; shared test mechanics, no production facade."""
import functools,importlib.util,json,subprocess,tempfile
from pathlib import Path
import ci
from core_consumer import prepare_output
from group_postgres_consumer import run_consumer
spec=importlib.util.spec_from_file_location('backend_t2',Path(__file__).with_name('backend-t2.py'));pg=importlib.util.module_from_spec(spec);spec.loader.exec_module(pg)
def main():
    out=ci.ROOT/'artifacts'/'backend-consumers';prepare_output(out)
    head=ci.command(['/usr/bin/git','rev-parse','HEAD']).stdout.strip()
    ci.require(not ci.command(['/usr/bin/git','status','--porcelain']).stdout.strip(),'commit tested source before independent consumption')
    records=[]
    with tempfile.TemporaryDirectory(prefix='mdm-backend-consumers-',dir='/tmp') as directory:
        base=Path(directory).resolve();source=base/'source'
        subprocess.run(['/usr/bin/git','clone','--quiet','--no-hardlinks',str(ci.ROOT),str(source)],check=True,env=ci.noninteractive())
        subprocess.run(['/usr/bin/git','-C',str(source),'checkout','--quiet','--detach',head],check=True,env=ci.noninteractive())
        pin=ci.workspace_pin(source)
        for capability in pg.NAMES:
            output=out/capability;output.mkdir()
            for defaults in (True,False):
                try:
                    result=run_consumer(source,base/capability,defaults,head,pin,output,capability=capability,fixture=functools.partial(pg.fixture,source=source),config_key='BACKEND_PG_CONFIG',expected_tests=pg.CONSUMERS[capability])
                except Exception as error:result={'status':'failed','error':str(error),'head':head,'defaultFeatures':defaults}
                result['capability']=capability;records.append(result)
                print(json.dumps({k:v for k,v in result.items() if k not in {'features','commands','toolchain'}}),flush=True)
    (out/'result.json').write_text(json.dumps(records,indent=2)+'\n')
    return int(any(r['status']!='passed' for r in records))
if __name__=='__main__':raise SystemExit(main())
