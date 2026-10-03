"""One Python scenario inside the runner-owned, bounded process group."""
import importlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

from build_run import require_lease
from t2_environment import Environment
from t2_fixtures import RunFixtures
from t2_registry import MODULES
from t2_model import ROOT


def main(argv=None):
    module_id, payload = sys.argv[1:] if argv is None else argv
    require_lease(ROOT)
    module = MODULES[module_id]
    values = json.loads(Path(payload).read_text())
    values['root'] = Path(values['root'])
    if values['migration_config']:
        values['migration_config'] = Path(values['migration_config'])
    fixture = SimpleNamespace(**values, env=dict(os.environ), owner=Environment(group='t2'))
    print('START python/' + module_id, flush=True)
    scenario = importlib.import_module('t2_modules.' + module.python)
    if module.python == 'gateway':
        context = SimpleNamespace(gateway_owner=Environment(group='t2-gateway'))
        context.gateway = lambda config: RunFixtures.gateway(context, config)
        scenario.main(context)
    else:
        scenario.execute(fixture)
    print('PASS python/' + module_id, flush=True)


if __name__ == '__main__':
    main()
