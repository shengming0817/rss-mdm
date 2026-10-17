"""Purpose-separated native bootstrap fixtures; protocol producers use real keys/TLS."""
import base64
import copy
import json
import secrets
from pathlib import Path
from t2_environment import private


def configure(root, value, env):
    agent = value['agent_pki']
    trust = json.loads(Path(agent['trust_file']).read_text())
    trust['purpose'] = 'agent_bootstrap'
    for issuer in trust['issuers']:
        issuer['provisioner'] = 'rss-agent-bootstrap'
        issuer['kid'] = ''
    trust_path = private(root / 'agent-bootstrap-trust.json', trust)
    configuration = dict(trust_file=str(trust_path))
    for phase in ('challenge', 'notify'):
        configuration[phase + '_id'] = 'bootstrap-' + phase
        configuration[phase + '_key_file'] = str(private(root / ('bootstrap-' + phase + '.key'), base64.b64encode(secrets.token_bytes(32)).decode()))
    agent['bootstrap'] = configuration
    original = next(p for p in value['device_pki'] if p['purpose'] == 'agent' and p['issuer'] == trust['issuers'][0]['digest'])
    provider = copy.deepcopy(original)
    provider.update(purpose='agent_bootstrap', scep_url=original['origin'] + '/scep/rss-agent-bootstrap')
    value['device_pki'].append(provider)
    # Rust in-process fixtures read these exact composition inputs as well.
    private(root / 'agent-pki.json', agent)
    private(root / 'device-pki.json', value['device_pki'])
    env['MDM_BOOTSTRAP_FIXTURE'] = str(private(root / 'bootstrap.json', configuration))
