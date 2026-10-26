#!/usr/bin/env python3
"""Apply RSS transport support to the pinned, external Fleet test client checkout."""
import argparse, hashlib, pathlib, shutil, subprocess
REVISION='0aabd28dccba2dae076704507c6c288337300d89'
UPSTREAM = {
    'pkg/mdm/mdmtest/apple.go': '5d4c52eec8a0cb3ea2877031849d53bb0b7d1ff21a3128f94352ca5170c56d2a',
    'pkg/mdm/mdmtest/windows.go': 'af87d2430a5d3d32f39545907974518b28330205156233816931f37aec3535f7',
    'pkg/mdm/mdmtest/scep_exchange.go': 'c4254aa6ec9e71dc50bbbf25e0b294a25bfd996d884fd6557a5ee3f4305a37a2',
    'server/fleet/microsoft_mdm.go': 'd3c6480aabc0bd214fde713003f4e8830397552d38ae278048e52161f150cef0',
}
def prepare(root):
    # Validate every upstream input before modifying any file; reruns use immutable originals.
    for relative, expected in UPSTREAM.items():
        path = root / relative
        original = path.with_suffix('.go.upstream')
        candidate = original if original.exists() else path
        if hashlib.sha256(candidate.read_bytes()).hexdigest() != expected:
            raise RuntimeError('unsupported Fleet source: ' + relative)
    here=pathlib.Path(__file__).resolve().parent
    package=root/'pkg/mdm/mdmtest'
    for name,edits in {
        'apple.go':[
            ('Organization:       []string{"fleet-organization"},','Organization:       c.externalOrganization(),'),
            ('type TestAppleMDMClient struct {','type TestAppleMDMClient struct {\n External *ExternalApple'),
            ('func (c *TestAppleMDMClient) request(contentType string, payload map[string]any) (*http.Response, error) {','func (c *TestAppleMDMClient) request(contentType string, payload map[string]any) (*http.Response, error) {\n if c.External != nil { return c.externalRequest(contentType, payload) }'),
            ('cn := fmt.Sprintf("fleet-testdevice-%s", c.Identifier())','cn := fmt.Sprintf("fleet-testdevice-%s", c.Identifier())\n if c.External != nil { cn = c.External.Subject }'),
        ],
        'windows.go':[
            ('for _, protoCmd := range c.queuedCommandResponses {','for _, protoCmd := range c.externalResponses() {'),
            ('var soapResponse fleet.SoapResponse','var soapResponse ExternalSOAPResponse'),
            ('fmt.Sprint(sessionIDInt)', 'fmt.Sprint(sessionIDInt+1)'),
            ('type TestWindowsMDMClient struct {','type TestWindowsMDMClient struct {\n External *ExternalWindows'),
            ('func (c *TestWindowsMDMClient) request(path string, reqBody []byte) (*http.Response, error) {','func (c *TestWindowsMDMClient) request(path string, reqBody []byte) (*http.Response, error) {\n if c.External != nil { return c.externalRequest(path, reqBody) }'),
        ],
        '../../../server/fleet/microsoft_mdm.go':[
            ('type SyncBody struct {','type SyncBody struct {\n Sequence ProtoCmds `xml:"Sequence,omitempty"`'),
            ('type SyncMLCmd struct {','type SyncMLCmd struct {\n SequenceCommands []SyncMLCmd `xml:"Sequence,omitempty"`\n AtomicCommands []SyncMLCmd `xml:"Atomic,omitempty"`'),
            ('// Process each command one by one','if msg.SyncBody.Sequence != nil { addCmds(msg.SyncBody.Sequence, "Sequence") }\n // Process each command one by one'),
        ],
        'scep_exchange.go': [('scepclient.Insecure(),','scepclient.WithRootCA(""),')],
    }.items():
        p=package/name
        backup=p.with_suffix('.go.upstream')
        if not backup.exists():shutil.copyfile(p,backup)
        text=backup.read_text()
        for old,new in edits:
            if text.count(old)!=1:raise RuntimeError(f'upstream drift: {name}: {old[:60]}')
            text=text.replace(old,new)
        p.write_text(text)
    shutil.copyfile(here/'external.go',package/'rss_external.go')
    dest=root/'cmd/rss-mdmtest';dest.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(here/'main.go',dest/'main.go')
    subprocess.run(['gofmt','-w',str(package/'rss_external.go'),str(dest/'main.go')],check=True)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('checkout',type=pathlib.Path);a=p.parse_args();prepare(a.checkout.resolve())
