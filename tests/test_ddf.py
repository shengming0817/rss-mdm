"""Fixed Microsoft DDF provenance and selected registry, independently regenerated."""
import hashlib
import json
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1] / 'crates/windows-mdm/ddf'
NS = '{http://schemas.microsoft.com/MobileDevice/DM}'

class DdfSource(unittest.TestCase):
    def test_exact_sources_and_inherited_registry(self):
        provenance = json.loads((ROOT / 'provenance.json').read_text())
        approved = {
            'url':'https://download.microsoft.com/download/015bd9f5-9cca-4821-8a85-a4c5f9a5d0f2/DDFv2Feb2026.zip',
            'archiveSha256':'bf667d895af4a8c8ab5a31065ce0e28ea2f8b649c4dc416f452f62fd1c42ff14',
            'files':{'Firewall.xml':'faf31f44e9c26eaff75adce1b98f4eca38c2c5035b23d02f374cfff9bc4438ca',
                     'DeviceStatus.xml':'9e33280b8593bf6ed0efcacfb96d6ff7fa3924ab7d60b4d01b65819cb167199b'},
            'selectedSha256':'2ac1869325a6c398ed7cd8232f3089a11bfb537a752f3d76d49e23cd3d709230'}
        self.assertEqual(provenance, approved)
        result = ET.Element('Registry', version='DDFv2Feb2026')
        for name, path in [('Firewall', ['MdmStore', 'DomainProfile', 'EnableFirewall']), ('DeviceStatus', ['Firewall', 'Status'])]:
            raw = (ROOT / (name + '.xml')).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), provenance['files'][name + '.xml'])
            # Only pinned vendor bytes reach the independent test parser; no network resolver.
            node = ET.fromstring(raw).find('Node')
            applicability = {}
            uri = './Vendor/MSFT'
            for part in [name] + path:
                if part != name:
                    node = next(n for n in node.findall('Node') if n.findtext('NodeName') == part)
                uri += '/' + part
                props = node.find('DFProperties')
                found = props.find(NS + 'Applicability')
                if found is not None:
                    applicability.update({n.tag.removeprefix(NS): n.text for n in found})
            self.assertEqual(len(props.find('AccessType')), 1)
            ET.SubElement(result, 'Node', uri=uri, operation=list(props.find('AccessType'))[0].tag,
                          format=list(props.find('DFFormat'))[0].tag, build=applicability['OsBuildVersion'],
                          editions=applicability['EditionAllowList'], csp=applicability['CspVersion'])
        ET.indent(result)
        expected = ET.tostring(result)
        self.assertEqual((ROOT / 'selected.xml').read_bytes(), expected)
        self.assertEqual(hashlib.sha256(expected).hexdigest(), provenance['selectedSha256'])

if __name__ == '__main__':
    unittest.main()
