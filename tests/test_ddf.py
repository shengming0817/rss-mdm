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
