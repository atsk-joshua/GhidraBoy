"""Backend composition and immutable build identities reject mismatched payloads."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from build_inputs import sha
from install import verify_package
from runtime_probe import selected_backends
from ghigbc.backends.identity import build_identity


class PackageSelectionTests(unittest.TestCase):
    def test_identity_ignores_diagnostic_paths_but_keeps_binary_and_build_inputs(self):
        receipt = dict(schema=1,backend='mgba',sourceRevision='revision',sourceArchiveSha256='source',
                       patchSha256='patch',sources={'adapter.c':'adapter'},
                       builderSha256='builder',binarySha256='binary',host='one',commands=['/tmp/one'])
        for version in (None,True,0,2,'1'):
            invalid=dict(receipt,schema=version)
            with self.assertRaisesRegex(ValueError,'receipt schema'):build_identity(invalid)
        moved = copy.deepcopy(receipt)
        moved.update(host='two',commands=['/elsewhere/two'],abiBuildFiles={'flags': '/tmp/two'})
        self.assertEqual(build_identity(receipt),build_identity(moved))
        for field in ('binarySha256','builderSha256','patchSha256','sourceRevision','sourceArchiveSha256'):
            changed=copy.deepcopy(receipt);changed[field]+='changed'
            self.assertNotEqual(build_identity(receipt),build_identity(changed),field)
        changed=copy.deepcopy(receipt);changed['sources']['adapter.c']='changed'
        self.assertNotEqual(build_identity(receipt),build_identity(changed))

    def test_selected_package_and_installed_runtime_must_agree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            runtime=root/'runtime-backends.json'; manifest=root/'suite.json'
            for names in (['sameboy'],['mgba'],['sameboy','mgba']):
                runtime.write_text(json.dumps(dict(schema=1,backends=names,default_backend=names[0])))
                data=dict(schema=1,kind='generic',backends=names,default_backend=names[0],
                          files={'runtime-backends.json':sha(runtime)},runtime_files=['runtime-backends.json'])
                manifest.write_text(json.dumps(data))
                self.assertEqual(verify_package(manifest,'generic')[0]['backends'],names)
                self.assertEqual(selected_backends(root),names)
            data['backends']=['mgba'];manifest.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,'manifest mismatch'):verify_package(manifest,'generic')
            data['backends']=['sameboy','mgba'];data['runtime_files'].append('unverified')
            manifest.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,'Unverified runtime'):verify_package(manifest,'generic')
            for names in ([],['mgba','mgba'],['other']):
                runtime.write_text(json.dumps(dict(schema=1,backends=names)))
                with self.assertRaises(ValueError):selected_backends(root)

    def test_legacy_package_defaults_to_sameboy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            manifest=root/'suite.json'
            manifest.write_text(json.dumps(dict(schema=1,kind='generic',files={},runtime_files=[])))
            verify_package(manifest,'generic')
            self.assertEqual(selected_backends(root),['sameboy'])


if __name__=='__main__':unittest.main()
