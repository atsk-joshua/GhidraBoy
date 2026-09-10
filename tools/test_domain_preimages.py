"""Counterexamples for the production-preimage evidence comparator, without a live Program."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from check_domain_preimages import verify


class DomainPreimagesTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.fresh = self.root / 'captures-persist-synthetic'
        self.reopened = self.root / 'captures-reopen'
        self.fresh.mkdir()
        self.reopened.mkdir()
        self.fields = ['far-call-review-v3', 'symbol:dynamic:rom2::4100:LAB_rom2__4100:DEFAULT:false',
                       'reference:0200:rom2::4100:DATA:-1:USER_DEFINED:true:91']
        self.fixture(self.fields, self.fields)

    def capture(self, directory, sequence, fields, caller, phase, pid, raw=None):
        fields = sorted(fields)
        raw = json.dumps(fields).encode() if raw is None else raw
        value = {'sequence': sequence, 'phase': phase, 'programId': 91, 'javaPid': pid,
                 'modification': 12, 'components': {'memory': 'a'*64}, 'includeOwnership': True,
                 'fields': fields, 'digest': hashlib.sha256(raw).hexdigest(),
                 'stack': ['fi.gekkio.ghidraboy.FarCallEvidence.recordCapture(FarCallEvidence.java:45)',
                           'fi.gekkio.ghidraboy.FarCallEvidence.capture(FarCallEvidence.java:119)',
                           'fi.gekkio.ghidraboy.FarCallEvidence.capture(FarCallEvidence.java:15)',
                           'fi.gekkio.ghidraboy.SoftwareCallDomains.fingerprint(SoftwareCallDomains.java:29)',
                           caller]}
        path = directory / f'{sequence:06d}.json'
        path.write_text(json.dumps(value))
        path.with_suffix('.preimage').write_bytes(raw)
        return value

    def fixture(self, before, after):
        stored = self.capture(self.fresh, 1, before, 'SoftwareCallDomains.install(SoftwareCallDomains.java:118)', 'installation', 100)
        self.capture(self.fresh, 2, before, 'GhidraBoyW3bDomains.domainState(GhidraBoyW3bDomains.java:40)', 'immediately-before-save', 100)
        self.capture(self.reopened, 1, after, 'SoftwareCallDomains.currentRecord(SoftwareCallDomains.java:135)', 'first-reopened-proof', 101)
        (self.root / 'persisted-registration.json').write_text(json.dumps({'programId': 91, 'dependencies': stored['digest']}))

    def test_complete_unchanged_production_preimages_pass(self):
        result = verify(self.root, 'unchanged')
        self.assertTrue(result['zeroUnexplainedDifferences'])
        self.assertEqual([], result['changedCategories'])

    def test_dynamic_id_only_change_preserves_duplicate_multiplicity(self):
        before = ['far-call-review-v2'] + ['symbol:4611686018427387905:rom2::4100:LAB:DEFAULT:false']*2
        after = ['far-call-review-v2'] + ['symbol:4611686022722355201:rom2::4100:LAB:DEFAULT:false']*2
        self.fixture(before, after)
        result = verify(self.root, 'dynamic-id-mismatch')
        self.assertEqual(['dynamicSymbols'], result['changedCategories'])
        self.assertEqual(2, result['allCategories']['dynamicSymbols']['afterCount'])
        self.fixture(before, after[:-1])
        with self.assertRaises(AssertionError):
            verify(self.root, 'dynamic-id-mismatch')

    def test_identical_sets_with_omitted_reference_occurrence_refuse(self):
        self.fixture(self.fields + self.fields[-1:], self.fields)
        with self.assertRaises(AssertionError):
            verify(self.root, 'unchanged')

    def test_corrupted_preimage_bytes_or_digest_refuse(self):
        path = self.reopened / '000001.json'
        original = path.read_text()
        raw = path.with_suffix('.preimage').read_bytes()
        path.with_suffix('.preimage').write_bytes(raw + b' ')
        with self.assertRaises(AssertionError):
            verify(self.root, 'unchanged')
        path.with_suffix('.preimage').write_bytes(raw)
        value = json.loads(original)
        value['digest'] = '0'*64
        path.write_text(json.dumps(value))
        with self.assertRaises(AssertionError):
            verify(self.root, 'unchanged')

    def test_claimed_fields_must_match_actual_serialized_bytes(self):
        path = self.reopened / '000001.json'
        value = json.loads(path.read_text())
        value['fields'].append('reference:forged')
        path.write_text(json.dumps(value))
        with self.assertRaises(AssertionError):
            verify(self.root, 'unchanged')

    def test_semantically_equal_json_with_different_bytes_refuses(self):
        self.capture(self.reopened, 1, self.fields, 'SoftwareCallDomains.currentRecord(SoftwareCallDomains.java:135)',
                     'first-reopened-proof', 101, json.dumps(sorted(self.fields), indent=2).encode())
        with self.assertRaises(AssertionError):
            verify(self.root, 'unchanged')

    def test_first_reopened_capture_must_be_the_first_production_guard(self):
        path = self.reopened / '000001.json'
        original = json.loads(path.read_text())
        for field, value in [('sequence', 2), ('stack', ['GhidraBoyW3bDomains.domainState(GhidraBoyW3bDomains.java:40)'])]:
            with self.subTest(field=field):
                altered = dict(original)
                altered[field] = value
                path.write_text(json.dumps(altered))
                with self.assertRaises(AssertionError):
                    verify(self.root, 'unchanged')

    def test_later_native_guard_change_cannot_hide_behind_first_match(self):
        self.capture(self.reopened, 2, self.fields + ['reference:new'],
                     'SoftwareCallDomains.currentRecord(SoftwareCallDomains.java:135)', 'first-reopened-proof', 101)
        with self.assertRaises(AssertionError):
            verify(self.root, 'unchanged')


if __name__ == '__main__':
    unittest.main()
