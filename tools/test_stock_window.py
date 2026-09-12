"""Independent malformed-evidence controls; GUI relations use captured sensitivity."""
import json
from pathlib import Path
import tempfile
import unittest
import check_stock_window as window


class StockWindowEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.record = dict(phase='P2', surface='normal-CodeBrowser-DecompilerProvider',
                           visible=True, program_id=12, entry='gb_ordinary_150::0150',
                           display_program_id=12, display_entry='gb_ordinary_150::0150',
                           display_program_matches=True, display_function_matches=True,
                           completed=False, highfunction_available=False,
                           error='Stale ordinary-entry registration; preview and refresh required')
        (self.root / 'P2-desktop.png').write_bytes(b'evidence-file-for-integrity-test')
        self.record['desktop_sha256'] = window.finite.sha(self.root / 'P2-desktop.png')
        self.write()

    def write(self, bind=True):
        (self.root / 'P2-request.json').write_text(json.dumps(self.record))
        if bind:
            (self.root / 'timeline.json').write_text(json.dumps([
                dict(kind='passive-capture', detail=dict(phase='P2', record_sha256=window.finite.sha(self.root / 'P2-request.json')))]))

    def test_expected_refusal_with_bound_identity(self):
        window.refusal(window.checked_record(self.root, 'P2'))

    def test_foreign_error_identity(self):
        self.record['display_program_id'] = 13
        self.write()
        with self.assertRaisesRegex(window.finite.Refusal, 'foreign displayed identity'):
            window.checked_record(self.root, 'P2')

    def test_native_crash_is_not_authority_refusal(self):
        self.record['error'] = 'Native process unexpectedly terminated'
        self.write()
        with self.assertRaisesRegex(window.finite.Refusal, 'wrong authority refusal'):
            window.refusal(window.checked_record(self.root, 'P2'))

    def test_missing_desktop_key(self):
        del self.record['desktop_sha256']
        self.write()
        with self.assertRaisesRegex(window.finite.Refusal, 'missing actual screenshot'):
            window.checked_record(self.root, 'P2')

    def test_request_edit_without_new_receipt(self):
        self.record['error'] += ' edited'
        self.write(bind=False)
        with self.assertRaisesRegex(window.finite.Refusal, 'changed request receipt'):
            window.checked_record(self.root, 'P2')

    def test_changed_desktop_bytes(self):
        (self.root / 'P2-desktop.png').write_bytes(b'replacement')
        with self.assertRaisesRegex(window.finite.Refusal, 'changed artifact'):
            window.checked_record(self.root, 'P2')


if __name__ == '__main__':
    unittest.main()
