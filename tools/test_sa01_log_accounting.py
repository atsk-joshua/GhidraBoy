"""Strict installed-phase diagnostics and exact package-member checks."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import sa01_production_persistence as production
import sa01_state_persistence as state


class Sa01LogAccountingTest(unittest.TestCase):
    rejection = ('Unresolved software-call injection at 0150: '
                 'Software-call annotations changed after review')

    def expected_lines(self):
        return [
            'WARN  ' + self.rejection + ' (SymbolicPropogator)  ',
            'ERROR Unexpected Exception: ' + self.rejection
            + ' (DecompileProcess) java.lang.IllegalArgumentException: ' + self.rejection,
        ]

    def test_exact_finite_stale_rejection_only_passes_its_phase(self):
        lines = self.expected_lines()
        expected, failures, native, warnings = production.classify_log('\n'.join(lines), 'edited-reopen')
        self.assertEqual(expected, lines)
        self.assertEqual((failures, native, warnings), ([], [], []))
        for phase in ('verify', 'edit', 'removed-reopen'):
            with self.subTest(phase=phase):
                expected, failures, _, _ = production.classify_log('\n'.join(lines), phase)
                self.assertEqual(expected, [])
                self.assertEqual(failures, lines)

    def test_wrong_site_reason_logger_and_extra_failure_are_not_waived(self):
        line = self.expected_lines()[0]
        cases = [line.replace('0150', '0160'),
                 line.replace('annotations changed after review', 'dependencies are stale'),
                 line.replace('SymbolicPropogator', 'OtherAnalyzer'),
                 line.rstrip() + ' ERROR another failure',
                 'WARN  unexpected prefix ' + self.rejection]
        for case in cases:
            with self.subTest(line=case):
                expected, failures, _, _ = production.classify_log(case, 'edited-reopen')
                self.assertEqual(expected, [])
                self.assertEqual(failures, [case])

    def test_native_and_unknown_warnings_fail_despite_success_markers(self):
        diagnostic = 'WARN  Removing unreachable block (ram,0x4507) (DecompileProcess)'
        warning = 'WARN  Newly introduced analyzer warning (NewAnalyzer)'
        for phase in ('verify', 'edited-reopen', 'removed-reopen'):
            with self.subTest(phase=phase):
                log = '\n'.join(['INFO SA01_PRODUCTION_VERIFY_PASS', diagnostic, warning])
                expected, failures, native, warnings = production.classify_log(log, phase)
                self.assertEqual(expected, [])
                self.assertEqual(failures, [diagnostic, warning])
                self.assertEqual(native, [diagnostic])
                self.assertEqual(warnings, [warning])
        unexpected, native = state.classify_log('\n'.join([
            'INFO SA01_STATE_PREPARE_PASS', 'INFO SA01_STATE_VERIFY_PASS', diagnostic, warning]))
        self.assertEqual(unexpected, [diagnostic, warning])
        self.assertEqual(native, [diagnostic])

    def test_state_campaign_does_not_waive_finite_stale_rejections(self):
        lines = self.expected_lines()
        unexpected, native = state.classify_log('\n'.join(lines))
        self.assertEqual(unexpected, lines)
        self.assertEqual(native, [])

    def test_expected_negative_does_not_hide_other_errors(self):
        expected_line = self.expected_lines()[0]
        failure = 'ERROR flow into unmapped memory gb_call_view_291_4500_state1::4507'
        expected, failures, _, _ = production.classify_log(
            '\n'.join([expected_line, failure]), 'edited-reopen')
        self.assertEqual(expected, [expected_line])
        self.assertEqual(failures, [failure])
        self.assertEqual(state.classify_log('INFO SA01_STATE_VERIFY_PASS'), ([], []))


class Sa01InstalledMembersTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.package = self.root / 'provider.zip'
        self.extension = self.root / 'distribution/Ghidra/Extensions/GhidraBoy'

    def write_package(self, members):
        with zipfile.ZipFile(self.package, 'w') as archive:
            for name, contents in members.items():
                archive.writestr(name, contents)

    def test_records_exact_installed_members(self):
        members = {'GhidraBoy/lib/provider.jar': b'exact package provider',
                   'GhidraBoy/data/languages/sm83.cspec': b'exact package compiler'}
        self.write_package(members)
        observed = production.install_extension(self.package, self.extension)
        self.assertEqual(observed, {name: hashlib.sha256(data).hexdigest()
                                    for name, data in members.items()})
        for name, data in members.items():
            self.assertEqual((self.extension.parent / name).read_bytes(), data)

    def test_wrong_installed_jar_is_rejected(self):
        member = 'GhidraBoy/lib/provider.jar'
        self.write_package({member: b'older qualified ZIP member'})
        extractall = zipfile.ZipFile.extractall

        def substitute_loose_jar(archive, path):
            extractall(archive, path)
            (Path(path) / member).write_bytes(b'newer unqualified loose build JAR')

        with patch.object(zipfile.ZipFile, 'extractall', substitute_loose_jar):
            with self.assertRaisesRegex(RuntimeError, 'Installed package member mismatch'):
                production.install_extension(self.package, self.extension)

    def test_archive_escape_rejects_before_extracting_any_member(self):
        self.write_package({'GhidraBoy/lib/provider.jar': b'valid', '../outside': b'invalid'})
        with self.assertRaisesRegex(ValueError, 'path outside GhidraBoy'):
            production.install_extension(self.package, self.extension)
        self.assertFalse(self.extension.exists())


if __name__ == '__main__':
    unittest.main()
