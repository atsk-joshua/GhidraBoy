"""Comparison evidence must not turn omitted observations into agreement."""
import unittest

from compare_backends import differences, fixture, timing_interval


class ComparisonTests(unittest.TestCase):
    def test_missing_rows_and_fields_are_not_agreement(self):
        row = {'name': 'synchronized', 'state': {'af': 0x4280, 'wram0': '42'}}
        for left, right in (([], []), ([row], []),
                            ([row], [{'name': 'other', 'state': row['state']}]),
                            ([row], [{'name': row['name'], 'state': {'af': 0x4280}}])):
            with self.subTest(left=left, right=right), self.assertRaises(ValueError):
                differences(left, right)

    def test_mismatch_preserves_named_boundary_field_and_both_values(self):
        left = [{'name': 'normal_store', 'state': {'af': 0x4280, 'wram0': '42'}}]
        right = [{'name': 'normal_store', 'state': {'af': 0x4280, 'wram0': '99'}}]
        self.assertEqual(differences(left, left), [])
        self.assertEqual(differences(left, right), [
            {'boundary': 'normal_store', 'field': 'wram0', 'sameboy': '42', 'mgba': '99'}])

    def test_negative_fixture_changes_only_intended_operand_and_checksum(self):
        positive, negative = fixture(), fixture(True)
        self.assertEqual(len(positive), 65536)
        changes = {i for i, (a, b) in enumerate(zip(positive, negative)) if a != b}
        self.assertEqual(changes - {0x14e, 0x14f}, {0x252})
        self.assertEqual((positive[0x252], negative[0x252]), (0x42, 0x99))
        for rom in (positive, negative):
            self.assertEqual(rom[0x14d], (-sum(rom[0x134:0x14d]) - 25) & 255)
            self.assertEqual(int.from_bytes(rom[0x14e:0x150], 'big'),
                             (sum(rom) - sum(rom[0x14e:0x150])) & 65535)

    def test_speed_divergence_retains_exact_minimal_reproducer(self):
        row = timing_interval('speed_switch_and_nop', 131096, 8388608, 20, 8388608)
        self.assertFalse(row['matches'])
        self.assertEqual(row['classification'], 'speed-switch-device-delay-unresolved')
        self.assertEqual((row['sameboy']['ticks'], row['mgba']['ticks']), (131096, 20))
        self.assertEqual(row['minimalCase'], {
            'start': {'bank': 0, 'pc': 0x284, 'speed': 1, 'KEY1': 1, 'IME': 0, 'IE': 0, 'IF': 0},
            'romBytes': '100000', 'operations': ['STOP 00', 'NOP'],
            'end': {'bank': 0, 'pc': 0x287, 'speed': 2},
            'input': 'All keys released; fixture initialization disables LCD and timer',
        })

    def test_ticks_are_compared_as_durations_without_tolerance(self):
        self.assertTrue(timing_interval('normal_nop', 8, 8388608, 4, 4194304)['matches'])
        self.assertFalse(timing_interval('normal_nop', 8, 8388608, 5, 4194304)['matches'])


if __name__ == '__main__':
    unittest.main()
