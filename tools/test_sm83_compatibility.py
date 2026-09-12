"""Sensitivity of strict preservation diffs and first-use command provenance."""
import unittest
from sm83_compatibility import differences, validate_capture_commands

class Sm83CompatibilityTest(unittest.TestCase):
    def test_preserves_multiplicity_and_binding(self):
        self.assertTrue(differences([{'symbolId': 1}, {'symbolId': 1}], [{'symbolId': 1}]))
        self.assertTrue(differences({'symbolId': 1, 'primary': True}, {'symbolId': 2, 'primary': True}))
        self.assertFalse(differences({'comment': 'saved'}, {'comment': 'saved'}))

    def test_first_use_rejects_hidden_script(self):
        records=[]
        for suffix, mode in [('old','old-saved'),('upgrade','upgrade'),('immutable','immutable')]:
            records.append({'phase':'annotated-'+suffix,'command':['headless','project','fixture','-scriptPath','scripts','-preScript','Sm83PreservationInventory.java',mode,'out.json','preserved','-noanalysis'],'exit':0,'markerObserved':True})
        validate_capture_commands(records,'annotated')
        records[-1]['command'].extend(['-postScript','Verify1131Upgrade.java'])
        with self.assertRaises(AssertionError):validate_capture_commands(records,'annotated')
