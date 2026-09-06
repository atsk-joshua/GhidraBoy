import json
import unittest
from ghigbc.mapping import accept_envelope, physical

class MappingTests(unittest.TestCase):
    def test_hardware_unknown_and_device_are_explicit(self):
        self.assertEqual(physical('rom',None,0)['status'],'unknown')
        self.assertEqual(physical('io',0,0)['status'],'device')
        self.assertEqual(physical('rom',256,0xb5)['bank'],256)
        self.assertEqual(physical('cart',3,5)['region'],'SRAM')
        with self.assertRaises(ValueError):physical('wram',0,4096)

    def test_current_identity_coverage_and_versions(self):
        data=dict(adapterVersion=1,static=dict(schemaVersion=2,language='SM83:LE:16:default'),currentExportSha256='a'*64,fullMappedCoverage=True,generation='b'*64)
        generation,raw=accept_envelope(json.dumps(data),'a'*64)
        self.assertEqual(generation,'b'*64);self.assertIsInstance(raw,bytes)
        for key,value in [('adapterVersion',2),('fullMappedCoverage',False),('currentExportSha256','c'*64),('generation','invalid')]:
            changed=dict(data);changed[key]=value
            with self.assertRaises(ValueError):accept_envelope(json.dumps(changed),'a'*64)

    def test_ordered_bounded_transfer(self):
        from ghigbc.mapping import EnvelopeTransfer
        data=dict(adapterVersion=1,static=dict(schemaVersion=2,language='SM83:LE:16:default'),currentExportSha256='a'*64,fullMappedCoverage=True,generation='b'*64)
        text=json.dumps(data);half=len(text)//2;transfer=EnvelopeTransfer()
        self.assertIsNone(transfer.append('b'*64,0,2,text[:half],'s',1,'a'*64))
        with self.assertRaises(ValueError):transfer.append('b'*64,1,2,text[half:],'s',2,'a'*64)
        self.assertIsNone(transfer.append('b'*64,0,2,text[:half],'s',2,'a'*64))
        self.assertEqual(transfer.append('b'*64,1,2,text[half:],'s',2,'a'*64)[0],'b'*64)
