from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import fl23_prewrite_adapter as adapter


class AdapterTests(unittest.TestCase):
    def test_old_pass_boolean_cannot_create_crc_proof(self):
        with patch.object(adapter,'audit_candidate',side_effect=ValueError('corrupt actual input')), \
             patch.object(adapter,'_load_json',return_value={'all_passed':True,'table_count':1}):
            result=adapter.assemble()
        self.assertEqual(result.kwargs['component_sums'],{})
        self.assertTrue(any('actual candidate checksum audit failed' in x for x in result.missing))

    def test_real_rows_used_instead_of_zero_sentinels(self):
        audit=dict(component_sums={'real':('abcd1234',0xabcd1234)},plaintext_sha256='a'*64,
                   table_count=10,regular_CRC_rows=115)
        with patch.object(adapter,'audit_candidate',return_value=audit):
            result=adapter.assemble(emmc_backup_ok='false',nor_backup_ok='false',upper_layer_resolved='false')
        self.assertEqual(result.kwargs['component_sums'],audit['component_sums'])
        for key in ('emmc_backup_ok','nor_backup_ok','upper_layer_resolved'):
            self.assertIs(result.kwargs[key],False)

    def test_bad_header_offset_rejected_without_slice_from_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp).resolve()/'header';p.write_bytes(b'X'*1024)
            self.assertIsNone(adapter.read_header(p,-512)[0])
            self.assertIsNone(adapter.read_header(p,True)[0])

    def test_header_read_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp).resolve()/'header';p.write_bytes(b'X'*1024)
            with patch.object(Path,'read_bytes',side_effect=AssertionError('unbounded input read')):
                self.assertEqual(len(adapter.read_header(p,0)[0]),512)

    def test_model_code_uses_actual_little_endian_header_encoding(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp).resolve()/'header';raw=bytearray(512)
            raw[36:40]=bytes.fromhex('81000301');p.write_bytes(raw)
            _,model,region,_=adapter.read_header(p)
            self.assertEqual(model,'01030081')
            self.assertEqual(region,'0')


if __name__ == '__main__':unittest.main()
