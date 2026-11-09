import importlib.util
import unittest
import zipfile
import zlib

spec = importlib.util.spec_from_file_location('store', '/tmp/ssm_re_work/patch_store.py')
assert spec is not None and spec.loader is not None
store = importlib.util.module_from_spec(spec)
spec.loader.exec_module(store)
APK = '/Users/jihyun.son/dev/rea/ssm/artifacts/Store_1.26.0.apk'

class StoreContract(unittest.TestCase):
 def test_exact_plan_and_preservation(self):
  with zipfile.ZipFile(APK) as z:
   d = z.read('classes.dex')
  p = store.plan(d)
  self.assertEqual(len(p), 16)
  self.assertEqual({o for o, _, _ in p}, {0x3a4f16,0x3a4fb2,0x3a4a4e,0x31f70e,0x3120b2,0x312cec,0x318068,0x3180b8,0x3181b8,0x318218,0x319150,0x319754,0x31c0fc,0x31c180,0x31c33c,0x3e7338})
  patched = bytearray(d)
  for o, old, new in p:
   self.assertEqual(len(old), len(new))
   self.assertEqual(d[o:o+len(bytes.fromhex(old))].hex(), old)
   patched[o:o+len(bytes.fromhex(new))] = bytes.fromhex(new)
  self.assertEqual(patched[0x27b194:0x27b1e4], d[0x27b194:0x27b1e4])
  for o in (0x3e7338,):
   self.assertEqual(patched[o+0x2e:o+0x32].hex(), '1203282d')
  store.validate_methods(patched, p)
  # The former partial overwrite leaves a detached move-result.
  patched[0x318068:0x318070] = bytes.fromhex('12100f0000000a00')
  with self.assertRaises(AssertionError): store.validate_methods(patched, p)
 def test_invalid_instructions(self):
  with zipfile.ZipFile(APK) as z:
   original = z.read('classes.dex')
  for bad in ('3e00', '0fff'):
   with self.subTest(instruction=bad):
    d = bytearray(original)
    for o, _, new in store.plan(original):
     d[o:o+len(bytes.fromhex(new))] = bytes.fromhex(new)
    d[0x318068:0x31806a] = bytes.fromhex(bad)
    with self.assertRaises(AssertionError): store.validate_methods(d, [(0x318068, '', '')])
 def test_double_to_int_wide_source(self):
  with zipfile.ZipFile(APK) as z:
   d = bytearray(z.read('classes.dex'))
  for o, _, new in store.plan(d):
   d[o:o+len(bytes.fromhex(new))] = bytes.fromhex(new)
  # Restrict this fixture to one register: v0 fits, its wide pair does not.
  d[0x318058:0x31805a] = b'\x01\x00'
  d[0x318068:0x31806a] = bytes.fromhex('8a00')
  with self.assertRaisesRegex(AssertionError, 'register out of range'):
   store.validate_methods(d, [(0x318068, '', '')])
 def test_crc_solver(self):
  b = bytearray(b'CRC independent fixture with sufficient bytes')
  expected = zlib.crc32(b)
  b[0] ^= 1
  store.restore_crc(b, 12, expected)
  self.assertEqual(zlib.crc32(b), expected)
 def test_native_contract(self):
  with zipfile.ZipFile(APK) as z:
   for name, patches in store.native_plans().items():
    original = z.read(name)
    patched = store.patch_native(name, original)
    self.assertEqual(len(original), len(patched))
    self.assertEqual(zlib.crc32(original), zlib.crc32(patched))
    for o, _, new in patches:
     self.assertEqual(patched[o:o+len(bytes.fromhex(new))].hex(), new)

if __name__ == '__main__': unittest.main()
