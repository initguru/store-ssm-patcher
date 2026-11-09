import importlib.util
from pathlib import Path
import unittest
import zipfile

ROOT = Path('/tmp/ssm_re_work')
spec = importlib.util.spec_from_file_location('patch_ssm', ROOT / 'patch_ssm.py')
assert spec is not None and spec.loader is not None
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)

class PatchContract(unittest.TestCase):
 def test_added_dex_contract(self):
  expected = [(0x5401da,'1a01487a71203cff13000c01','1a01120b0000000000000000'),(0x4fdbec,'0a06','1216'),(0x4eadda,'0a03','1213'),(0x4ee052,'0a03','1213'),(0x4f1bda,'0a03','1213'),(0x4f5862,'0a03','1213'),(0x50e90c,'0a04','1214'),(0x50ec16,'0a05','1215')]
  for item in expected: self.assertIn(item, patcher.DEX['classes.dex'])
 def test_android_fallback_dex_contract(self):
  expected = {
   'classes.dex': [
    (0x5766bc,'62008474','12100f00'),
    (0x571b0c,'120054318f74','12100f000000'),
    (0x55fba0,'6200bd73','12100f00'),
    (0x560f68,'6200bd73','0e000000'),
    (0x529fec,'6e30325b2005','000000000000'),
    (0x52a01c,'6e30f00b1502','000000000000'),
    (0x52a064,'6e30f00b0501','000000000000'),
    (0x4ce692,'13020020','13020000'),
    (0x4ce7ee,'13000020','13000000'),
    (0x4d9602,'13000020','13000000'),
    (0x4d9eaa,'13000020','13000000'),
    (0x4db652,'13000020','13000000'),
    (0x57fa34,'1a00fa5a','0e000000'),
    (0x5401d6,'38021100','00000000'),
    (0x5758e8,'62008474','12100f00'),
    (0x570edc,'120054318f74','12100f000000'),
    (0x551c22,'6e30d70b2105','000000000000'),
    (0x552876,'1214','1204'),
    (0x54fb70,'08061700','12000f00'),
    (0x4fc468,'1a003d96','12100f00'),
    (0x4db080,'7100f3f000000c00','12100f0000000000'),
    (0x50735c,'1a003996','12100f00'),
    (0x5073c0,'1a003b96','12100f00')],
   'classes2.dex': [(0xb4c70,'7100b70200000c00','12100f0000000000'),
                    (0xb34c4,'7100860200000c00','12000f0000000000')]
  }
  with zipfile.ZipFile('/Users/jihyun.son/dev/rea/ssm/artifacts/SSM_5.5.14.2624.apk') as src, zipfile.ZipFile('/Users/jihyun.son/dev/rea/ssm/artifacts/SSM_5.5.14.2624_patched.apk') as dst:
   for name, patches in expected.items():
    original, patched = src.read(name), dst.read(name)
    patcher.dex_valid(patched)
    candidate = bytearray(original)
    for off, old, new in patcher.DEX[name]:
     self.assertEqual(original[off:off+len(bytes.fromhex(old))].hex(), old)
     candidate[off:off+len(bytes.fromhex(new))] = bytes.fromhex(new)
    patcher.validate_methods(candidate, patcher.DEX[name])
    for off, old, new in patches:
     with self.subTest(dex=name, offset=hex(off)):
      self.assertEqual(original[off:off+len(bytes.fromhex(old))], bytes.fromhex(old))
      self.assertIn((off, old, new), patcher.DEX[name])
      self.assertEqual(patched[off:off+len(bytes.fromhex(new))], bytes.fromhex(new))
   self.assertFalse(any(off == 0x52e3cc for off, _, _ in patcher.DEX['classes.dex']))
   for apk in (src, dst):
    self.assertEqual(apk.read('classes.dex')[0x52e3cc:0x52e3d0].hex(), '12000f00')
 def test_store_on_resume_branches_to_sso_tail(self):
  spec = importlib.util.spec_from_file_location('patch_store', ROOT / 'patch_store.py')
  assert spec is not None and spec.loader is not None
  store = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(store)
  with zipfile.ZipFile('/Users/jihyun.son/dev/rea/ssm/artifacts/Store_1.26.0.apk') as src:
   original = src.read('classes.dex')
  plan = store.plan(original)
  self.assertNotIn((0x3a4a3e,'6e10','0e00'), plan)
  self.assertIn((0x3a4a4e,'1a038226','2900e202'), plan)
  patched = bytearray(original)
  for off, old, new in plan:
   self.assertEqual(original[off:off+len(bytes.fromhex(old))].hex(), old)
   patched[off:off+len(bytes.fromhex(new))] = bytes.fromhex(new)
  self.assertEqual(patched[0x3a4a38:0x3a4a40], original[0x3a4a38:0x3a4a40])
  self.assertEqual(0x3a4a4e + 2 * int.from_bytes(patched[0x3a4a50:0x3a4a52], 'little', signed=True), 0x3a5012)
  self.assertEqual(patched[0x3a5012:0x3a5016].hex(), '1d005501')
  with zipfile.ZipFile('/Users/jihyun.son/dev/rea/ssm/artifacts/Store_1.26.0_patched.apk') as dst:
   actual = dst.read('classes.dex')
  patcher.dex_valid(actual)
  self.assertEqual(actual[0x3a4a3e:0x3a4a40].hex(), '6e10')
  self.assertEqual(actual[0x3a4a4e:0x3a4a52].hex(), '2900e202')
  self.assertEqual(0x3a4a4e + 2 * int.from_bytes(actual[0x3a4a50:0x3a4a52], 'little', signed=True), 0x3a5012)
  self.assertEqual(actual[0x3a5012:0x3a5016].hex(), '1d005501')
 def test_real_arm64_registration_and_body(self):
  with zipfile.ZipFile('/Users/jihyun.son/dev/rea/ssm/artifacts/SSM_5.5.14.2624.apk') as z:
   plans = patcher.ELF(z.read('lib/arm64-v8a/libnative-lib.so')).patches()
  actual = {name:(off,patch.hex()) for name,off,patch in plans}
  self.assertEqual(actual['checkSecurityStatus'], (0x314d4,'00008052c0035fd6'))
  self.assertEqual(actual['checkSecurityStatus_body'], (0x31694,'00008052c0035fd6'))

if __name__ == '__main__': unittest.main()
