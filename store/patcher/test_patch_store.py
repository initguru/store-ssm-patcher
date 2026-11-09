import importlib.util
import tempfile
import unittest
import zipfile
import zlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from patcher_common import DexFile, decode_tries, extract_apk_cert_sha1

spec = importlib.util.spec_from_file_location('store', ROOT / 'store' / 'patcher' / 'patch_store.py')
assert spec is not None and spec.loader is not None
store = importlib.util.module_from_spec(spec)
spec.loader.exec_module(store)
APK = ROOT / 'store' / 'apk' / 'Store_1.26.0.apk'
PATCHED_APK = ROOT / 'artifacts' / 'Store_1.26.0_patched.apk'

class StoreContract(unittest.TestCase):
 def test_empty_padding_payload(self):
  with zipfile.ZipFile(APK) as z:
   dex = DexFile(z.read('classes.dex'))
  for m in dex.methods:
   if m.code_off:
    dex.decode_method(m)

 def test_exact_plan_and_preservation(self):
  cert_sha1 = extract_apk_cert_sha1(APK)
  self.assertEqual(cert_sha1, 'e8404b806937b690b087fecca7845f7dfa34371e')
  with zipfile.ZipFile(APK) as z:
   d = z.read('classes.dex')
  p = store.plan(d, cert_sha1)
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
  dex = DexFile(d)
  m_sig = store.select(dex, 'sig-check', store.RULES[14])
  self.assertTrue(len(decode_tries(d, m_sig, dex)) >= 1)
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

 def test_cfg_padding_and_reachable_payload(self):
  with zipfile.ZipFile(APK) as z:
   original = z.read('classes.dex')
  d = bytearray(original)
  p = store.plan(original)
  for o, _, new in p:
   d[o:o+len(bytes.fromhex(new))] = bytes.fromhex(new)
  store.validate_methods(d, p)
  # Replacing the entry goto with nop makes the alignment nop reachable.
  d[0x3e7338:0x3e733a] = b'\x00\x00'
  with self.assertRaisesRegex(AssertionError, 'invalid fallthrough into payload'):
   store.validate_methods(d, p)

 def test_branch_and_return_rejection(self):
  with zipfile.ZipFile(APK) as z:
   original = z.read('classes.dex')
  for bad, reason in (('2801', 'invalid branch target'), ('0e00', 'return type mismatch')):
   with self.subTest(bad=bad):
    d = bytearray(original)
    # goto into the second code unit of the following invoke instruction.
    d[0x318068:0x31806a] = bytes.fromhex('2802' if bad == '2801' else bad)
    with self.assertRaisesRegex(AssertionError, reason):
     store.validate_methods(d, [(0x318068, '', '')])

 def test_exact_window_rejection(self):
  with zipfile.ZipFile(APK) as z:
   original = z.read('classes.dex')
  p = store.plan(original)
  d = bytearray(original)
  for o, _, new in p:
   d[o:o+len(bytes.fromhex(new))] = bytes.fromhex(new)
  store.fix_dex(d)
  store.verify_dex_exact(original, d, p)
  d[112] ^= 1
  store.fix_dex(d)
  with self.assertRaisesRegex(AssertionError, 'Unexpected DEX modifications'):
   store.verify_dex_exact(original, d, p)

 def test_semantic_fail_closed(self):
  with zipfile.ZipFile(APK) as z:
   dex = DexFile(z.read('classes.dex'))
  with self.assertRaisesRegex(ValueError, 'found 0'):
   store.find_unique_method(dex, 'missing', class_filter='Lmissing;')
  with self.assertRaisesRegex(ValueError, 'expected 1 method'):
   store.find_unique_method(dex, 'ambiguous')
  m = store.select(dex, 'resume', store.RESUME)
  with self.assertRaisesRegex(ValueError, 'expected 1 instruction'):
   store.find_unique_insn_offset(dex, m, 'missing-insn', pattern=b'\xff' * 20)

 def test_rejects_integer_and_uninitialized_object_returns(self):
  with zipfile.ZipFile(APK) as z: original = z.read('classes.dex')
  dex = DexFile(original)
  method = next(m for m in dex.methods if m.code_off and m.return_type.startswith(('L', '[')) and m.registers_size > m.ins_size and m.insns_size >= 4)
  for code in ('1210110000000000', '1100000000000000'):
   data = bytearray(original)
   data[method.insns_off:method.insns_off+8] = bytes.fromhex(code)
   with self.subTest(code=code), self.assertRaises(AssertionError):
    store.validate_methods(data, [(method.insns_off, '', code)])

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
    resolved = store.resolve_native_patches(name, original)
    self.assertEqual(resolved, patches)
    patched = store.patch_native(name, original)
    self.assertEqual(len(original), len(patched))
    self.assertEqual(zlib.crc32(original), zlib.crc32(patched))
    for o, _, new in resolved:
     self.assertEqual(patched[o:o+len(bytes.fromhex(new))].hex(), new)

 def test_verify_rejects_unplanned_entry_modification(self):
  with tempfile.TemporaryDirectory() as tmp:
   target = PATCHED_APK
   if not target.exists():
    import subprocess
    target = Path(tmp) / 'store_patched.apk'
    subprocess.run([sys.executable, str(ROOT / 'store' / 'patcher' / 'patch_store.py'), str(APK), str(target)], check=True)
   store.verify(APK, target)
   tampered = Path(tmp) / 'tampered.apk'
   with zipfile.ZipFile(target) as zi, zipfile.ZipFile(tampered, 'w') as zo:
    for info in zi.infolist():
     data = zi.read(info.filename)
     if info.filename == 'AndroidManifest.xml':
      data = data[:-1] + bytes([data[-1] ^ 1])
     zo.writestr(info, data)
   with self.assertRaises(AssertionError):
    store.verify(APK, tampered)

 def test_analysis_and_rea_evidence_completeness(self):
  import json
  root = ROOT / 'store' / 'analysis'
  p1 = json.loads((root / 'store_disassembly_and_patches.json').read_text())
  p2 = json.loads((root / 'store_certificate_and_universal_audit.json').read_text())
  methods = p1['dex_analysis']['classes.dex']['methods']
  self.assertEqual(len(methods), 18)
  for sig, m in methods.items():
   self.assertIn('try_blocks', m, sig)
   self.assertIn('before_instructions', m, sig)
   self.assertIn('after_instructions', m, sig)
   self.assertNotIn('tries', m, sig)
  sec = p2['security_critical_methods']
  self.assertEqual(len(sec), 17)
  for sig, m in sec.items():
   self.assertIn('try_blocks', m, sig)
   self.assertIn('before_instructions', m, sig)
   self.assertIn('after_instructions', m, sig)
   self.assertNotIn('before', m, sig)
   self.assertNotIn('after', m, sig)
   self.assertNotIn('tries', m, sig)
  rea = json.loads((ROOT / 'store' / 'rea' / 'rea_store_evidence.json').read_text())
  import hashlib
  import subprocess
  src_sha = hashlib.sha256(APK.read_bytes()).hexdigest()
  apk_sha = rea['canonical_artifacts']['patched_apk_sha256']
  self.assertEqual(len(apk_sha), 64)
  if PATCHED_APK.is_file():
   self.assertEqual(hashlib.sha256(PATCHED_APK.read_bytes()).hexdigest(), apk_sha)
  self.assertEqual(rea['canonical_artifacts']['original_apk_sha256'], src_sha)
  self.assertEqual(rea['canonical_artifacts']['source_apk_sha256'], src_sha)
  self.assertEqual(rea['patched_apk_signature_inspection']['summary']['artifact']['sha256'], apk_sha)
  self.assertEqual(rea['rea_apk_signature_inspection']['summary']['artifact']['sha256'], apk_sha)
  self.assertEqual(len(rea['artifacts']), 2)
  self.assertEqual({a['sha256'] for a in rea['artifacts']}, {src_sha, apk_sha})
  self.assertEqual({a['digest']['sha256'] for a in rea['artifacts']}, {src_sha, apk_sha})
  self.assertEqual({r['subject']['digest']['sha256'] for r in rea['records']}, {src_sha, apk_sha})
  rec_ids = {r['evidence_id'] for r in rea['records']}
  self.assertIn(rea['patched_apk_signature_inspection']['evidence_id'], rec_ids)
  self.assertIn(rea['patched_apk_signature_inspection']['parent_evidence_id'], rec_ids)
  with tempfile.TemporaryDirectory() as tmp:
   target = PATCHED_APK
   if not target.is_file():
    target = Path(tmp) / 'store_patched.apk'
    subprocess.run([sys.executable, str(ROOT / 'store' / 'patcher' / 'patch_store.py'), str(APK), str(target)], check=True)
   with zipfile.ZipFile(target) as zf:
    for d in rea['android14_dex2oat64_verification']:
     self.assertEqual(d['source_patched_apk_sha256'], apk_sha)
     self.assertEqual(hashlib.sha256(zf.read(d['dex'])).hexdigest(), d['sha256'])

 def test_duplicate_source_entries_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   dup_src = Path(tmp) / 'dup_src.apk'
   dummy_out = Path(tmp) / 'dummy_out.apk'
   with zipfile.ZipFile(dup_src, 'w') as z:
    z.writestr('a.txt', b'1')
    z.writestr('a.txt', b'2')
   with zipfile.ZipFile(dummy_out, 'w') as z:
    z.writestr('a.txt', b'1')
   with self.assertRaisesRegex(AssertionError, 'duplicate source entries'):
    store.verify(dup_src, dummy_out, 'e8404b806937b690b087fecca7845f7dfa34371e')

if __name__ == '__main__': unittest.main()
