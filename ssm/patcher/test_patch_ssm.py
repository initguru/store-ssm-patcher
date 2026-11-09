"""Repository-local static DEX/ELF and whole-entry integrity regressions."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from patcher_common import decode_tries, extract_apk_cert_sha1, find_unique_insn_offset, find_unique_method

spec = importlib.util.spec_from_file_location('patch_ssm', Path(__file__).resolve().parent / 'patch_ssm.py')
assert spec is not None and spec.loader is not None
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)
SOURCE = REPO_ROOT / 'ssm' / 'apk' / 'SSM_5.5.14.2624.apk'
OUTPUT = REPO_ROOT / 'artifacts' / 'SSM_5.5.14.2624_patched.apk'

NEW_PATCHES = [
 (0x529fde,'32504f00','00000000'), (0x529fea,'b715','1205'),
 (0x52a006,'32503b00','00000000'), (0x52a00e,'38051600','00000000'),
 (0x52a022,'6005c507','282d0000'), (0x528fa4,'32302000','00000000'),
 (0x528fb0,'df030301','12030000'), (0x528fce,'32300b00','00000000'),
 (0x528fda,'df030301','12030000'), (0x502f8a,'1215','1205'),
 (0x560e98,'b725','1205'), (0x560ed4,'39051e00','281e0000'),
 (0x552520,'71004eea0000','0e0000000000'), (0x5526c4,'1a00516b','0e000000'),
 (0x551cc0,'22008726','0e000000')]

CERT_AND_AUDIT_PATCHES = [
 (0x4ead54,'1201','1211'), (0x4edfcc,'1201','1211'),
 (0x4f1b54,'1201','1211'), (0x4f57dc,'1201','1211'),
 (0x50e85c,'1202','1212'), (0x50eaf4,'1202','1212'),
 (0x52c2ea,'39000300','00000000'), (0x53d31a,'0a06','1206'),
 (0x53d41c,'390a0300','0e000000'), (0x56585a,'0a04','1214'),
 (0x53e340,'0a04','1214'), (0x4c5994,'0a00','1200')]

class PatchContract(unittest.TestCase):
 def test_semantic_plan_and_count(self):
  self.assertEqual([len(patcher.DEX[n]) for n in ('classes.dex','classes2.dex')], [72,8])
  self.assertTrue(set(NEW_PATCHES) <= set(patcher.DEX['classes.dex']))
  self.assertTrue(set(CERT_AND_AUDIT_PATCHES) <= set(patcher.DEX['classes.dex']))
  self.assertFalse({0x529fec,0x52a01c,0x52a064} & {o for o,_,_ in patcher.DEX['classes.dex']})
  cert_sha1 = extract_apk_cert_sha1(SOURCE)
  self.assertEqual(cert_sha1, '7477ca27bf39d4a8bde8e8c95ac706418b6e5b24')
  with zipfile.ZipFile(SOURCE) as z:
   for name, expected in patcher.DEX.items():
    self.assertEqual(patcher.plan_dex(name, z.read(name), cert_sha1), expected)

 def test_manifest_sanitization_and_sdk_target(self):
  with zipfile.ZipFile(SOURCE) as z: original = z.read('AndroidManifest.xml')
  result = patcher.patch_manifest(original)
  self.assertEqual((len(original), len(result)), (84052, 82172))
  self.assertEqual(struct.unpack_from('<HHI', result), (3, 8, len(result)))
  for text in patcher.SCRUB_STRINGS:
   self.assertNotIn(text.encode('utf-16le'), result)
   self.assertNotIn(text.encode('utf-8'), result)
  count, = struct.unpack_from('<I', result, 16)
  start, = struct.unpack_from('<I', result, 28)
  strings = []
  for idx in range(count):
   off = 8 + start + struct.unpack_from('<I', result, 36 + idx * 4)[0]
   length, = struct.unpack_from('<H', result, off)
   strings.append(result[off+2:off+2+length*2].decode('utf-16le'))
  off = 8 + struct.unpack_from('<I', result, 12)[0]
  attrs = {}
  tags = []
  while off < len(result):
   kind, _, size = struct.unpack_from('<HHI', result, off)
   if kind == 0x0102:
    tag = strings[struct.unpack_from('<I', result, off+20)[0]]
    tags.append(tag)
    astart, width, nattrs = struct.unpack_from('<HHH', result, off+24)
    for i in range(nattrs):
     aoff = off+16+astart+i*width
     name = strings[struct.unpack_from('<I', result, aoff+4)[0]]
     if tag in ('manifest', 'uses-sdk'):
      attrs[tag, name] = struct.unpack_from('<IHBBI', result, aoff+8)
   off += size
  original_tags = []
  off = 8 + struct.unpack_from('<I', original, 12)[0]
  while off < len(original):
   kind, _, size = struct.unpack_from('<HHI', original, off)
   if kind == 0x0102:
    original_tags.append(strings[struct.unpack_from('<I', original, off+20)[0]])
   off += size
  self.assertEqual(original_tags.count('uses-permission') - tags.count('uses-permission'), 19)
  self.assertEqual(original_tags.count('service') - tags.count('service'), 1)
  self.assertEqual(attrs['manifest', 'compileSdkVersionCodename'], (47, 8, 0, 3, 47))
  self.assertEqual(strings[47], 'R')
  for tag, name, value in [('manifest','compileSdkVersion',30), ('manifest','platformBuildVersionCode',30), ('manifest','platformBuildVersionName',11), ('uses-sdk','targetSdkVersion',30)]:
   self.assertEqual(attrs[tag, name], (0xffffffff,8,0,0x10,value))

 def test_native_crc_preserved(self):
  import zlib
  with zipfile.ZipFile(SOURCE) as z:
   for name in z.namelist():
    if name.startswith('lib/') and name.endswith('/libnative-lib.so'):
     original = z.read(name)
     result = patcher.patch_native(original, patcher.ELF(original).patches())
     self.assertEqual(len(result), len(original))
     self.assertEqual(zlib.crc32(result), zlib.crc32(original))
     for _, off, patch_bytes in patcher.ELF(original).patches():
      self.assertEqual(result[off:off+len(patch_bytes)], patch_bytes)

 def test_dynamic_cert_string_and_semantic_fallback(self):
  with zipfile.ZipFile(SOURCE) as z:
   dex = patcher.DexFile(z.read('classes.dex'))
  idx = dex.find_string_index('7477CA27BF39D4A8BDE8E8C95AC706418B6E5B24')
  self.assertEqual(idx, 0x0b12)
  # Relaxed insns_size/registers_size fallback and obfuscated class/method fallback
  m1 = find_unique_method(dex, 'fallback-size', class_filter='Lcom/sktelecom/ssm/policy/gid20/l/c;',
   name_filter='h', proto='(Landroid/content/Context;)Ljava/lang/String;',
   insns_size=9999, registers_size=99, required_strings=('com.sktelecom.ssm','currentSignature'))
  self.assertEqual(m1.signature, 'Lcom/sktelecom/ssm/policy/gid20/l/c;->h(Landroid/content/Context;)Ljava/lang/String;')
  m2 = find_unique_method(dex, 'fallback-obf', class_filter='Lcom/obfuscated/NonExistent;',
   name_filter='renamedMethod', proto='(Landroid/content/Context;)Ljava/lang/String;',
   insns_size=9999, registers_size=99, required_strings=('com.sktelecom.ssm','currentSignature'))
  self.assertEqual(m2.signature, m1.signature)
  off = find_unique_insn_offset(dex, m1, 'fallback-rel', pattern='1a01487a71203cff13000c01', rel_off=9999)
  self.assertEqual(off, 0x5401da)
  # Verify decode_tries on PolicyService$c.b (tries_size == 2)
  mp = find_unique_method(dex, 'tries-test', class_filter='Lcom/sktelecom/ssm/policy/PolicyService$c;',
   name_filter='b', proto='(Lretrofit2/d;Lretrofit2/r;)V')
  tries = decode_tries(dex.data, mp, dex)
  self.assertEqual(len(tries), 4)
  self.assertEqual(tries[0]['handlers'][0]['type'], 'Ljava/lang/Exception;')

 def test_existing_class_does_not_fallback_to_other_method(self):
  with zipfile.ZipFile(SOURCE) as z:
   dex = patcher.DexFile(z.read('classes.dex'))
  with self.assertRaises(ValueError):
   find_unique_method(dex, 'existing-class',
    class_filter='Lcom/sktelecom/ssm/policy/gid20/l/c;',
    name_filter='nonexistentMethod', proto='(Landroid/content/Context;)Ljava/lang/String;',
    required_strings=('com.sktelecom.ssm', 'currentSignature'))

 def test_permission_presets_return_without_persisting_empty_list(self):
  self.assertIn((0x51fe58, '1a008582', '28290000'), patcher.DEX['classes.dex'])
  self.assertIn((0x51ffe0, '1a00e6a9', '28290000'), patcher.DEX['classes.dex'])
  self.assertIn((0x57acb4, '6200bb741a010000', '1a00000011000000'), patcher.DEX['classes.dex'])
  self.assertIn((0x51feb4, '62022472', '11010000'), patcher.DEX['classes.dex'])
  self.assertIn((0x52003c, '6e1094e504000a02', '1101000000000000'), patcher.DEX['classes.dex'])

 def test_semantic_precondition_fails_closed(self):
  with zipfile.ZipFile(SOURCE) as z: original = bytearray(z.read('classes.dex'))
  original[0x529fea] = 0
  with self.assertRaises((ValueError,AssertionError)):
   patcher.plan_dex('classes.dex',original)

 def test_actual_apk_exact_changes_and_cfg(self):
  with tempfile.TemporaryDirectory() as tmp:
   target = OUTPUT
   if not target.exists():
    target = Path(tmp) / 'ssm_patched.apk'
    subprocess.run([sys.executable, str(Path(__file__).resolve().parent / 'patch_ssm.py'), str(SOURCE), str(target)], check=True)
   with zipfile.ZipFile(SOURCE) as src, zipfile.ZipFile(target) as dst:
    plans={n:patcher.ELF(src.read(n)).patches() for n in src.namelist() if n.startswith('lib/') and n.endswith('/libnative-lib.so')}
    patcher.check(SOURCE,target,plans)
    for name in plans:
     self.assertEqual((dst.getinfo(name).CRC, dst.getinfo(name).file_size),
                      (src.getinfo(name).CRC, src.getinfo(name).file_size))
    for name, patches in patcher.DEX.items():
     patcher.verify_dex_exact(src.read(name), dst.read(name), patches)

 def test_new_bytecode_and_cfg(self):
  with zipfile.ZipFile(SOURCE) as z: original=z.read('classes.dex')
  candidate=bytearray(original)
  for off,old,new in patcher.DEX['classes.dex']:
   self.assertEqual(original[off:off+len(bytes.fromhex(old))].hex(),old)
   candidate[off:off+len(bytes.fromhex(new))]=bytes.fromhex(new)
  patcher.validate_methods(candidate,patcher.DEX['classes.dex'])
  dex=patcher.DexFile(candidate)
  expected={'u0','Z','E','g0','k0','l0','N'}
  seen=set()
  for off,old,new in NEW_PATCHES:
   self.assertEqual(candidate[off:off+len(bytes.fromhex(new))].hex(),new)
   method=next(m for m in dex.methods if m.insns_off<=off<m.insns_off+2*m.insns_size)
   seen.add(method.name)
   dex.decode_method(method)
   self.assertIn(off,{i[1] for i in method.insns})
  self.assertEqual(seen,expected)
  for off,old,new in CERT_AND_AUDIT_PATCHES:
   self.assertEqual(candidate[off:off+len(bytes.fromhex(new))].hex(),new)
   method=next(m for m in dex.methods if m.insns_off<=off<m.insns_off+2*m.insns_size)
   dex.decode_method(method)
   self.assertIn(off,{i[1] for i in method.insns})
  # The new unconditional branches must land on actual instructions.
  for off,target in [(0x52a022,0x52a07c),(0x560ed4,0x560f10)]:
   self.assertEqual(off+2*struct.unpack_from('<b',candidate,off+1)[0],target)

 def test_validator_rejects_bad_branch_register_return_and_move_result(self):
  with zipfile.ZipFile(SOURCE) as z: original=z.read('classes.dex')
  for off,new in [(0x529fde,'2900ff7f'),(0x529fea,'12ff'),(0x552520,'0f0000000000'),(0x552520,'0a0000000000')]:
   with self.subTest(offset=hex(off),new=new):
    b=bytearray(original);b[off:off+len(bytes.fromhex(new))]=bytes.fromhex(new)
    with self.assertRaises(AssertionError):patcher.validate_methods(b,[(off,'',new)])

 def test_rejects_integer_and_uninitialized_object_returns(self):
  with zipfile.ZipFile(SOURCE) as z: original = z.read('classes.dex')
  for code in ('1210110000000000', '1100000000000000',
               '160000003800020012001100', '160000003200020012001100',
               '22000d2711000000'):
   data = bytearray(original)
   data[0x51fe58:0x51fe58+360] = bytes.fromhex(code).ljust(360, b'\0')
   with self.subTest(code=code), self.assertRaises(AssertionError):
    patcher.validate_methods(data, [(0x51fe58, '', code)])

  import struct
  dex = patcher.DexFile(original)
  method = next(m for m in dex.methods if m.code_off and m.return_type == 'Ljava/lang/String;' and m.registers_size >= 2 and m.insns_size >= 7 and not m.tries_size)
  cls = dex.type_ids.index('Ljava/lang/StringBuilder;')
  init = next(i for i,m in enumerate(dex.method_ids) if m['class_type'] == 'Ljava/lang/StringBuilder;' and m['name'] == '<init>' and m['proto'] == '()V')
  code = b'\x22\x00'+struct.pack('<H',cls)+b'\x70\x10'+struct.pack('<H',init)+b'\x00\x00\x11\x00'
  data = bytearray(original)
  data[method.insns_off:method.insns_off+method.insns_size*2] = code.ljust(method.insns_size*2-2, b'\0') + b'\x11\x00'
  with self.assertRaisesRegex(AssertionError, 'reference type mismatch'):
   patcher.validate_methods(data, [(method.insns_off, '', code.hex())])

 def test_reference_return_and_wide_branch_types(self):
  with zipfile.ZipFile(SOURCE) as z: original = z.read('classes.dex')
  dex = patcher.DexFile(original)
  method = next(m for m in dex.methods if m.code_off and m.return_type == 'Ljava/lang/String;' and m.registers_size >= 2 and m.insns_size >= 6 and not m.tries_size)
  cls = dex.type_ids.index('Ljava/util/ArrayList;')
  init = next(i for i,m in enumerate(dex.method_ids) if m['class_type'] == 'Ljava/util/ArrayList;' and m['name'] == '<init>' and m['proto'] == '()V')
  codes = [(b'\x22\x00'+struct.pack('<H',cls)+b'\x70\x10'+struct.pack('<H',init)+b'\x00\x00\x11\x00', 'reference type mismatch'),
           (bytes.fromhex('160000003800020012001100'), 'invalid zero-test operand'),
           (bytes.fromhex('160000003200020012001100'), 'incompatible equality operands')]
  for code, reason in codes:
   data = bytearray(original)
   data[method.insns_off:method.insns_off+method.insns_size*2] = code.ljust(method.insns_size*2-2, b'\0') + b'\x11\x00'
   with self.subTest(reason=reason), self.assertRaisesRegex(AssertionError, reason):
    patcher.validate_methods(data, [(method.insns_off, '', code.hex())])

 def test_real_arm64_common_bl_target(self):
  with zipfile.ZipFile(SOURCE) as z: b=z.read('lib/arm64-v8a/libnative-lib.so')
  elf=patcher.ELF(b)
  self.assertEqual({n:o for n,o,_ in elf.patches()}['checkSecurityStatus_body'],0x31694)
  # Retarget both wrappers: a hardcoded body offset would fail this test.
  changed=bytearray(b)
  for name in ('checkSecurityStatus','checkSecurityStatusWithBomb'):
   start=elf.file(elf.jni(name))
   for off in range(start,start+64,4):
    insn=struct.unpack_from('<I',b,off)[0]
    if insn & 0xfc000000 == 0x94000000:
     imm=insn & 0x3ffffff
     if imm & 0x2000000: imm-=0x4000000
     if elf.addr(off)+imm*4 == elf.addr(0x31694):
      delta=(elf.addr(0x31698)-elf.addr(off))//4
      struct.pack_into('<I',changed,off,0x94000000 | (delta & 0x3ffffff))
  self.assertEqual({n:o for n,o,_ in patcher.ELF(changed).patches()}['checkSecurityStatus_body'],0x31698)

class FullIntegrity(unittest.TestCase):
 def test_exact_planned_change_accepted(self):self.check_candidate(False)
 def test_rechecksummed_outside_window_change_rejected(self):self.check_candidate(True)
 def check_candidate(self,tamper):
  original=bytearray(128);original[:8]=b'dex\n035\0';original[40:42]=b'\x12\x01';patcher.fix_dex(original)
  candidate=bytearray(original);candidate[40:42]=b'\x12\x00'
  if tamper:candidate[100]^=1
  patcher.fix_dex(candidate)
  with tempfile.TemporaryDirectory() as directory:
   source,output=(Path(directory)/n for n in ('source.apk','output.apk'))
   for path,data in ((source,original),(output,candidate)):
    with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED) as archive:
     archive.writestr('classes.dex',data);archive.writestr('res/2p.xml',b'a');archive.writestr('res/2P.xml',b'b')
   with patch.object(patcher,'validate_methods'):
    if tamper:
     with self.assertRaisesRegex(ValueError,'unexpected DEX change'):patcher.check(source,output,{},{'classes.dex':[(40,'1201','1200')]})
    else:patcher.check(source,output,{},{'classes.dex':[(40,'1201','1200')]})

 def test_analysis_and_rea_evidence_completeness(self):
  import json
  from patcher_common import dump_analysis_json
  sample = {'byte_offset': 0, 'ref': 'A  B   C'}
  self.assertEqual(json.loads(dump_analysis_json({'items': [sample]})), {'items': [sample]})
  root = REPO_ROOT / 'ssm' / 'analysis'
  p1 = json.loads((root / 'ssm_patched_and_core_methods.json').read_text())
  p2 = json.loads((root / 'ssm_callgraph_and_signatures.json').read_text())
  p3 = json.loads((root / 'ssm_certificate_and_universal_audit.json').read_text())
  for d in p1['dex_analysis'].values():
   for m in d['methods']:
    self.assertIn('try_blocks', m)
    self.assertIn('before_instructions', m)
    self.assertIn('after_instructions', m)
  for m in p2['patched_methods_summary']:
   self.assertIn('try_blocks', m)
   self.assertIn('before_instructions', m)
   self.assertIn('after_instructions', m)
  self.assertGreaterEqual(len(p3['security_critical_methods']), 24)
  for sig, m in p3['security_critical_methods'].items():
   self.assertIn('try_blocks', m, sig)
   self.assertIn('before_instructions', m, sig)
   self.assertIn('after_instructions', m, sig)
   self.assertNotIn('before', m, sig)
   self.assertNotIn('after', m, sig)
  rea = json.loads((REPO_ROOT / 'ssm' / 'rea' / 'rea_ssm_evidence.json').read_text())
  import hashlib
  src_sha = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
  apk_sha = rea['canonical_artifacts']['patched_apk_sha256']
  self.assertEqual( len(apk_sha), 64 )
  if OUTPUT.is_file():
   self.assertEqual(hashlib.sha256(OUTPUT.read_bytes()).hexdigest(), apk_sha)
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
   target = OUTPUT
   if not target.is_file():
    target = Path(tmp) / 'ssm_patched.apk'
    subprocess.run([sys.executable, str(Path(__file__).resolve().parent / 'patch_ssm.py'), str(SOURCE), str(target)], check=True)
   size = target.stat().st_size
   self.assertEqual(rea['canonical_artifacts']['patched_apk_bytes'], size)
   self.assertEqual(rea['patched_apk_signature_inspection']['summary']['artifact']['bytes'], size)
   self.assertEqual(next(a for a in rea['artifacts'] if a['sha256'] == apk_sha)['size_bytes'], size)
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
    patcher.check(dup_src, dummy_out, {}, {})

if __name__=='__main__':unittest.main()
