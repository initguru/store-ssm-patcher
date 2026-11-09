"""Repository-local static DEX/ELF and whole-entry integrity regressions."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[2]
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

class PatchContract(unittest.TestCase):
 def test_semantic_plan_and_count(self):
  self.assertEqual([len(patcher.DEX[n]) for n in ('classes.dex','classes2.dex')], [50,4])
  self.assertTrue(set(NEW_PATCHES) <= set(patcher.DEX['classes.dex']))
  self.assertFalse({0x529fec,0x52a01c,0x52a064} & {o for o,_,_ in patcher.DEX['classes.dex']})
  with zipfile.ZipFile(SOURCE) as z:
   for name, expected in patcher.DEX.items():
    self.assertEqual(patcher.plan_dex(name,z.read(name)), expected)

 def test_semantic_precondition_fails_closed(self):
  with zipfile.ZipFile(SOURCE) as z: original = bytearray(z.read('classes.dex'))
  original[0x529fea] = 0
  with self.assertRaises((ValueError,AssertionError)):
   patcher.plan_dex('classes.dex',original)

 def test_actual_apk_exact_changes_and_cfg(self):
  with zipfile.ZipFile(SOURCE) as src, zipfile.ZipFile(OUTPUT) as dst:
   plans={n:patcher.ELF(src.read(n)).patches() for n in src.namelist() if n.startswith('lib/') and n.endswith('/libnative-lib.so')}
   patcher.check(SOURCE,OUTPUT,plans)
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
  # The new unconditional branches must land on actual instructions.
  for off,target in [(0x52a022,0x52a07c),(0x560ed4,0x560f10)]:
   self.assertEqual(off+2*struct.unpack_from('<b',candidate,off+1)[0],target)

 def test_validator_rejects_bad_branch_register_return_and_move_result(self):
  with zipfile.ZipFile(SOURCE) as z: original=z.read('classes.dex')
  for off,new in [(0x529fde,'2900ff7f'),(0x529fea,'12ff'),(0x552520,'0f0000000000'),(0x552520,'0a0000000000')]:
   with self.subTest(offset=hex(off),new=new):
    b=bytearray(original);b[off:off+len(bytes.fromhex(new))]=bytes.fromhex(new)
    with self.assertRaises(AssertionError):patcher.validate_methods(b,[(off,'',new)])

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
   with patch.object(patcher,'DEX',{'classes.dex':[(40,'1201','1200')]}),patch.object(patcher,'validate_methods'):
    if tamper:
     with self.assertRaisesRegex(ValueError,'unexpected DEX change'):patcher.check(source,output,{})
    else:patcher.check(source,output,{})

if __name__=='__main__':unittest.main()
