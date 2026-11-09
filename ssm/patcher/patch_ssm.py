#!/usr/bin/env python3
"""Strict SSM APK patcher; run with python3 -I from outside extracted inputs."""
import argparse
import hashlib
import sys
from pathlib import Path
import struct
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from patcher_common import (DEFAULT_KEYSTORE, DexFile, build_signed_apk, dex_valid,
 find_unique_insn_offset, find_unique_method, fix_dex,
 run, validate_methods, verify_dex_exact)

__all__ = ['verify_dex_exact']

DEX = {
 'classes.dex': [
 (0x5768b4,'63002f72','1214280b'),
 (0x55fcc2,'38000a00','28090000'),
 (0x5291f6,'38000300','00000000'),
 (0x52a202,'38000300','00000000'),
 (0x52a234,'38000300','00000000'),
 (0x548818,'22008726','12000f00'),
 (0x58006e,'0a01','1201'),
 (0x57fa34,'1a00fa5a','0e000000'),
 (0x5401da,'1a01487a71203cff13000c01','1a01120b0000000000000000'),
 (0x4fdbec,'0a06','1216'),
 (0x4eadda,'0a03','1213'),
 (0x4ee052,'0a03','1213'),
 (0x4f1bda,'0a03','1213'),
 (0x4f5862,'0a03','1213'),
 (0x50e90c,'0a04','1214'),
 (0x50ec16,'0a05','1215'),
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
 'classes2.dex': [(0xb3e66,'6e309d023001','000000000000'),(0xb3e6c,'0a03','1203'),
 (0xb4c70,'7100b70200000c00','12100f0000000000'),(0xb34c4,'7100860200000c00','12000f0000000000')]
}

DEX['classes.dex'] += [
 (0x5766bc,'62008474','12100f00'),(0x571b0c,'120054318f74','12100f000000'),
 (0x55fba0,'6200bd73','12100f00'),(0x560f68,'6200bd73','0e000000'),
 (0x529fde,'32504f00','00000000'),(0x529fea,'b715','1205'),
 (0x52a006,'32503b00','00000000'),(0x52a00e,'38051600','00000000'),
 (0x52a022,'6005c507','282d0000'),(0x528fa4,'32302000','00000000'),
 (0x528fb0,'df030301','12030000'),(0x528fce,'32300b00','00000000'),
 (0x528fda,'df030301','12030000'),(0x502f8a,'1215','1205'),
 (0x560e98,'b725','1205'),(0x560ed4,'39051e00','281e0000'),
 (0x552520,'71004eea0000','0e0000000000'),(0x5526c4,'1a00516b','0e000000'),
 (0x551cc0,'22008726','0e000000'),(0x4ce692,'13020020','13020000'),
 (0x4ce7ee,'13000020','13000000'),(0x4d9602,'13000020','13000000'),
 (0x4d9eaa,'13000020','13000000'),(0x4db652,'13000020','13000000')]

# Independent, version-specific semantic identities. No absolute file offsets are
# used to select a method; relative instruction positions disambiguate repeats.
SEMANTIC_METHODS = [
 ('policy/ss/util/SamsungInterface','D1','(Z)Z',49,5),
 ('policy/o0/i/a','G0','(Z)Z',47,6),
 ('policy/z/h/a','d0','(Z)V',94,6),
 ('policy/z/h/a','x0','(Z)V',70,5),
 ('policy/i0/b','E','(Ljava/lang/String;)Z',73,4),
 ('policy/util/r','b','()Z',60,5),
 ('policy/util/MeatGrinder','onNativeSecurityCritical','()V',17,1),
 ('policy/gid20/l/c','h','(Landroid/content/Context;)Ljava/lang/String;',33,4),
 ('init/f1$c','b','(Lretrofit2/d;Lretrofit2/r;)V',320,13),
 ('init/o0$e','b','(Lretrofit2/d;Lretrofit2/r;)V',267,10),
 ('init/p0$f','b','(Lretrofit2/d;Lretrofit2/r;)V',267,10),
 ('init/q0$d','b','(Lretrofit2/d;Lretrofit2/r;)V',267,10),
 ('init/r0$e','b','(Lretrofit2/d;Lretrofit2/r;)V',267,10),
 ('policy/PolicyService$b','b','(Lretrofit2/d;Lretrofit2/r;)V',289,8),
 ('policy/PolicyService$c','b','(Lretrofit2/d;Lretrofit2/r;)V',273,10),
 ('policy/ss/util/SamsungInterface','O0','(ZLjava/lang/Class;)Z',87,8),
 ('policy/ss/util/a','u','(Z)Z',72,5),
 ('policy/i0/j/a','L','(Landroid/content/Context;)V',127,6),
 ('policy/i0/j/a','n0','(Landroid/content/Context;Z)V',59,6),
 ('policy/i0/j/a','T','(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Z)I',688,28),
 ('init/c1','z','(Landroid/content/Context;)Z',24,4),
 ('SamsungELMActivity','M','(Landroid/content/Context;)Z',40,4),
 ('lib/f','g0','(Landroid/content/Context;)Z',42,4),
 ('lib/f','h0','(Landroid/content/Context;)Z',42,4),
 ('policy/ss/util/SamsungInterface','z1','(Z)Z',35,5),
 ('policy/ss/util/a','O','(Z)Z',72,5),
 ('policy/o0/i/a','E0','(Z)Z',96,6),
 ('policy/o0/i/a','i0','(Ljava/util/List;)V',62,5),
 ('InoutActivity','b2','(Landroid/content/DialogInterface;I)V',19,3),
 ('InoutActivity','onCreate','(Landroid/os/Bundle;)V',648,7),
 ('PrivacyActivity','onCreate','(Landroid/os/Bundle;)V',147,7),
 ('QrcodeActivity','onCreate','(Landroid/os/Bundle;)V',200,4),
 ('SamsungELMActivity','onCreate','(Landroid/os/Bundle;)V',46,3),
 ('policy/z/h/a','u0','(Z)V',109,6),
 ('policy/z/h/a','Z','(Z)V',61,4),
 ('lib/a','E','(Z)V',37,6),
 ('policy/o0/i/a','g0','(Z)V',104,6),
 ('policy/i0/j/a','k0','(Landroid/content/Context;)V',188,9),
 ('policy/i0/j/a','l0','(Landroid/content/Context;Landroid/net/Uri;)V',124,11),
 ('policy/i0/j/a','N','(Landroid/content/Context;I)V',148,10),
 ('watcher/WatchingService$k','k','(Landroid/content/Context;)V',30,4),
 ('watcher/WatchingService','W','(Landroid/content/Context;)Z',60,4),
 ('watcher/WatchingService$k','t','(Landroid/content/Context;Ljava/util/List;)Z',221,11),
]
# Method identity index and byte-relative instruction position, in DEX table order.
SEMANTIC_SITES = {
 'classes.dex': [(0,12),(1,18),(2,46),(3,54),(3,104),(4,0),(5,26),(6,0),
 (7,26),(8,432),(9,354),(10,354),(11,354),(12,354),(13,272),(14,314),
 (7,22),(15,0),(16,0),(17,214),(18,46),(19,0),(20,0),(21,0),(22,0),(23,0),
 (24,0),(25,0),(26,0),(27,0),(33,58),(33,70),(33,98),(33,106),(33,126),
 (34,56),(34,68),(34,98),(34,110),(35,42),(36,48),(36,108),(37,0),(38,0),(39,0),
 (28,26),(29,22),(30,22),(31,22),(32,22)],
 'classes2.dex': [(40,30),(40,36),(41,0),(42,0)]
}

SEMANTIC_FEATURES = {
 0: dict(required_strings=('DEBUG - block USB',)),
 1: dict(required_strings=('DEBUG - block USB',)),
 2: dict(required_strings=('setDeveloperMode : ',)),
 3: dict(required_strings=('setUsbState : ',)),
 5: dict(required_strings=('rootReason',)),
 6: dict(required_strings=('Security Critical: Starting shutdown sequence from Native signal',)),
 7: dict(required_strings=('com.sktelecom.ssm','currentSignature')),
 16: dict(required_calls=('Lcom/samsung/android/knox/restriction/RestrictionPolicy;->setCameraState(Z)Z',)),
 25: dict(required_calls=('Lcom/samsung/android/knox/restriction/RestrictionPolicy;->setScreenCapture(Z)Z',)),
 33: dict(required_strings=('setScreenCaptureState : ',), required_fields=('Landroid/os/Build$VERSION;->SDK_INT:I',),
          required_calls=('Landroid/app/admin/DevicePolicyManager;->clearProfileOwner(Landroid/content/ComponentName;)V',)),
 34: dict(required_strings=('setCameraState : ',), required_calls=('Landroid/app/admin/DevicePolicyManager;->setCameraDisabled(Landroid/content/ComponentName;Z)V',)),
 35: dict(required_strings=('device_policy',), required_calls=('Landroid/app/admin/DevicePolicyManager;->setCameraDisabled(Landroid/content/ComponentName;Z)V',)),
 36: dict(required_strings=('device_policy',), required_fields=('Landroid/os/Build$VERSION;->SDK_INT:I',)),
 37: dict(required_calls=('Landroid/database/Cursor;->close()V',)),
 38: dict(required_strings=(';',)),
 39: dict(required_strings=('40','41')),
}

def plan_dex(dex_name, dex_bytes):
 dex = DexFile(dex_bytes)
 sites = SEMANTIC_SITES[dex_name]
 assert len(sites) == len(DEX[dex_name])
 plan = []
 for index, ((identity, relative), (_, old, new)) in enumerate(zip(sites, DEX[dex_name])):
  cls, name, proto, size, registers = SEMANTIC_METHODS[identity]
  rid = f'{dex_name}:{index}'
  method = find_unique_method(dex, rid, class_filter='Lcom/sktelecom/ssm/'+cls+';',
   name_filter=name, proto=proto, insns_size=size, registers_size=registers,
   **SEMANTIC_FEATURES.get(identity, {}))
  off = find_unique_insn_offset(dex, method, rid, pattern=old, rel_off=relative)
  if len(bytes.fromhex(old)) != len(bytes.fromhex(new)):
   raise ValueError(f'{rid}: unequal patch widths')
  plan.append((off, old, new))
 if plan != DEX[dex_name]:
  raise ValueError(f'{dex_name}: semantic plan differs from version-specific contract')
 return plan

class ELF:
 def __init__(self,b):
  self.b=b; assert b[:4]==b'\x7fELF' and b[5]==1
  self.w=b[4]==2; self.step=8 if self.w else 4
  self.machine=struct.unpack_from('<H',b,18)[0]
  off=struct.unpack_from('<Q' if self.w else '<I',b,40 if self.w else 32)[0]
  size,count=struct.unpack_from('<HH',b,58 if self.w else 46)
  fmt='<IIQQQQIIQQ' if self.w else '<IIIIIIIIII'
  self.ss=[struct.unpack_from(fmt,b,off+i*size) for i in range(count)]
  self.symbols={}; self.reloc={}
  for s in self.ss:
   if s[1]==11:
    st=self.ss[s[6]]; strings=b[st[4]:st[4]+st[5]]
    for o in range(s[4],s[4]+s[5],s[9]):
     if self.w: name,_,_,sec,val,_=struct.unpack_from('<IBBHQQ',b,o)
     else: name,val,_,_,_,sec=struct.unpack_from('<IIIBBH',b,o)
     end=strings.find(b'\0',name); key=strings[name:end].decode(errors='replace')
     if sec: self.symbols[key]=val
   elif s[1]==4:
    for o in range(s[4],s[4]+s[5],s[9]):
     target,_,addend=struct.unpack_from('<QQq' if self.w else '<IIi',b,o)
     self.reloc[target]=addend
 def file(self,addr):
  if self.machine==40: addr &= ~1
  for s in self.ss:
   if s[1]!=8 and s[3]<=addr<s[3]+s[5]: return addr-s[3]+s[4]
  raise ValueError('unmapped address '+hex(addr))
 def addr(self,off):
  for s in self.ss:
   if s[1]!=8 and s[4]<=off<s[4]+s[5] and s[2]&2: return off-s[4]+s[3]
  raise ValueError('unmapped offset '+hex(off))
 def ptr(self,off):
  return self.reloc.get(self.addr(off),struct.unpack_from('<Q' if self.w else '<I',self.b,off)[0])
 def jni(self,name):
  raw=name.encode()+b'\0'; at=self.b.find(raw); assert at>=0 and self.b.find(raw,at+1)<0
  address=self.addr(at); hits=[]
  for s in self.ss:
   if s[2]&3!=3 or s[1]==8: continue
   for o in range(s[4],s[4]+s[5]-3*self.step+1,self.step):
    if self.ptr(o)==address:
     signature=self.file(self.ptr(o+self.step))
     assert self.b[signature:signature+30].startswith(b'(Landroid/content/Context;Z)I\0')
     hits.append(self.ptr(o+2*self.step))
  assert len(hits)==1,(name,hits)
  return hits[0]
 def patches(self):
  zero={183:'00008052c0035fd6',40:'00207047',3:'31c0c3',62:'31c0c3'}[self.machine]
  ret={183:'c0035fd6',40:'7047',3:'c3',62:'c3'}[self.machine]
  found=[]
  for name in ['checkSecurityStatus','checkSecurityStatusWithBomb','isFoundDangerousProps','isFoundDangerousPropsAndroid14','_Z17delayedKillSwitchv']:
   address=self.jni(name) if name.startswith('check') else self.symbols[name]
   off=self.file(address); patch=bytes.fromhex(ret if name.startswith('_Z17') else zero)
   if self.machine==40: assert address&1,'expected Thumb function'
   if self.machine==183:
    expected={'checkSecurityStatus':0x314d4,'checkSecurityStatusWithBomb':0x314e4,'isFoundDangerousProps':0x32630,'_Z17delayedKillSwitchv':0x32bcc}
    if name in expected: assert off==expected[name],(name,hex(off))
   found.append((name,off,patch))
  if self.machine==183:
   targets=[]
   for name in ('checkSecurityStatus','checkSecurityStatusWithBomb'):
    start=self.file(self.jni(name)); calls=set()
    for off in range(start,start+16*4,4):
     insn=struct.unpack_from('<I',self.b,off)[0]
     if (insn & 0xfc000000)==0x94000000:
      imm=insn & 0x3ffffff
      if imm & 0x2000000: imm-=0x4000000
      calls.add(self.addr(off)+imm*4)
    targets.append(calls)
   common=targets[0] & targets[1]
   if len(common)!=1: raise ValueError(('ambiguous security body',sorted(common)))
   found.append(('checkSecurityStatus_body',self.file(common.pop()),bytes.fromhex(zero)))
  return found

def removed(name):
 upper=name.upper()
 return upper=='META-INF/MANIFEST.MF' or upper.startswith('META-INF/') and upper.endswith(('.SF','.RSA','.DSA'))

def check(original,output,plans):
 with zipfile.ZipFile(original) as src,zipfile.ZipFile(output) as dst:
  originals={i.filename:i for i in src.infolist() if not removed(i.filename)}
  actual={i.filename:i for i in dst.infolist()}
  assert len(actual)==len(dst.infolist()),'duplicate output entries'
  assert originals.keys()<=actual.keys(),'missing original entries'
  added=actual.keys()-originals.keys()
  assert all(removed(n) for n in added),('unexpected entries',added)
  for n,i in originals.items():
   assert dst.getinfo(n).compress_type==i.compress_type,(n,'compression changed')
   b=dst.read(n)
   if n in DEX:
    expected_dex=bytearray(src.read(n))
    for off,old,new in DEX[n]:
     before,after=bytes.fromhex(old),bytes.fromhex(new)
     if len(before)!=len(after) or expected_dex[off:off+len(before)]!=before:
      raise ValueError((n,hex(off),'original mismatch'))
     expected_dex[off:off+len(after)]=after
    fix_dex(expected_dex)
    if b!=expected_dex:
     raise ValueError((n,'unexpected DEX change'))
    assert dex_valid(b), (n,'invalid DEX checksums')
    validate_methods(b,DEX[n])
    for off,_,new in DEX[n]:
     assert b[off:off+len(bytes.fromhex(new))]==bytes.fromhex(new),(n,hex(off),'patch absent')
     print(n,hex(off),new)
    print(n,'SHA-1 and Adler32 OK')
   elif n in plans:
    original=src.read(n); expected=bytearray(original)
    for symbol,off,patch in plans[n]:
     expected[off:off+len(patch)]=patch
     assert b[off:off+len(patch)]==patch,(n,symbol,'patch absent')
     print(n,symbol,hex(off),patch.hex())
    assert b==expected,(n,'unexpected native change')
   else: assert b==src.read(n),(n,'content changed')
  raw=Path(output).read_bytes();stored=0;native=0
  for entry in dst.infolist():
   if entry.compress_type==zipfile.ZIP_STORED:
    nl,el=struct.unpack_from('<HH',raw,entry.header_offset+26)
    alignment=4096 if entry.filename.endswith('.so') else 4
    assert (entry.header_offset+30+nl+el)%alignment==0,(entry.filename,'misaligned')
    stored+=1;native+=int(entry.filename.endswith('.so'))
  print('STORED alignment OK:',stored,'entries; 4096-byte native entries:',native,'; others 4-byte')
  assert 'res/2p.xml' in actual and 'res/2P.xml' in actual
  print('ZIP entries original:',len(src.infolist()),'output:',len(dst.infolist()),'retained:',len(originals),'signing entries:',len(added))
  print('Case-distinct res/2p.xml and res/2P.xml both retained')

def regenerate_analysis(source, output):
 """Regenerate static evidence from independently decoded APK DEX streams.

 Incoming edges enumerate every explicit invoke instruction in every code-bearing
 method of every DEX, not reflection, virtual dispatch expansion or native calls.
 """
 import json
 root=Path(__file__).resolve().parents[2] / 'ssm' / 'analysis'
 first=root/'ssm_patched_and_core_methods.json'
 second=root/'ssm_callgraph_and_signatures.json'
 previous=json.loads(first.read_text())
 summaries=json.loads(second.read_text())['patched_methods_summary']
 selected={(r['dex'],r['method']) for r in summaries}
 for n,section in previous['dex_analysis'].items():
  methods=section.get('methods',[])
  for record in (methods.values() if isinstance(methods,dict) else methods):
   signature=record.get('method',record.get('signature'))
   if signature: selected.add((n,signature))
 before={};after={}; incoming={}; after_incoming={}
 with zipfile.ZipFile(source) as src,zipfile.ZipFile(output) as dst:
  for name in src.namelist():
   if not (name.startswith('classes') and name.endswith('.dex')):continue
   before[name]=DexFile(src.read(name));after[name]=DexFile(dst.read(name))
   for dex,edges in ((before[name],incoming),(after[name],after_incoming)):
    for m in dex.methods:
     if not m.code_off:continue
     dex.decode_method(m)
     for relative,off,_,op,_,ref in m.insns:
      if op in (*range(0x6e,0x73),*range(0x74,0x79)):
       edges.setdefault(ref,[]).append(dict(dex=name,method=m.signature,file_offset=hex(off),byte_offset=relative))
   for m in before[name].methods:
    if any(m.insns_off<=o<m.insns_off+2*m.insns_size for o,_,_ in DEX.get(name,[])):
     selected.add((name,m.signature))
  native={}
  for name in src.namelist():
   if name.startswith('lib/') and name.endswith('/libnative-lib.so'):
    b=src.read(name)
    native[name]=[dict(symbol=s,offset=hex(o),orig_hex=b[o:o+len(p)].hex(),patch_hex=p.hex()) for s,o,p in ELF(b).patches()]
 def instructions(m):
  return [dict(byte_offset=r,file_offset=hex(o),width=w,opcode=hex(op),raw_hex=raw.hex(),ref=ref) for r,o,w,op,raw,ref in m.insns]
 records=[]
 for name,signature in sorted(selected):
  if name not in before:continue
  m=next((m for m in before[name].methods if m.signature==signature),None)
  if m is None or not m.code_off:continue
  a=next(m for m in after[name].methods if m.signature==signature)
  patches=[dict(offset=hex(o),old=old,new=new) for o,old,new in DEX.get(name,[]) if m.insns_off<=o<m.insns_off+2*m.insns_size]
  records.append(dict(dex=name,method=signature,code_item=hex(m.code_off),insns_start=hex(m.insns_off),
   header=dict(registers=m.registers_size,ins=m.ins_size,outs=m.outs_size,tries=m.tries_size,insns_size_cu=m.insns_size),
   has_patch=bool(patches),patch_tuples=patches,before_instructions=instructions(m),after_instructions=instructions(a),
   unique_strings=sorted(m.strings),unique_calls=sorted(m.calls),unique_fields=sorted(m.fields),
   incoming_callers=incoming.get(signature,[]),after_incoming_callers=after_incoming.get(signature,[])))
 dex_analysis: dict[str, dict] = {}
 evidence=dict(apk=Path(source).name,patch_tuple_count=sum(map(len,DEX.values())),native_analysis=native,dex_analysis=dex_analysis)
 for name,patches in DEX.items():
  methods=[r for r in records if r['dex']==name]
  dex_analysis[name]=dict(patch_tuples=[dict(offset=hex(o),old=old,new=new) for o,old,new in patches],method_count=len(methods),methods=methods)
 first.write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+'\n')
 second.write_text(json.dumps(dict(patch_tuple_count=sum(map(len,DEX.values())),incoming_callers_coverage='All explicit invoke sites across all APK DEX methods; no runtime dispatch or reflection inference',patched_methods_summary=records),ensure_ascii=False,indent=2)+'\n')

def main():
 p=argparse.ArgumentParser();p.add_argument('source');p.add_argument('output');p.add_argument('--red',action='store_true');p.add_argument('--regenerate-analysis',action='store_true');a=p.parse_args()
 src=Path(a.source).resolve(); out=Path(a.output).resolve()
 assert src!=out and not out.exists(),'refusing overwrite'
 replacements={};plans={}
 with zipfile.ZipFile(src) as z:
  for n,patches in DEX.items():
   b=bytearray(z.read(n));assert dex_valid(b),(n,'invalid input DEX')
   patches=plan_dex(n,b)
   for off,old,new in patches:
    before=bytes.fromhex(old);after=bytes.fromhex(new)
    assert len(before)==len(after)
    assert b[off:off+len(before)]==before,(n,hex(off),'original mismatch')
    b[off:off+len(after)]=after
   validate_methods(b,patches)
   replacements[n]=fix_dex(b)
  for n in z.namelist():
   if not n.startswith('lib/') or not n.endswith('/libnative-lib.so'):continue
   b=z.read(n);elf=ELF(b);plans[n]=elf.patches();changed=bytearray(b)
   for symbol,off,patch in plans[n]:
    before=b[off:off+len(patch)]
    assert before!=patch and len(before)==len(patch),(n,symbol,'unexpected original')
    print('Native plan',n,symbol,hex(off),'original',before.hex(),'patch',patch.hex())
    changed[off:off+len(patch)]=patch
   replacements[n]=changed
 assert len(plans)==4
 if a.red:
  check(src,src,plans)
  raise AssertionError('RED expected failure did not occur')
 with tempfile.TemporaryDirectory(prefix='ssm-build-') as tmp:
  tmp=Path(tmp);signed=tmp/'signed.apk';ks=DEFAULT_KEYSTORE
  build_signed_apk(src, signed, replacements, ks)
  check(src, signed, plans)
  verification=run('jarsigner','-verify',signed)
  assert b'jar verified.' in verification
  print('v2 RSA signature verified with OpenSSL; Android platform verifier not executed')
  with open(signed,'rb') as source,open(out,'xb') as dest:
   while True:
    chunk=source.read(1024*1024)
    if not chunk:break
    dest.write(chunk)
 if a.regenerate_analysis:regenerate_analysis(src,out)
 print('OUTPUT',out,'SHA256',hashlib.sha256(out.read_bytes()).hexdigest())
 print('Signed with existing local re_release keystore; cannot update an original-signed installation.')
if __name__=='__main__':main()
