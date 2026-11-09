#!/usr/bin/env python3
"""Strict SSM APK patcher; run with python3 -I from outside extracted inputs."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile
import zipfile
import zlib

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
 (0x529fec,'6e30325b2005','000000000000'),
 (0x52a01c,'6e30f00b1502','000000000000'),
 (0x52a064,'6e30f00b0501','000000000000'),(0x4ce692,'13020020','13020000'),
 (0x4ce7ee,'13000020','13000000'),(0x4d9602,'13000020','13000000'),
 (0x4d9eaa,'13000020','13000000'),(0x4db652,'13000020','13000000')]

# Reuse the single DEX validator already used by the signing dependency.
def validate_methods(d, p):
 spec=importlib.util.spec_from_file_location('store_validator',Path(__file__).with_name('patch_store.py'))
 assert spec is not None and spec.loader is not None
 store=importlib.util.module_from_spec(spec);spec.loader.exec_module(store)
 store.validate_methods(d,p)

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
   found.append(('checkSecurityStatus_body',0x31694,bytes.fromhex(zero)))
  return found

def dex_valid(b):
 assert b[12:32]==hashlib.sha1(b[32:]).digest(),'DEX SHA-1 mismatch'
 assert struct.unpack_from('<I',b,8)[0]==zlib.adler32(b[12:])&0xffffffff,'DEX Adler32 mismatch'

def fix_dex(b):
 b[12:32]=hashlib.sha1(b[32:]).digest()
 struct.pack_into('<I',b,8,zlib.adler32(b[12:])&0xffffffff)
 return b

def removed(name):
 upper=name.upper()
 return upper=='META-INF/MANIFEST.MF' or upper.startswith('META-INF/') and upper.endswith(('.SF','.RSA','.DSA'))

def run(args):
 p=subprocess.run([str(a) for a in args],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 print(p.stdout, end='')
 if p.returncode: raise RuntimeError('command failed: '+str(args[0]))
 return p.stdout

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
    dex_valid(b)
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

def main():
 p=argparse.ArgumentParser();p.add_argument('source');p.add_argument('output');p.add_argument('--red',action='store_true');a=p.parse_args()
 src=Path(a.source).resolve(); out=Path(a.output).resolve()
 assert src!=out and not out.exists(),'refusing overwrite'
 replacements={};plans={}
 with zipfile.ZipFile(src) as z:
  for n,patches in DEX.items():
   b=bytearray(z.read(n));dex_valid(b)
   extracted=Path('/tmp/ssm_re_work/ssm')/n
   assert extracted.read_bytes()==b,(n,'extracted original mismatch')
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
  tmp=Path(tmp);unsigned=tmp/'unsigned.apk';aligned=tmp/'aligned.apk';signed=tmp/'signed.apk';v1=tmp/'v1.apk'
  work=Path(__file__).resolve().parent;ks=work/'re_release.keystore'
  assert ks.is_file(),'existing signing keystore required'
  spec=importlib.util.spec_from_file_location('patch_store',work/'patch_store.py')
  assert spec is not None and spec.loader is not None
  store=importlib.util.module_from_spec(spec);spec.loader.exec_module(store)
  store.repack(src,unsigned,replacements,True)
  run(['jarsigner','-keystore',ks,'-storepass','changeit','-sigalg','SHA256withRSA','-digestalg','SHA-256','-signedjar',v1,unsigned,'re_release'])
  store.repack(v1,aligned)
  run(['openssl','pkcs12','-in',ks,'-passin','pass:changeit','-nodes','-nocerts','-out',tmp/'key.pem'])
  run(['openssl','pkcs12','-in',ks,'-passin','pass:changeit','-clcerts','-nokeys','-out',tmp/'cert.pem'])
  store.v2(aligned,signed,tmp)
  check(src,signed,plans)
  verification=run(['jarsigner','-verify',signed])
  assert 'jar verified.' in verification
  print('v2 RSA signature verified with OpenSSL; Android platform verifier not executed')
  with open(signed,'rb') as source,open(out,'xb') as dest:
   while True:
    chunk=source.read(1024*1024)
    if not chunk:break
    dest.write(chunk)
 print('OUTPUT',out,'SHA256',hashlib.sha256(out.read_bytes()).hexdigest())
 print('Signed with existing local re_release keystore; cannot update an original-signed installation.')
if __name__=='__main__':main()
