#!/usr/bin/env python3
import argparse, copy, hashlib, re, struct, subprocess, zipfile, zlib
from pathlib import Path
U=lambda b,o:struct.unpack_from('<I',b,o)[0]
def uleb(b,o):
 v=s=0
 while True:
  x=b[o];o+=1;v|=(x&127)<<s
  if x<128:return v,o
  s+=7
def methods(d):
 strings=[]
 for i in range(U(d,56)):
  o=U(d,U(d,60)+4*i);_,o=uleb(d,o);e=d.index(0,o);strings.append(d[o:e].decode('utf8','replace'))
 types=[strings[U(d,U(d,68)+4*i)] for i in range(U(d,64))]
 prot=[]
 for i in range(U(d,72)):
  o=U(d,76)+12*i;r=types[U(d,o+4)];p=U(d,o+8)
  args='' if not p else ''.join(types[struct.unpack_from('<H',d,p+4+j*2)[0]] for j in range(U(d,p)))
  prot.append('('+args+')'+r)
 mids=[]
 for i in range(U(d,88)):
  c,p,n=struct.unpack_from('<HHI',d,U(d,92)+8*i);mids.append((types[c],strings[n],prot[p]))
 out={}
 for i in range(U(d,96)):
  o=U(d,U(d,100)+32*i+24)
  if not o:continue
  counts=[]
  for _ in range(4):v,o=uleb(d,o);counts.append(v)
  for _ in range(counts[0]+counts[1]):_,o=uleb(d,o);_,o=uleb(d,o)
  for count in counts[2:]:
   idx=0
   for _ in range(count):
    v,o=uleb(d,o);idx+=v;_,o=uleb(d,o);co,o=uleb(d,o)
    if co:out[mids[idx]]=co
 return out
FIX=[(0x3a4f16,'6e30230c3103','000000000000'),(0x3a4fb2,'39011600','28160000'),(0x3a4a4e,'1a038226','2900e202'),(0x31f70e,'6e30230c2002','000000000000')]
FIX += [(0x3120b2,'170000008000','190000400000'),(0x312cec,'2200b300','0e000000'),(0x318068,'71006a2600000a00','12100f0000000000'),(0x3180b8,'71005e2600000a00','12100f0000000000'),(0x3181b8,'6200c513','0e000000'),(0x318218,'710066260000','0e0000000000'),(0x319150,'6900ee13','12000f00'),(0x319754,'2200f208','0e000000'),(0x31c0fc,'7110b62607000a00','12000f0000000000'),(0x31c180,'6e10850306000c06','0e00000000000000'),(0x31c33c,'14006456a4e3','12100f000000')]
# Patch only the signkey entry; preserve the local database key derivation.
ENTRY_OLD='6e10730304000c006e10860300000c006e10730304000c046e10870304000c046001290113021c00120334211500150100086e30020440010c047110730004000c047110890004000c0446040403280d'
ENTRY_NEW='281000000003010014000000e8404b806937b690b087fecca7845f7dfa34371e1300140023040e0e2604eeffffff1203282d000000000000000000000000000000000000000000000000000000000000'
FIX += [(0x3e7338,ENTRY_OLD,ENTRY_NEW)]
NATIVE={
 'arm64-v8a':[(0x2322c,'10f7ff97','e6ffff17'),(0x21f5c,'ff4305d1','c0035fd6'),(0x244a4,'fd7bbfa9','c0035fd6'),(0x232cc,'fd7bbca9','c0035fd6')],
 'armeabi-v7a':[(0x116cc,'fef770fb','dfe700bf'),(0x10960,'f0b5','7047'),(0x12328,'80b5','7047'),(0x11798,'f0b5','7047')],
 'x86':[(0x28d20,'e87bdbffff','e9b0000000'),(0x27b10,'55','c3'),(0x29f50,'55','c3'),(0x28e20,'55','c3')],
 'x86_64':[(0x277a1,'e85adbffff','e9a8000000'),(0x26550,'55','c3'),(0x28bf0,'50','c3'),(0x278a0,'55','c3')]}
ZW=[(0x815f0,'ff0740d1ff4301d1','00008052c0035fd6'),(0x83e68,'21001d32','1f2003d5'),(0x84150,'01008012','01008052'),(0x88060,'010447b9','13000014'),(0x881e0,'35010034','09000014'),(0x88214,'d37efe97','1f2003d5'),(0x91698,'d6bfff97','1f2003d5'),(0x916c4,'a759fe97','1f2003d5')]
CRC={'arm64-v8a':0x14661592,'armeabi-v7a':0x92e39496,'x86':0x900c9ec8,'x86_64':0x5d8fafd7}
def plan(d):
 for o in (0x3e73c2,0x27b21e):assert d[o:o+8].hex()=='12207120d9080400'
 for o,old,new in FIX:
  assert len(old)==len(new)
  assert d[o:o+len(bytes.fromhex(old))].hex()==old,hex(o)
 return list(FIX)
def native_plans():
 return {**{'lib/'+abi+'/libsecurity-checker-lib.so':p for abi,p in NATIVE.items()},'lib/arm64-v8a/libzwfeyyadt.so':ZW}
def restore_crc(b,o,target):
 assert 0<=o<=len(b)-4
 base=zlib.crc32(b)&0xffffffff; basis={}
 for bit in range(32):
  b[o+bit//8]^=1<<(bit%8);v=(zlib.crc32(b)&0xffffffff)^base;b[o+bit//8]^=1<<(bit%8);mask=1<<bit
  while v:
   k=v.bit_length()-1
   if k not in basis:basis[k]=(v,mask);break
   v0,m0=basis[k];v^=v0;mask^=m0
 assert len(basis)==32
 v=base^target;mask=0
 while v:
  v0,m0=basis[v.bit_length()-1];v^=v0;mask^=m0
 for bit in range(32):
  if mask>>bit&1:b[o+bit//8]^=1<<(bit%8)
 assert zlib.crc32(b)&0xffffffff==target

def correction_offset(b):
 assert b[:4]==b'\x7fELF' and b[5]==1
 wide=b[4]==2
 ph,sh=struct.unpack_from('<QQ' if wide else '<II',b,32 if wide else 28)
 pe,pn,se,sn,si=struct.unpack_from('<HHHHH',b,54 if wide else 42)
 sections=[struct.unpack_from('<IIQQQQIIQQ' if wide else '<IIIIIIIIII',b,sh+i*se) for i in range(sn)]
 st=sections[si];names=b[st[4]:st[4]+st[5]];candidates=[]
 protected=[(0,64 if wide else 52),(ph,ph+pe*pn),(sh,sh+se*sn),(st[4],st[4]+st[5])]
 for i in range(pn):
  p=struct.unpack_from('<IIQQQQQQ' if wide else '<IIIIIIII',b,ph+i*pe)
  if p[0]==1:protected.append((p[2] if wide else p[1],(p[2] if wide else p[1])+p[5 if wide else 4]))
 for s in sections:
  if names[s[0]:].split(b'\0')[0]==b'.comment' and s[5]>=16:candidates.append(s[4]+8)
 for o in candidates:
  if all(o+4<=a or o>=e for a,e in protected):return o
 raise AssertionError('No safe .comment CRC correction slot')
def patch_native(name,original):
 b=bytearray(original);target=zlib.crc32(original)&0xffffffff
 if name.endswith('libzwfeyyadt.so'):
  assert len(b)==690220 and target==0x5de340e3;o=0xa8828
 else:
  assert target==CRC[name.split('/')[1]];o=correction_offset(b)
 for off,old,new in native_plans()[name]:
  assert len(old)==len(new) and b[off:off+len(bytes.fromhex(old))].hex()==old,(name,hex(off))
  b[off:off+len(bytes.fromhex(new))]=bytes.fromhex(new)
 restore_crc(b,o,target);assert len(b)==len(original)
 return b

def validate_methods(d,p):
 # DEX instruction widths in 16-bit code units; payloads are variable-sized.
 widths={op:1 for op in range(0xe3) if op not in {*range(0x3e,0x44),0x73,0x79,0x7a}}
 for ops,w in [('02 05 08 13 15 16 19 1a 1c 1f 20 22 23 29',2),('03 06 09 14 17 1b 24 25 26 2a 2b 2c',3),('18',5)]:
  for op in ops.split():widths[int(op,16)]=w
 for a,b,w in [(0x2d,0x3e,2),(0x44,0x6e,2),(0x6e,0x73,3),(0x74,0x79,3),(0x90,0xb0,2),(0xd0,0xe3,2)]:
  for op in range(a,b):widths[op]=w
 targets=set()
 for co in methods(d).values():
  start=co+16;end=start+2*U(d,co+12)
  if any(start<=o<end for o,_,_ in p):targets.add((start,end))
 assert targets
 for start,end in targets:
  o=start;prev=None;starts=set();registers,_,_,tries=struct.unpack_from('<HHHH',d,start-16)
  while o<end:
   starts.add((o-start)//2)
   op=d[o];word=struct.unpack_from('<H',d,o)[0]
   assert op in widths,('illegal opcode',hex(o),hex(op))
   w=widths[op]
   if op==0 and word:
    if word==0x100:w=4+2*struct.unpack_from('<H',d,o+2)[0]
    elif word==0x200:w=2+4*struct.unpack_from('<H',d,o+2)[0]
    elif word==0x300:w=4+(struct.unpack_from('<H',d,o+2)[0]*U(d,o+4)+1)//2
    else:raise AssertionError(('invalid payload',hex(o)))
   if op in (0x0a,0x0b,0x0c):assert prev in (*range(0x6e,0x73),*range(0x74,0x79),0x24,0x25),('orphan move-result',hex(o))
   assert o+2*w<=end,('instruction overrun',hex(o))
   regs=[];wide=set();a=word>>8
   if not (op==0 or op in (0x0e,0x28,0x29,0x2a)):
    if op in (0x02,0x05,0x08):regs=[a,struct.unpack_from('<H',d,o+2)[0]]
    elif op in (0x03,0x06,0x09):regs=list(struct.unpack_from('<HH',d,o+2))
    elif op in (*range(0x6e,0x73),0x24):
     count=word>>12;assert count<=5
     packed=struct.unpack_from('<H',d,o+4)[0];regs=[(packed>>(4*i))&15 for i in range(4)]+[(word>>8)&15];regs=regs[:count]
    elif op in (*range(0x74,0x79),0x25):
     first=struct.unpack_from('<H',d,o+4)[0];regs=list(range(first,first+a))
    elif op in (0x01,0x04,0x07,0x12,0x20,0x21,0x23) or 0x32<=op<=0x37 or 0x52<=op<=0x5f or 0x7b<=op<=0x8f or 0xb0<=op<=0xcf or 0xd0<=op<=0xd7:regs=[a&15,a>>4]
    elif 0x2d<=op<=0x31 or 0x44<=op<=0x51 or 0x90<=op<=0xaf:
     b,c=d[o+2:o+4];regs=[a,b,c]
    elif 0xd8<=op<=0xe2:regs=[a,d[o+2]]
    else:regs=[a]
    if op==0x12:regs=regs[:1]
    if op in (0x04,0x05,0x06):wide={0,1}
    elif op in (0x0b,0x10,0x16,0x17,0x18,0x19,0x45,0x4c,0x53,0x5a,0x61,0x68):wide={0}
    elif op in (0x2f,0x30,0x31):wide={1,2}
    elif op in (0x7d,0x7e,0x80,0x86,0x8b):wide={0,1}
    elif op in (0x81,0x83,0x88,0x89):wide={0}
    elif op in (0x84,0x85,0x8a,0x8c):wide={1}
    elif 0x9b<=op<=0xa5:wide={0,1} if op>=0xa3 else {0,1,2}
    elif 0xab<=op<=0xaf:wide={0,1,2}
    elif 0xbb<=op<=0xc5:wide={0} if op>=0xc3 else {0,1}
    elif 0xcb<=op<=0xcf:wide={0,1}
    for i,v in enumerate(regs):assert v+(i in wide)<registers,('register out of range',hex(o),v,registers)
   prev=op;o+=2*w
  assert o==end
  starts.add((end-start)//2)
  if tries:
   table=end+((end-start)//2%2)*2
   for i in range(tries):
    addr,count,_=struct.unpack_from('<IHH',d,table+8*i)
    assert addr in starts and addr+count in starts,('invalid try boundary',hex(table+8*i))

def repack(src,dst,replacements=None,strip=False):
 with zipfile.ZipFile(src) as zi,zipfile.ZipFile(dst,'w') as zo:
  for info in zi.infolist():
   if strip and re.match(r'^META-INF/(?:[^/]+\.(?:SF|RSA|DSA)|MANIFEST\.MF)$',info.filename,re.I):continue
   data=(replacements or {}).get(info.filename)
   if data is None:data=zi.read(info)
   x=copy.copy(info);x.extra=b''
   if x.compress_type==zipfile.ZIP_STORED:
    alignment=4096 if x.filename.endswith('.so') else 4
    assert zo.fp is not None
    base=zo.fp.tell()+30+len(x.filename.encode('utf8'));pad=(-base)%alignment
    if pad:
     if pad<4:pad+=alignment
     x.extra=struct.pack('<HH',0xd935,pad-4)+bytes(pad-4)
   zo.writestr(x,data)
def lp(b):return struct.pack('<I',len(b))+b
def run(*a):return subprocess.check_output(a,stderr=subprocess.STDOUT)
def v2(src,dst,work):
 b=Path(src).read_bytes();e=b.rfind(b'PK\x05\x06');cd=U(b,e+16)
 chunks=[]
 for section in (b[:cd],b[cd:e],b[e:]):
  for i in range(0,len(section),1048576):
   c=section[i:i+1048576];chunks.append(hashlib.sha256(b'\xa5'+struct.pack('<I',len(c))+c).digest())
 digest=hashlib.sha256(b'\x5a'+struct.pack('<I',len(chunks))+b''.join(chunks)).digest()
 cert=run('openssl','x509','-in',str(work/'cert.pem'),'-outform','DER')
 pub=run('openssl','pkey','-in',str(work/'key.pem'),'-pubout','-outform','DER')
 signed=lp(lp(struct.pack('<I',0x103)+lp(digest)))+lp(lp(cert))+lp(b'')
 (work/'signed-data').write_bytes(signed)
 sig=run('openssl','dgst','-sha256','-sign',str(work/'key.pem'),str(work/'signed-data'))
 (work/'signature').write_bytes(sig);(work/'pub.pem').write_bytes(run('openssl','pkey','-in',str(work/'key.pem'),'-pubout'))
 assert b'Verified OK' in run('openssl','dgst','-sha256','-verify',str(work/'pub.pem'),'-signature',str(work/'signature'),str(work/'signed-data'))
 signer=lp(signed)+lp(lp(struct.pack('<I',0x103)+lp(sig)))+lp(pub)
 pair=struct.pack('<I',0x7109871a)+lp(lp(signer));pair=struct.pack('<Q',len(pair))+pair
 size=len(pair)+24;block=struct.pack('<Q',size)+pair+struct.pack('<Q',size)+b'APK Sig Block 42'
 end=bytearray(b[e:]);struct.pack_into('<I',end,16,cd+len(block));Path(dst).write_bytes(b[:cd]+block+b[cd:e]+end)
def verify(original,result,p):
 with zipfile.ZipFile(original) as a,zipfile.ZipFile(result) as z:
  d=z.read('classes.dex')
  for o,_,new in p:
   assert d[o:o+len(bytes.fromhex(new))].hex()==new,hex(o)
   print('DEX',hex(o),new, 'return-void' if new=='0e00' else 'nop / goto / const-return')
  assert d[12:32]==hashlib.sha1(d[32:]).digest();assert U(d,8)==zlib.adler32(d[12:])&0xffffffff
  assert p==plan(a.read('classes.dex')) and len(p)==16
  original=a.read('classes.dex')
  for o in (0x313766,0x313398,0x3135f0,0x27b194):assert d[o:o+16]==original[o:o+16],hex(o)
  expected=bytearray(original)
  for o,_,new in p:expected[o:o+len(bytes.fromhex(new))]=bytes.fromhex(new)
  assert d[32:]==expected[32:]
  validate_methods(d,p)
  for name,patches in native_plans().items():
   b=z.read(name)
   for o,_,new in patches:assert b[o:o+len(bytes.fromhex(new))].hex()==new,(name,hex(o))
  for info in a.infolist():
   if info.filename.endswith('.so'):
    actual=z.getinfo(info.filename);data=z.read(info.filename)
    assert (actual.CRC,actual.file_size)==(info.CRC,info.file_size),info.filename
    assert zlib.crc32(data)&0xffffffff==info.CRC
  print('All native patches and original .so sizes/CRCs verified; c94 runtime value not independently evaluated')
  raw=Path(result).read_bytes()
  for i in z.infolist():
   if i.compress_type==0:
    off=i.header_offset;nl,el=struct.unpack_from('<HH',raw,off+26);assert (off+30+nl+el)%4==0,i.filename
  for i in a.infolist():
   if not re.match(r'^META-INF/(?:[^/]+\.(?:SF|RSA|DSA)|MANIFEST\.MF)$',i.filename,re.I):assert i.filename in z.namelist()
  print('DEX checksums OK; stored alignment OK; entries',len(a.infolist()),'->',len(z.infolist()))
  names=a.namelist();coll={}
  for n in names:coll.setdefault(n.lower(),[]).append(n)
  print('case collisions preserved',[v for v in coll.values() if len(v)>1])
def main():
 ap=argparse.ArgumentParser();ap.add_argument('source');ap.add_argument('output');ap.add_argument('--red',action='store_true');args=ap.parse_args();work=Path('/tmp/ssm_re_work');
 with zipfile.ZipFile(args.source) as z:
  original=z.read('classes.dex');assert original==Path('/tmp/ssm_re_work/store/classes.dex').read_bytes();p=plan(original)
  if args.red:verify(args.source,args.source,p);return
  d=bytearray(original)
  for o,old,new in p:
   assert d[o:o+len(bytes.fromhex(old))].hex()==old,(hex(o),old)
   d[o:o+len(bytes.fromhex(new))]=bytes.fromhex(new)
  d[12:32]=hashlib.sha1(d[32:]).digest();struct.pack_into('<I',d,8,zlib.adler32(d[12:])&0xffffffff);replacements={'classes.dex':d}
  validate_methods(d,p)
  for name in native_plans():replacements[name]=patch_native(name,z.read(name))
 repack(args.source,work/'unsigned.apk',replacements,True)
 ks=work/'re_release.keystore'
 if not ks.exists():run('keytool','-genkeypair','-keystore',str(ks),'-storetype','PKCS12','-storepass','changeit','-keypass','changeit','-alias','re_release','-keyalg','RSA','-keysize','2048','-validity','3650','-dname','CN=Local APK Rebuild')
 run('jarsigner','-keystore',str(ks),'-storepass','changeit','-sigalg','SHA256withRSA','-digestalg','SHA-256','-signedjar',str(work/'v1.apk'),str(work/'unsigned.apk'),'re_release')
 repack(work/'v1.apk',work/'aligned.apk')
 run('openssl','pkcs12','-in',str(ks),'-passin','pass:changeit','-nodes','-nocerts','-out',str(work/'key.pem'))
 run('openssl','pkcs12','-in',str(ks),'-passin','pass:changeit','-clcerts','-nokeys','-out',str(work/'cert.pem'))
 v2(work/'aligned.apk',args.output,work);verify(args.source,args.output,p)
 print(run('jarsigner','-verify',args.output).decode())
 print('v2 RSA signature verified with OpenSSL; Android platform verifier not executed')
if __name__=='__main__':main()
