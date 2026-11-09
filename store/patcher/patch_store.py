#!/usr/bin/env python3
"""Fail-closed static Store QA rebuild using shared verification primitives."""
import argparse
import hashlib
import re
import struct
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from patcher_common import (DEFAULT_KEYSTORE, DexFile, build_signed_apk,
 correction_offset, decode_tries, dex_valid, dump_analysis_json,
 extract_apk_cert_sha1, find_unique_insn_offset, find_unique_method, fix_dex,
 require, restore_crc, run, validate_methods, verify_dex_exact)

__all__ = ['validate_methods', 'restore_crc', 'dex_valid']

DEFAULT_STORE_CERT_SHA1 = 'e8404b806937b690b087fecca7845f7dfa34371e'

FIX=[(0x3a4f16,'6e30230c3103','000000000000'),(0x3a4fb2,'39011600','28160000'),(0x3a4a4e,'1a038226','2900e202'),(0x31f70e,'6e30230c2002','000000000000'),
 (0x3120b2,'170000008000','190000400000'),(0x312cec,'2200b300','0e000000'),(0x318068,'71006a2600000a00','12100f0000000000'),(0x3180b8,'71005e2600000a00','12100f0000000000'),(0x3181b8,'6200c513','0e000000'),(0x318218,'710066260000','0e0000000000'),(0x319150,'6900ee13','12000f00'),(0x319754,'2200f208','0e000000'),(0x31c0fc,'7110b62607000a00','12000f0000000000'),(0x31c180,'6e10850306000c06','0e00000000000000'),(0x31c33c,'14006456a4e3','12100f000000')]
# Patch only the signkey entry; preserve the local database key derivation.
ENTRY_OLD='6e10730304000c006e10860300000c006e10730304000c046e10870304000c046001290113021c00120334211500150100086e30020440010c047110730004000c047110890004000c0446040403280d'
ENTRY_NEW='281000000003010014000000e8404b806937b690b087fecca7845f7dfa34371e1300140023040e0e2604eeffffff1203282d000000000000000000000000000000000000000000000000000000000000'
FIX += [(0x3e7338,ENTRY_OLD,ENTRY_NEW)]

def build_entry_new(cert_sha1=None):
 sha1_hex = (cert_sha1 or DEFAULT_STORE_CERT_SHA1).lower()
 raw = bytes.fromhex(sha1_hex)
 require(len(raw) == 20, 'Invalid SHA-1 certificate digest length')
 return '281000000003010014000000' + raw.hex() + '1300140023040e0e2604eeffffff1203282d' + ('00' * 30)

RESUME=('Lm5/b;', '()V',814,16,('TracerPid:','Core_check fail!'),('Landroidx/fragment/app/w;->onResume()V',),('Landroid/os/Build;->TAGS:Ljava/lang/String;',))
RULES=[RESUME,RESUME,RESUME,
 ('Lcom/skhy/store/login/activity/LoginActivity;','(Landroid/os/Bundle;)V',410,8,(),('Landroidx/fragment/app/w;->onCreate(Landroid/os/Bundle;)V',),('Landroid/os/Build$VERSION;->SDK_INT:I',)),
 ('Lcom/liapp/x;','()V',230,4,("'",),('Ljava/util/HashSet;-><init>()V',),()),
 ('Lcom/liapp/x;','(I)V',116,4,('WWRFP',),('Ljava/lang/System;->exit(I)V',),()),
 ('Lcom/skhy/common/guard/GuardHooks;','()Z',32,4,(),('Lcom/skhy/common/guard/GuardHooks;->nativeGuardsReady()Z',),()),
 ('Lcom/skhy/common/guard/GuardHooks;','()Z',94,6,('guardsReadyPlus',),('Lcom/skhy/common/guard/GuardHooks;->nativeCheckRWX()Z',),()),
 ('Lcom/skhy/common/guard/GuardHooks;','(Landroid/app/Activity;)V',18,2,(),('Ljava/util/concurrent/atomic/AtomicLong;->incrementAndGet()J',),('Lcom/skhy/common/guard/GuardHooks;->RESUME_SEQ:Ljava/util/concurrent/atomic/AtomicLong;',)),
 ('Lcom/skhy/common/guard/GuardLoader;','()V',8,0,(),(),()),
 ('Lcom/skhy/common/util/LiappAlert;','(Landroid/content/Context;ILjava/lang/String;)I',14,3,(),('Lcom/skhy/common/util/LiappAlert;->forceExit(I)V',),('Lcom/skhy/common/util/LiappAlert;->g_CurrentContext:Landroid/content/Context;',)),
 ('Lcom/skhy/common/util/LiappAlert;','(I)V',80,3,('android.intent.category.HOME',),('Ljava/lang/System;->exit(I)V',),('Lcom/skhy/common/util/LiappAlert;->g_CurrentContext:Landroid/content/Context;',)),
 ('Lcom/skhy/common/util/Y;','(Landroid/content/Context;Ljava/lang/String;I)Z',58,10,('',),('Lcom/skhy/common/util/Y;->nativeDecision([BIII)Z',),('Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;',)),
 ('Lcom/skhy/common/util/Y;','(Landroid/app/Activity;)V',82,7,('SHA-256','classes.dex'),('Ljava/security/MessageDigest;->digest()[B',),()),
 ('Lcom/skhy/common/util/Y;','(Landroid/content/Context;Ljava/lang/String;)Z',142,13,('App signature is valid.','SHA-256'),('Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z',),('Landroid/os/Build$VERSION;->SDK_INT:I',)),
 ('Lt3/a;','(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;',138,6,('SHA1','0'),('La5/a;->a0(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;',),('Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;',))]
PRESERVED=('La5/b;','(Landroid/content/Context;)Ljava/lang/String;',84,5,('SHA1',),('Ljava/security/MessageDigest;->digest()[B',),('Landroid/os/Build$VERSION;->SDK_INT:I',))

def select(dex, rule_id, rule):
 cls,proto,size,regs,strings,calls,fields=rule
 return find_unique_method(dex,rule_id,class_filter=cls,proto=proto,insns_size=size,registers_size=regs,required_strings=strings,required_calls=calls,required_fields=fields)

def plan(d, cert_sha1=None):
 dex=DexFile(d)
 preserved=select(dex,'database-key-preserved',PRESERVED)
 require(preserved.signature=='La5/b;->b(Landroid/content/Context;)Ljava/lang/String;', 'unexpected preserved database key method')
 entry_new = build_entry_new(cert_sha1)
 result=[]
 for i,((_,old,new),rule) in enumerate(zip(FIX,RULES)):
  if i == 15:
   new = entry_new
  m=select(dex,f'patch-{i}',rule)
  pattern=old+'14016202127f' if i==1 else old
  o=find_unique_insn_offset(dex,m,f'patch-{i}',pattern=pattern)
  require(len(old)==len(new), f'patch-{i}: unequal patch widths')
  require(not (preserved.insns_off<=o<preserved.insns_off+2*preserved.insns_size), f'patch-{i}: overlaps preserved method')
  result.append((o,old,new))
 require(len(result)==16, 'expected 16 Store DEX patches')
 return result

NATIVE={
 'arm64-v8a':[(0x2322c,'10f7ff97','e6ffff17'),(0x21f5c,'ff4305d1','c0035fd6'),(0x244a4,'fd7bbfa9','c0035fd6'),(0x232cc,'fd7bbca9','c0035fd6')],
 'armeabi-v7a':[(0x116cc,'fef770fb','dfe700bf'),(0x10960,'f0b5','7047'),(0x12328,'80b5','7047'),(0x11798,'f0b5','7047')],
 'x86':[(0x28d20,'e87bdbffff','e9b0000000'),(0x27b10,'55','c3'),(0x29f50,'55','c3'),(0x28e20,'55','c3')],
 'x86_64':[(0x277a1,'e85adbffff','e9a8000000'),(0x26550,'55','c3'),(0x28bf0,'50','c3'),(0x278a0,'55','c3')]}
ZW=[(0x815f0,'ff0740d1ff4301d1','00008052c0035fd6'),(0x83e68,'21001d32','1f2003d5'),(0x84150,'01008012','01008052'),(0x88060,'010447b9','13000014'),(0x881e0,'35010034','09000014'),(0x88214,'d37efe97','1f2003d5'),(0x91698,'d6bfff97','1f2003d5'),(0x916c4,'a759fe97','1f2003d5')]

NATIVE_SPECS = {
 'arm64-v8a': [
  ('pattern', '10f7ff97', '10f7ff97', 'e6ffff17'),
  ('symbol', 'Java_com_skhy_common_util_Y_cs', 'ff4305d1', 'c0035fd6'),
  ('pattern', 'fd7bbfa9fd030091e0031f2ab4f10094ff0301d1', 'fd7bbfa9', 'c0035fd6'),
  ('symbol', 'Java_com_skhy_common_util_ZY_secure', 'fd7bbca9', 'c0035fd6'),
 ],
 'armeabi-v7a': [
  ('pattern', 'fef770fb', 'fef770fb', 'dfe700bf'),
  ('symbol', 'Java_com_skhy_common_util_Y_cs', 'f0b5', '7047'),
  ('pattern', '80b56f46002043f090e8d4d4f0b503af2de9000b', '80b5', '7047'),
  ('symbol', 'Java_com_skhy_common_util_ZY_secure', 'f0b5', '7047'),
 ],
 'x86': [
  ('pattern', 'e87bdbffff', 'e87bdbffff', 'e9b0000000'),
  ('symbol', 'Java_com_skhy_common_util_Y_cs', '55', 'c3'),
  ('pattern', '5589e55383e4f083ec10e8000000005b81c3ad74', '55', 'c3'),
  ('symbol', 'Java_com_skhy_common_util_ZY_secure', '55', 'c3'),
 ],
 'x86_64': [
  ('pattern', 'e85adbffff', 'e85adbffff', 'e9a8000000'),
  ('symbol', 'Java_com_skhy_common_util_Y_cs', '55', 'c3'),
  ('pattern', '5031ffe838f40300cccccccccccccccc55415741', '50', 'c3'),
  ('symbol', 'Java_com_skhy_common_util_ZY_secure', '55', 'c3'),
 ],
}

ZW_SPECS = [
 ('pattern', 'ff0740d1ff4301d1ff4301d1f76302a9', 'ff0740d1ff4301d1', '00008052c0035fd6'),
 ('pattern', '21001d32030000141f03006ba1ffff54', '21001d32', '1f2003d5'),
 ('pattern', '0100801201641bb981058052e0420091', '01008012', '01008052'),
 ('pattern', '010447b9c1000035018840b9a1010035', '010447b9', '13000014'),
 ('pattern', '35010034000080d2b53201118905fe97', '35010034', '09000014'),
 ('pattern', 'd37efe977382049160ea45b900040011', 'd37efe97', '1f2003d5'),
 ('pattern', 'd6bfff97938204912100805273220091', 'd6bfff97', '1f2003d5'),
 ('pattern', 'a759fe9760825bb9e0003037a2fdfff0', 'a759fe97', '1f2003d5'),
]

def _elf_symbols(b):
 require(b[:4]==b'\x7fELF' and b[5]==1, 'invalid ELF header')
 wide=b[4]==2
 machine=struct.unpack_from('<H',b,18)[0]
 off=struct.unpack_from('<Q' if wide else '<I',b,40 if wide else 32)[0]
 size,count=struct.unpack_from('<HH',b,58 if wide else 46)
 fmt='<IIQQQQIIQQ' if wide else '<IIIIIIIIII'
 ss=[struct.unpack_from(fmt,b,off+i*size) for i in range(count)]
 symbols={}
 for s in ss:
  if s[1]==11:
   st=ss[s[6]]; strings=b[st[4]:st[4]+st[5]]
   for o in range(s[4],s[4]+s[5],s[9]):
    if wide: name,_,_,sec,val,_=struct.unpack_from('<IBBHQQ',b,o)
    else: name,val,_,_,_,sec=struct.unpack_from('<IIIBBH',b,o)
    end=strings.find(b'\0',name); key=strings[name:end].decode(errors='replace')
    if sec:
     addr = (val & ~1) if machine == 40 else val
     for sec_hdr in ss:
      if sec_hdr[1]!=8 and sec_hdr[3]<=addr<sec_hdr[3]+sec_hdr[5]:
       symbols[key]=addr-sec_hdr[3]+sec_hdr[4]
       break
 return symbols

def _find_unique_bytes(b, hex_sig):
 raw = bytes.fromhex(hex_sig)
 pos = b.find(raw)
 require(pos >= 0 and b.find(raw, pos + 1) < 0, f'Expected unique byte signature {hex_sig}')
 return pos

def resolve_native_patches(name, original):
 b = bytes(original)
 if name.endswith('libzwfeyyadt.so'):
  specs = ZW_SPECS
  syms = {}
 else:
  abi = name.split('/')[1]
  specs = NATIVE_SPECS[abi]
  syms = _elf_symbols(b)
 resolved = []
 for kind, key, old, new in specs:
  if kind == 'symbol':
   require(key in syms, f'Missing ELF symbol {key} in {name}')
   off = syms[key]
  else:
   off = _find_unique_bytes(b, key)
  raw_old = bytes.fromhex(old)
  require(b[off:off+len(raw_old)] == raw_old, (name, hex(off), 'precondition failed'))
  resolved.append((off, old, new))
 return resolved

def native_plans():
 return {**{'lib/'+abi+'/libsecurity-checker-lib.so':p for abi,p in NATIVE.items()},'lib/arm64-v8a/libzwfeyyadt.so':ZW}

def patch_native(name,original):
 b=bytearray(original);target=zlib.crc32(original)&0xffffffff
 o=correction_offset(b)
 patches = resolve_native_patches(name, original)
 for off,old,new in patches:
  require(len(old)==len(new) and b[off:off+len(bytes.fromhex(old))].hex()==old,(name,hex(off)))
  b[off:off+len(bytes.fromhex(new))]=bytes.fromhex(new)
 restore_crc(b,o,target);require(len(b)==len(original), (name, 'length changed'))
 return b

def _is_sig_entry(name):
 return bool(re.match(r'^META-INF/(?:[^/]+\.(?:SF|RSA|DSA|EC)|MANIFEST\.MF)$',name,re.I))

def verify(src,out,cert_sha1=None):
 cert_sha1 = cert_sha1 or extract_apk_cert_sha1(src)
 with zipfile.ZipFile(src) as a,zipfile.ZipFile(out) as z:
  originals={i.filename:i for i in a.infolist() if not _is_sig_entry(i.filename)}
  actual={i.filename:i for i in z.infolist()}
  require(len(actual)==len(z.infolist()), 'duplicate output entries')
  require(originals.keys()<=actual.keys(), 'missing original entries')
  added=actual.keys()-originals.keys()
  require(all(_is_sig_entry(n) for n in added), ('unexpected entries', added))
  original=a.read('classes.dex');p=plan(original, cert_sha1)
  verify_dex_exact(original,z.read('classes.dex'),p)
  patched_natives = set(native_plans())
  for name in patched_natives:
   expected_so=patch_native(name,a.read(name));b=z.read(name)
   require(b==expected_so,('Unexpected native modifications',name))
  for name, info in originals.items():
   actual_info=z.getinfo(name);data=z.read(name)
   require(actual_info.compress_type==info.compress_type, (name, 'compression changed'))
   if name.endswith('.so'):
    require((actual_info.CRC,actual_info.file_size)==(info.CRC,info.file_size),name)
    require((zlib.crc32(data)&0xffffffff)==info.CRC, name)
   if name != 'classes.dex' and name not in patched_natives:
    require(data == a.read(name), (name, 'content changed'))
  lower_counts = {}
  for n in originals:
   lower_counts[n.lower()] = lower_counts.get(n.lower(), 0) + 1
  case_distinct = {n for n in originals if lower_counts[n.lower()] > 1}
  require(case_distinct <= actual.keys(), 'missing case-distinct resource entries')
  raw=Path(out).read_bytes()
  for info in z.infolist():
   if info.compress_type==zipfile.ZIP_STORED:
    nl,el=struct.unpack_from('<HH',raw,info.header_offset+26)
    alignment=4096 if info.filename.endswith('.so') else 4
    require((info.header_offset+30+nl+el)%alignment==0,info.filename)
 print('Exact DEX and five native transformations, CRCs, retained entries and alignment verified')

def regenerate_analysis(source, output):
 """Record independently decoded before/after streams and explicit invoke sites."""
 import json
 root=Path(__file__).resolve().parents[1]/'analysis'
 path=root/'store_disassembly_and_patches.json'
 audit_path=root/'store_certificate_and_universal_audit.json'
 evidence=json.loads(path.read_text())
 cert_sha1=extract_apk_cert_sha1(source)
 before={};after={};incoming={}
 with zipfile.ZipFile(source) as src, zipfile.ZipFile(output) as dst:
  for name in src.namelist():
   if not (name.startswith('classes') and name.endswith('.dex')):continue
   before[name]=DexFile(src.read(name));after[name]=DexFile(dst.read(name))
   for m in before[name].methods:
    if not m.code_off:continue
    before[name].decode_method(m)
    for relative,off,_,op,_,ref in m.insns:
     if op in (*range(0x6e,0x73),*range(0x74,0x79)):
      incoming.setdefault(ref,[]).append(dict(dex=name,method=m.signature,file_offset=hex(off),byte_offset=relative))
 def instructions(m):
  return [dict(byte_offset=r,file_offset=hex(o),width=w,opcode=hex(op),raw_hex=raw.hex(),ref=ref) for r,o,w,op,raw,ref in m.insns]
 require('classes.dex' in before and 'classes.dex' in after, 'missing classes.dex')
 dex=before['classes.dex'];patched=after['classes.dex'];patches=plan(dex.data, cert_sha1)
 methods=evidence['dex_analysis']['classes.dex']['methods']
 for m in dex.methods:
  if not any(m.insns_off<=o<m.insns_off+2*m.insns_size for o,_,_ in patches):continue
  a=next((x for x in patched.methods if x.signature==m.signature), None)
  require(a is not None and bool(a.code_off), f'missing patched method {m.signature}')
  if a is None: raise AssertionError(m.signature)
  patched.decode_method(a)
  record=methods.setdefault(m.signature,{})
  record.pop('instructions',None)
  record.update(
   try_blocks=decode_tries(dex.data, m, dex),
   before_instructions=instructions(m),
   after_instructions=instructions(a),
   incoming_callers=incoming.get(m.signature,[]))
 evidence['incoming_callers_coverage']='All explicit invoke sites across every source APK DEX; excludes reflection, native calls and runtime dispatch expansion'
 path.write_text(dump_analysis_json(evidence))
 if audit_path.exists():
  audit_doc=json.loads(audit_path.read_text())
  for sig, rec in audit_doc.get('certificate_and_integrity_methods', {}).items():
   m=next((x for x in dex.methods if x.signature==sig), None)
   a=next((x for x in patched.methods if x.signature==sig), None)
   require(m is not None and a is not None, f'missing audit method {sig}')
   if m is None or a is None: raise AssertionError(sig)
   patched.decode_method(a)
   rec.pop('before', None)
   rec.pop('after', None)
   rec['try_blocks']=decode_tries(dex.data, m, dex)
   rec['before_instructions']=instructions(m)
   rec['after_instructions']=instructions(a)
  audit_path.write_text(dump_analysis_json(audit_doc))

def main():
 ap=argparse.ArgumentParser();ap.add_argument('source');ap.add_argument('output')
 ap.add_argument('--keystore',type=Path,default=DEFAULT_KEYSTORE)
 ap.add_argument('--red',action='store_true')
 ap.add_argument('--regenerate-analysis',action='store_true')
 args=ap.parse_args()
 src=Path(args.source).resolve();out=Path(args.output).resolve()
 if args.red:
  verify(src,src)
  raise AssertionError('RED expected failure did not occur')
 require(src!=out and not out.exists(),'refusing overwrite')
 cert_sha1=extract_apk_cert_sha1(src)
 with zipfile.ZipFile(src) as z:
  original=z.read('classes.dex');p=plan(original, cert_sha1);d=bytearray(original)
  for o,old,new in p:
   require(d[o:o+len(bytes.fromhex(old))].hex()==old, ('DEX precondition mismatch', hex(o)))
   d[o:o+len(bytes.fromhex(new))]=bytes.fromhex(new)
  fix_dex(d);verify_dex_exact(original,d,p)
  replacements={'classes.dex':d}
  for name in native_plans():replacements[name]=patch_native(name,z.read(name))
 with tempfile.TemporaryDirectory(prefix='store-build-') as tmp:
  signed=Path(tmp)/'signed.apk'
  build_signed_apk(src,signed,replacements,keystore=args.keystore)
  verify(src,signed,cert_sha1)
  verification=run('jarsigner','-verify',signed)
  require(b'jar verified.' in verification, 'jarsigner verification failed')
  with open(signed,'rb') as fsrc, open(out,'xb') as fdst:
   while True:
    chunk=fsrc.read(1024*1024)
    if not chunk:break
    fdst.write(chunk)
 if args.regenerate_analysis:
  regenerate_analysis(src, out)
 print('OUTPUT',out,'SHA256',hashlib.sha256(out.read_bytes()).hexdigest())
 print('Local signing verified; Android platform verifier and runtime not executed')

if __name__=='__main__':main()
