#!/usr/bin/env python3
"""Fail-closed static Store QA rebuild using shared verification primitives."""
import argparse
import re
import struct
import sys
import zipfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from patcher_common import (DEFAULT_KEYSTORE, DexFile, build_signed_apk,
 correction_offset, dex_valid, find_unique_insn_offset, find_unique_method,
 fix_dex, restore_crc, validate_methods, verify_dex_exact)

__all__ = ['validate_methods', 'restore_crc', 'dex_valid']

FIX=[(0x3a4f16,'6e30230c3103','000000000000'),(0x3a4fb2,'39011600','28160000'),(0x3a4a4e,'1a038226','2900e202'),(0x31f70e,'6e30230c2002','000000000000'),
 (0x3120b2,'170000008000','190000400000'),(0x312cec,'2200b300','0e000000'),(0x318068,'71006a2600000a00','12100f0000000000'),(0x3180b8,'71005e2600000a00','12100f0000000000'),(0x3181b8,'6200c513','0e000000'),(0x318218,'710066260000','0e0000000000'),(0x319150,'6900ee13','12000f00'),(0x319754,'2200f208','0e000000'),(0x31c0fc,'7110b62607000a00','12000f0000000000'),(0x31c180,'6e10850306000c06','0e00000000000000'),(0x31c33c,'14006456a4e3','12100f000000')]
# Patch only the signkey entry; preserve the local database key derivation.
ENTRY_OLD='6e10730304000c006e10860300000c006e10730304000c046e10870304000c046001290113021c00120334211500150100086e30020440010c047110730004000c047110890004000c0446040403280d'
ENTRY_NEW='281000000003010014000000e8404b806937b690b087fecca7845f7dfa34371e1300140023040e0e2604eeffffff1203282d000000000000000000000000000000000000000000000000000000000000'
FIX += [(0x3e7338,ENTRY_OLD,ENTRY_NEW)]

# Semantic selectors are independent of code-item offsets and obfuscated names.
# class, prototype, code units, registers, required strings/calls/fields
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

def plan(d):
 dex=DexFile(d)
 preserved=select(dex,'database-key-preserved',PRESERVED)
 assert preserved.signature=='La5/b;->b(Landroid/content/Context;)Ljava/lang/String;'
 result=[]
 for i,((_,old,new),rule) in enumerate(zip(FIX,RULES)):
  m=select(dex,f'patch-{i}',rule)
  pattern=old+'14016202127f' if i==1 else old
  o=find_unique_insn_offset(dex,m,f'patch-{i}',pattern=pattern)
  assert len(old)==len(new)
  assert not (preserved.insns_off<=o<preserved.insns_off+2*preserved.insns_size)
  result.append((o,old,new))
 assert len(result)==16
 return result

NATIVE={
 'arm64-v8a':[(0x2322c,'10f7ff97','e6ffff17'),(0x21f5c,'ff4305d1','c0035fd6'),(0x244a4,'fd7bbfa9','c0035fd6'),(0x232cc,'fd7bbca9','c0035fd6')],
 'armeabi-v7a':[(0x116cc,'fef770fb','dfe700bf'),(0x10960,'f0b5','7047'),(0x12328,'80b5','7047'),(0x11798,'f0b5','7047')],
 'x86':[(0x28d20,'e87bdbffff','e9b0000000'),(0x27b10,'55','c3'),(0x29f50,'55','c3'),(0x28e20,'55','c3')],
 'x86_64':[(0x277a1,'e85adbffff','e9a8000000'),(0x26550,'55','c3'),(0x28bf0,'50','c3'),(0x278a0,'55','c3')]}
ZW=[(0x815f0,'ff0740d1ff4301d1','00008052c0035fd6'),(0x83e68,'21001d32','1f2003d5'),(0x84150,'01008012','01008052'),(0x88060,'010447b9','13000014'),(0x881e0,'35010034','09000014'),(0x88214,'d37efe97','1f2003d5'),(0x91698,'d6bfff97','1f2003d5'),(0x916c4,'a759fe97','1f2003d5')]
CRC={'arm64-v8a':0x14661592,'armeabi-v7a':0x92e39496,'x86':0x900c9ec8,'x86_64':0x5d8fafd7}

def native_plans():
 return {**{'lib/'+abi+'/libsecurity-checker-lib.so':p for abi,p in NATIVE.items()},'lib/arm64-v8a/libzwfeyyadt.so':ZW}

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

def verify(src,out):
 with zipfile.ZipFile(src) as a,zipfile.ZipFile(out) as z:
  original=a.read('classes.dex');p=plan(original)
  verify_dex_exact(original,z.read('classes.dex'),p)
  for name in native_plans():
   expected_so=patch_native(name,a.read(name));b=z.read(name)
   assert b==expected_so,('Unexpected native modifications',name)
  for info in a.infolist():
   if info.filename.endswith('.so'):
    actual=z.getinfo(info.filename);data=z.read(info.filename)
    assert (actual.CRC,actual.file_size)==(info.CRC,info.file_size),info.filename
    assert zlib.crc32(data)&0xffffffff==info.CRC
   if not re.match(r'^META-INF/(?:[^/]+\.(?:SF|RSA|DSA|EC)|MANIFEST\.MF)$',info.filename,re.I):
    assert info.filename in z.namelist()
  raw=Path(out).read_bytes()
  for info in z.infolist():
   if info.compress_type==zipfile.ZIP_STORED:
    nl,el=struct.unpack_from('<HH',raw,info.header_offset+26)
    alignment=4096 if info.filename.endswith('.so') else 4
    assert (info.header_offset+30+nl+el)%alignment==0,info.filename
 print('Exact DEX and five native transformations, CRCs, retained entries and alignment verified')

def regenerate_analysis(source, output):
 """Record independently decoded before/after streams and explicit invoke sites."""
 import json
 path=Path(__file__).resolve().parents[1]/'analysis'/'store_disassembly_and_patches.json'
 evidence=json.loads(path.read_text())
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
 dex=before['classes.dex'];patched=after['classes.dex'];patches=plan(dex.data)
 methods=evidence['dex_analysis']['classes.dex']['methods']
 for m in dex.methods:
  if not any(m.insns_off<=o<m.insns_off+2*m.insns_size for o,_,_ in patches):continue
  a=next(a for a in patched.methods if a.signature==m.signature)
  patched.decode_method(a)
  record=methods.setdefault(m.signature,{})
  record.pop('instructions',None)
  record.update(before_instructions=instructions(m),after_instructions=instructions(a),incoming_callers=incoming.get(m.signature,[]))
 evidence['incoming_callers_coverage']='All explicit invoke sites across every source APK DEX; excludes reflection, native calls and runtime dispatch expansion'
 path.write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+'\n')


def main():
 ap=argparse.ArgumentParser();ap.add_argument('source');ap.add_argument('output')
 ap.add_argument('--keystore',type=Path,default=DEFAULT_KEYSTORE)
 ap.add_argument('--red',action='store_true');args=ap.parse_args()
 if args.red:
  verify(args.source,args.source);return
 with zipfile.ZipFile(args.source) as z:
  original=z.read('classes.dex');p=plan(original);d=bytearray(original)
  for o,old,new in p:
   assert d[o:o+len(bytes.fromhex(old))].hex()==old
   d[o:o+len(bytes.fromhex(new))]=bytes.fromhex(new)
  fix_dex(d);verify_dex_exact(original,d,p)
  replacements={'classes.dex':d}
  for name in native_plans():replacements[name]=patch_native(name,z.read(name))
 build_signed_apk(args.source,args.output,replacements,keystore=args.keystore)
 verify(args.source,args.output)
 print('Local signing verified; Android platform verifier and runtime not executed')

if __name__=='__main__':main()
