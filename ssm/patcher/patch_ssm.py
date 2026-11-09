#!/usr/bin/env python3
"""Strict SSM APK patcher; run with python3 -I from outside extracted inputs."""
import argparse
import hashlib
import os
import struct
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from patcher_common import (DEFAULT_KEYSTORE, DexFile, build_signed_apk,
 correction_offset, restore_crc, decode_tries, dex_valid, dump_analysis_json, extract_apk_cert_sha1,
 find_unique_insn_offset, find_unique_method, fix_dex, require, run,
 validate_methods, verify_dex_exact)

__all__ = ['verify_dex_exact']

DEFAULT_SSM_CERT_SHA1 = '7477ca27bf39d4a8bde8e8c95ac706418b6e5b24'

REMOVED_PERMISSIONS = frozenset({
 'android.permission.MANAGE_DEVICE_POLICY_LOCK_TASK',
 'android.permission.WRITE_SECURE_SETTINGS',
 'android.permission.GET_ACCOUNTS',
 'android.permission.READ_CONTACTS',
 'android.permission.WRITE_CONTACTS',
 'android.permission.READ_PHONE_STATE',
 'android.permission.READ_PRIVILEGED_PHONE_STATE',
 'android.permission.ACCESS_BACKGROUND_LOCATION',
 'android.permission.LAUNCH_ACTIVITY_FROM_FOREGROUND_SERVICE',
 'android.permission.READ_CALL_LOG',
 'android.permission.READ_OWNER_DATA',
 'android.permission.CALL_PHONE',
 'android.permission.SYSTEM_ALERT_WINDOW',
 'android.permission.PROCESS_OUTGOING_CALLS',
 'android.permission.WRITE_CALL_LOG',
 'com.sec.android.provider.logsprovider.permission.READ_LOGS',
 'com.sec.android.provider.logsprovider.permission.WRITE_LOGS',
 'android.permission.DISABLE_KEYGUARD',
 'android.permission.RECORD_AUDIO',
})
REMOVED_SERVICES = frozenset({
 'com.sktelecom.ssm.accessibility.SSMAccessibilityService',
})
SCRUB_STRINGS = REMOVED_PERMISSIONS | REMOVED_SERVICES | frozenset({
 'android.permission.BIND_ACCESSIBILITY_SERVICE',
 'android.accessibilityservice.AccessibilityService',
 'android.accessibilityservice',
})

def patch_manifest(data: bytes) -> bytes:
 require(struct.unpack_from('<HHI', data, 0) == (3, 8, len(data)), 'invalid AXML header')
 ctype, header, size = struct.unpack_from('<HHI', data, 8)
 require(ctype == 1 and header == 28 and 8 + size <= len(data), 'invalid StringPool')
 count, _, flags, start, _ = struct.unpack_from('<5I', data, 16)
 require(flags == 0, 'expected UTF-16LE StringPool')
 out = bytearray(data[:8+size])
 strings = []
 scrub_indices = set()
 string_offsets = {}
 for idx in range(count):
  off = 8 + start + struct.unpack_from('<I', data, 36+idx*4)[0]
  u16_len, = struct.unpack_from('<H', data, off)
  off += 2
  if u16_len & 0x8000:
   u16_len = ((u16_len & 0x7fff) << 16) | struct.unpack_from('<H', data, off)[0]
   off += 2
  text = data[off:off+u16_len*2].decode('utf-16le')
  strings.append(text)
  string_offsets[idx] = off
  if text in SCRUB_STRINGS:
   scrub_indices.add(idx)
   out[off:off+u16_len*2] = ('android.permission.UNUSED_' + f'{idx:03d}' + '_'*u16_len)[:u16_len].encode('utf-16le')
 pos = 8 + size
 ctype, header, size = struct.unpack_from('<HHI', data, pos)
 require(ctype == 0x0180 and header == 8 and size >= 8 and pos+size <= len(data), 'invalid ResourceMap')
 out.extend(data[pos:pos+size])
 pos += size
 skipped = 0
 sdk = dict(compileSdkVersion=30, platformBuildVersionCode=30, platformBuildVersionName=11)
 codename_refs = []
 retained_refs = set()
 while pos < len(data):
  ctype, header, size = struct.unpack_from('<HHI', data, pos)
  require(size >= header >= 8 and pos+size <= len(data), 'invalid XML chunk')
  chunk = bytearray(data[pos:pos+size])
  refs = set()
  if ctype in (0x0100, 0x0101, 0x0102, 0x0103):
   node_refs = set(struct.unpack_from('<II', chunk, 16))
   require(47 not in node_refs, 'shared codename node string')
   refs.update(node_refs)
  if header >= 16:
   comment, = struct.unpack_from('<I', chunk, 12)
   require(comment != 47, 'shared codename comment string')
   refs.add(comment)
  if ctype == 0x0104:
   text_idx, _, _, dtype, value = struct.unpack_from('<IHBBI', chunk, 16)
   refs.add(text_idx)
   if dtype == 3: refs.add(value)
  if ctype == 0x0102:
   tag = strings[struct.unpack_from('<I', chunk, 20)[0]]
   astart, width, nattrs = struct.unpack_from('<HHH', chunk, 24)
   require(width >= 20 and 16+astart+nattrs*width <= size, 'invalid XML attributes')
   remove = False
   for idx in range(nattrs):
    aoff = 16 + astart + idx*width
    name = strings[struct.unpack_from('<I', chunk, aoff+4)[0]]
    raw, _, _, dtype, value = struct.unpack_from('<IHBBI', chunk, aoff+8)
    attr_refs = set(struct.unpack_from('<II', chunk, aoff)) | {raw}
    if dtype == 3: attr_refs.add(value)
    if 47 in attr_refs:
     require(tag == 'manifest' and name == 'compileSdkVersionCodename' and
             (raw, dtype, value) == (47, 3, 47), 'shared codename string')
     codename_refs.append((tag, name))
    refs.update(attr_refs)
    if name == 'name':
     text = strings[raw] if raw != 0xffffffff else strings[value] if dtype == 3 else None
     remove |= (tag == 'uses-permission' and text in REMOVED_PERMISSIONS or
                tag == 'service' and text in REMOVED_SERVICES)
    new_val = sdk.get(name) if tag == 'manifest' else 30 if tag == 'uses-sdk' and name == 'targetSdkVersion' else None
    if new_val is not None:
     struct.pack_into('<IHBBI', chunk, aoff+8, 0xffffffff, 8, 0, 0x10, new_val)
   if skipped or remove:
    skipped += 1
  elif ctype == 0x0103 and skipped:
   skipped -= 1
   pos += size
   continue
  if ctype == 0x0104:
   require(47 not in refs, 'shared codename text string')
  if not skipped:
   retained_refs.update(refs)
   out.extend(chunk)
  pos += size
 require(not skipped, 'unclosed removed XML element')
 require(not scrub_indices & retained_refs, 'scrubbed string referenced by retained XML')
 require(strings[47] == '9' and len(codename_refs) == 1, 'unexpected compile SDK codename')
 off = string_offsets[47]
 out[off:off+2] = 'R'.encode('utf-16le')
 struct.pack_into('<I', out, 4, len(out))
 return bytes(out)

def patch_native(b, patches):
 changed = bytearray(b)
 for symbol, off, patch in patches:
  before = b[off:off+len(patch)]
  require(before != patch and len(before) == len(patch), (symbol, 'unexpected original'))
  changed[off:off+len(patch)] = patch
 restore_crc(changed, correction_offset(changed), zlib.crc32(b) & 0xffffffff)
 return changed

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
 (0x4d9eaa,'13000020','13000000'),(0x4db652,'13000020','13000000'),
 (0x4ead54,'1201','1211'),(0x4edfcc,'1201','1211'),
 (0x4f1b54,'1201','1211'),(0x4f57dc,'1201','1211'),
 (0x50e85c,'1202','1212'),(0x50eaf4,'1202','1212'),
 (0x52c2ea,'39000300','00000000'),(0x53d31a,'0a06','1206'),
 (0x53d41c,'390a0300','0e000000'),(0x56585a,'0a04','1214'),
 (0x53e340,'0a04','1214'),(0x4c5994,'0a00','1200')]

DEX['classes.dex'] += [
 (0x51feb4,'62022472','11010000'),
 (0x52003c,'6e1094e504000a02','1101000000000000'),
 (0x581044,'711008f000000a00','1210000000000000'),
 (0x581388,'6000c507','12100f00'),
 (0x4fbc60,'7110581703000a03','1213000000000000'),
 (0x4f9b50,'37650a00','00000000'),
 (0x4fb484,'54108a6f','12000f00'),
 (0x51fe58,'1a008582','28290000'),
 (0x51ffe0,'1a00e6a9','28290000'),
 (0x57acb4,'6200bb741a010000','1a00000011000000')]
DEX['classes2.dex'] += [
 (0xaa80a,'7110330207000c01','1100000000000000'),
 (0xaa6f0,'60000f00','12100f00'),
 (0xaa758,'60000f00','12100f00'),
 (0xae1f8,'1a00944e','12100f00')]

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
 ('policy/db/t','a','(Landroid/content/Context;)Z',211,8),
 ('policy/gid20/h','i','(Lorg/json/JSONObject;)Lorg/json/JSONObject;',118,7),
 ('policy/gid20/h','s','(Landroid/content/Context;)V',86,11),
 ('policy/receiver/PolicyBroadcastReceiver$a','run','()V',1038,9),
 ('policy/gid20/l/a','u','(Ljava/lang/String;)I',228,10),
 ('BackgroundService','onStartCommand','(Landroid/content/Intent;II)I',675,26),
 ('policy/config/Preset','o','()Ljava/util/List;',180,6),
 ('policy/config/Preset','J','()Ljava/util/List;',152,5),
 ('policy/util/y','z','(Landroid/content/Context;)Z',5,1),
 ('policy/util/y','K','(Landroid/content/Context;)Z',89,6),
 ('init/a1','k','(Landroid/content/Context;)Z',53,4),
 ('init/v0','k','(Landroid/content/Context;)Z',60,9),
 ('init/z0','u','(Landroid/content/Context;)Z',28,3),
 ('util/b','c','(Landroid/content/Context;)Ljava/util/List;',103,8),
 ('util/b','d','(Landroid/content/Context;)Z',44,3),
 ('util/b','e','(Landroid/content/Context;)Z',48,3),
 ('util/h','s','(Landroid/content/Context;)Z',18,2),
 ('policy/util/h','k','(Landroid/content/Context;)Ljava/lang/String;',234,7),
]

SEMANTIC_SITES = {
 'classes.dex': [(0,12),(1,18),(2,46),(3,54),(3,104),(4,0),(5,26),(6,0),
 (7,26),(8,432),(9,354),(10,354),(11,354),(12,354),(13,272),(14,314),
 (7,22),(15,0),(16,0),(17,214),(18,46),(19,0),(20,0),(21,0),(22,0),(23,0),
 (24,0),(25,0),(26,0),(27,0),(33,58),(33,70),(33,98),(33,106),(33,126),
 (34,56),(34,68),(34,98),(34,110),(35,42),(36,48),(36,108),(37,0),(38,0),(39,0),
 (28,26),(29,22),(30,22),(31,22),(32,22),
 (9,220),(10,220),(11,220),(12,220),(13,96),(14,24),
 (43,6),(44,58),(45,0),(46,834),(47,252),(48,68),
 (49,92),(50,92),(51,0),(52,0),(53,36),(54,72),(55,0),
 (49,0),(50,0),(60,0)],
 'classes2.dex': [(40,30),(40,36),(41,0),(42,0),(56,10),(57,0),(58,0),(59,0)]
}

SEMANTIC_FEATURES = {
 0: dict(required_strings=('DEBUG - block USB',)),
 1: dict(required_strings=('DEBUG - block USB',)),
 2: dict(required_strings=('setDeveloperMode : ',)),
 3: dict(required_strings=('setUsbState : ',)),
 4: dict(required_strings=('.*MtpStorageSwitch.*',)),
 5: dict(required_strings=('rootReason',)),
 6: dict(required_strings=('Security Critical: Starting shutdown sequence from Native signal',)),
 7: dict(required_strings=('com.sktelecom.ssm','currentSignature')),
 8: dict(required_strings=('ApkFileHash','apkFileHash = ')),
 9: dict(required_strings=('ApkFileHash','FH = ')),
 10: dict(required_strings=('ApkFileHash','FH = ')),
 11: dict(required_strings=('ApkFileHash','FH = ')),
 12: dict(required_strings=('ApkFileHash','FH = ')),
 13: dict(required_strings=('ApkFileHash','Exception in apkHashResponse: ')),
 14: dict(required_strings=('ApkFileHash','Exception in apkCCHashResponse: ')),
 15: dict(required_strings=('device_policy',), required_calls=('Landroid/app/admin/DevicePolicyManager;->getCameraDisabled(Landroid/content/ComponentName;)Z',)),
 16: dict(required_calls=('Lcom/samsung/android/knox/restriction/RestrictionPolicy;->setCameraState(Z)Z',)),
 17: dict(required_strings=('jstest120905 performCamera() oDPM.isAdminActive(mDeviceAdminSample) = ',)),
 18: dict(required_strings=('170922 - setCameraEnable ',)),
 19: dict(required_strings=('170918 - controlCamera: ',)),
 20: dict(required_strings=('isActivateLicense',)),
 21: dict(required_strings=('SAMSUNG','isActivateLicense')),
 22: dict(required_strings=('isActivateBCKLicense','isActivateBckLicense:')),
 23: dict(required_strings=('isActivateKnoxLicense','isActivateKpeLicense:')),
 24: dict(required_calls=('Lcom/samsung/android/knox/restriction/RestrictionPolicy;->isScreenCaptureEnabled(Z)Z',)),
 25: dict(required_calls=('Lcom/samsung/android/knox/restriction/RestrictionPolicy;->setScreenCapture(Z)Z',)),
 26: dict(required_calls=('Lcom/lge/mdm/LGMDMManager;->setAllowScreenCapture(Landroid/content/ComponentName;Z)V',)),
 27: dict(required_calls=('Lcom/lge/mdm/LGMDMManager;->setAllowScreenCaptureBlacklistWithoutADB(Landroid/content/ComponentName;ZLjava/util/List;)V',)),
 28: dict(required_calls=('Landroid/content/DialogInterface;->dismiss()V','Landroid/view/Window;->addFlags(I)V')),
 29: dict(required_strings=('NFC EventCode = ',)),
 30: dict(required_calls=('Landroid/app/Activity;->setResult(I)V','Landroid/app/Activity;->getWindow()Landroid/view/Window;')),
 31: dict(required_calls=('Landroid/content/Intent;->getBooleanExtra(Ljava/lang/String;Z)Z','Landroid/app/Activity;->getWindow()Landroid/view/Window;')),
 32: dict(required_calls=('Landroid/app/Activity;->finish()V','Landroid/view/Window;->addFlags(I)V')),
 33: dict(required_strings=('setScreenCaptureState : ',), required_fields=('Landroid/os/Build$VERSION;->SDK_INT:I',),
          required_calls=('Landroid/app/admin/DevicePolicyManager;->clearProfileOwner(Landroid/content/ComponentName;)V',)),
 34: dict(required_strings=('setCameraState : ',), required_calls=('Landroid/app/admin/DevicePolicyManager;->setCameraDisabled(Landroid/content/ComponentName;Z)V',)),
 35: dict(required_strings=('device_policy',), required_calls=('Landroid/app/admin/DevicePolicyManager;->setCameraDisabled(Landroid/content/ComponentName;Z)V',)),
 36: dict(required_strings=('device_policy',), required_fields=('Landroid/os/Build$VERSION;->SDK_INT:I',)),
 37: dict(required_calls=('Landroid/database/Cursor;->close()V',)),
 38: dict(required_strings=(';',)),
 39: dict(required_strings=('40','41')),
 40: dict(required_calls=('Lcom/sktelecom/ssm/policy/util/MeatGrinder;->checkSecurityStatusWithBomb(Landroid/content/Context;Z)I',)),
 41: dict(required_strings=('ELM activate = ','SAMSUNG')),
 42: dict(required_strings=('needCameraWatching = ','camList2 : ')),
 43: dict(required_strings=('checkDbFileHash pre integrity = ','dbintegrity')),
 44: dict(required_strings=('malwareReportUrl','malwareReportEnable','gid20cid214')),
 45: dict(required_strings=('gid20cid271','packagename','signature')),
 46: dict(required_strings=('commandMalwareInspection','android.intent.action.PACKAGE_REPLACED')),
 47: dict(required_strings=('sha256Value : ',' / info.signature : ')),
 48: dict(required_strings=('commandMalwareInspection','gid20cid214')),
 49: dict(required_strings=('essentialPermissions',)),
 50: dict(required_strings=('optionalPermissions',)),
 51: dict(required_calls=('Lcom/sktelecom/ssm/policy/util/b;->a(Landroid/content/Context;)Z',)),
 52: dict(required_strings=('canDrawOverlays = ','android:system_alert_window')),
 53: dict(required_strings=('isEnabled = ',), required_calls=('Landroid/provider/Settings;->canDrawOverlays(Landroid/content/Context;)Z',)),
 54: dict(required_strings=('permissionAgree',)),
 55: dict(required_calls=('Lcom/sktelecom/ssm/policy/config/Preset;->J()Ljava/util/List;',)),
 56: dict(required_strings=('170918 permission : ',)),
 57: dict(required_strings=('20160120 init isActiveEssentialPermissions.size() : ',)),
 58: dict(required_strings=('20181210 init isActiveOptionalPermissions.size() : ',)),
 59: dict(required_strings=('phone',), required_calls=('Landroid/telephony/TelephonyManager;->getCallState()I',)),
}

def plan_dex(dex_name, dex_bytes, cert_sha1=None):
 dex = DexFile(dex_bytes)
 sites = SEMANTIC_SITES[dex_name]
 require(len(sites) == len(DEX[dex_name]), f'{dex_name}: site/rule count mismatch')
 plan = []
 for index, ((identity, relative), (_, old, new)) in enumerate(zip(sites, DEX[dex_name])):
  cls, name, proto, size, registers = SEMANTIC_METHODS[identity]
  rid = f'{dex_name}:{index}'
  method = find_unique_method(dex, rid, class_filter='Lcom/sktelecom/ssm/'+cls+';',
   name_filter=name, proto=proto, insns_size=size, registers_size=registers,
   **SEMANTIC_FEATURES.get(identity, {}))
  off = find_unique_insn_offset(dex, method, rid, pattern=old, rel_off=relative)
  if identity == 7 and old.startswith('1a01'):
   str_idx = dex.find_string_index(cert_sha1 or DEFAULT_SSM_CERT_SHA1)
   require(0 <= str_idx <= 0xffff, f'{rid}: cert string index out of 16-bit range')
   new = '1a01' + struct.pack('<H', str_idx).hex() + '0000000000000000'
  if len(bytes.fromhex(old)) != len(bytes.fromhex(new)):
   raise ValueError(f'{rid}: unequal patch widths')
  if any(off < x + len(bytes.fromhex(y)) and x < off + len(bytes.fromhex(old)) for x, y, _ in plan):
   raise ValueError(f'{rid}: overlapping patch at {hex(off)}')
  plan.append((off, old, new))
 return plan

class ELF:
 def __init__(self,b):
  self.b=b; require(b[:4]==b'\x7fELF' and b[5]==1, 'invalid ELF header')
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
  raw=name.encode()+b'\0'; at=self.b.find(raw); require(at>=0 and self.b.find(raw,at+1)<0, f'ambiguous JNI name {name}')
  address=self.addr(at); hits=[]
  for s in self.ss:
   if s[2]&3!=3 or s[1]==8: continue
   for o in range(s[4],s[4]+s[5]-3*self.step+1,self.step):
    if self.ptr(o)==address:
     signature=self.file(self.ptr(o+self.step))
     require(self.b[signature:signature+30].startswith(b'(Landroid/content/Context;Z)I\0'), f'unexpected JNI signature for {name}')
     hits.append(self.ptr(o+2*self.step))
  require(len(hits)==1,(name,hits))
  return hits[0]
 def patches(self):
  zero={183:'00008052c0035fd6',40:'00207047',3:'31c0c3',62:'31c0c3'}[self.machine]
  ret={183:'c0035fd6',40:'7047',3:'c3',62:'c3'}[self.machine]
  found=[]
  for name in ['checkSecurityStatus','checkSecurityStatusWithBomb','isFoundDangerousProps','isFoundDangerousPropsAndroid14','_Z17delayedKillSwitchv']:
   address=self.jni(name) if name.startswith('check') else self.symbols[name]
   off=self.file(address); patch=bytes.fromhex(ret if name.startswith('_Z17') else zero)
   if self.machine==40: require(bool(address&1),'expected Thumb function')
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
 return upper=='META-INF/MANIFEST.MF' or upper.startswith('META-INF/') and upper.endswith(('.SF','.RSA','.DSA','.EC'))

def check(original,output,plans,dex_plans=None):
 with zipfile.ZipFile(original) as src,zipfile.ZipFile(output) as dst:
  src_infos=src.infolist()
  require(len({i.filename for i in src_infos})==len(src_infos),'duplicate source entries')
  originals={i.filename:i for i in src_infos if not removed(i.filename)}
  actual={i.filename:i for i in dst.infolist()}
  require(len(actual)==len(dst.infolist()),'duplicate output entries')
  require(originals.keys()<=actual.keys(),'missing original entries')
  added=actual.keys()-originals.keys()
  require(all(removed(n) for n in added),('unexpected entries',added))
  resolved_dex_plans = dex_plans
  if resolved_dex_plans is None:
   cert_sha1 = extract_apk_cert_sha1(original)
   resolved_dex_plans = {n: plan_dex(n, src.read(n), cert_sha1) for n in DEX}
  for n,i in originals.items():
   require(dst.getinfo(n).compress_type==i.compress_type,(n,'compression changed'))
   b=dst.read(n)
   if n in resolved_dex_plans:
    active_patches = resolved_dex_plans[n]
    expected_dex=bytearray(src.read(n))
    for off,old,new in active_patches:
     before,after=bytes.fromhex(old),bytes.fromhex(new)
     if len(before)!=len(after) or expected_dex[off:off+len(before)]!=before:
      raise ValueError((n,hex(off),'original mismatch'))
     expected_dex[off:off+len(after)]=after
    fix_dex(expected_dex)
    if b!=expected_dex:
     raise ValueError((n,'unexpected DEX change'))
    require(dex_valid(b), (n,'invalid DEX checksums'))
    validate_methods(b,active_patches)
    for off,_,new in active_patches:
     require(b[off:off+len(bytes.fromhex(new))]==bytes.fromhex(new),(n,hex(off),'patch absent'))
     print(n,hex(off),new)
    print(n,'SHA-1 and Adler32 OK')
   elif n in plans:
    original_so=src.read(n); expected=bytearray(original_so)
    for symbol,off,patch in plans[n]:
     expected[off:off+len(patch)]=patch
     require(b[off:off+len(patch)]==patch,(n,symbol,'patch absent'))
     print(n,symbol,hex(off),patch.hex())
    restore_crc(expected, correction_offset(expected), zlib.crc32(original_so) & 0xffffffff)
    require(b==expected,(n,'unexpected native change'))
    require((dst.getinfo(n).CRC, dst.getinfo(n).file_size) == (i.CRC, i.file_size), n)
   elif n == 'AndroidManifest.xml' and len(src.read(n)) >= 84000:
    require(b == patch_manifest(src.read(n)), (n, 'manifest mismatch'))
   else: require(b==src.read(n),(n,'content changed'))
  raw=Path(output).read_bytes();stored=0;native=0
  for entry in dst.infolist():
   if entry.compress_type==zipfile.ZIP_STORED:
    nl,el=struct.unpack_from('<HH',raw,entry.header_offset+26)
    alignment=4096 if entry.filename.endswith('.so') else 4
    require((entry.header_offset+30+nl+el)%alignment==0,(entry.filename,'misaligned'))
    stored+=1;native+=int(entry.filename.endswith('.so'))
  print('STORED alignment OK:',stored,'entries; 4096-byte native entries:',native,'; others 4-byte')
  require('res/2p.xml' in actual and 'res/2P.xml' in actual, 'missing case-distinct resource entries')
  print('ZIP entries original:',len(src.infolist()),'output:',len(dst.infolist()),'retained:',len(originals),'signing entries:',len(added))
  print('Case-distinct res/2p.xml and res/2P.xml both retained')

def regenerate_analysis(source, output):
 """Regenerate static evidence from independently decoded APK DEX streams."""
 import json
 root=Path(__file__).resolve().parents[2] / 'ssm' / 'analysis'
 first=root/'ssm_patched_and_core_methods.json'
 second=root/'ssm_callgraph_and_signatures.json'
 third=root/'ssm_certificate_and_universal_audit.json'
 require(first.is_file() and second.is_file() and third.is_file(), 'missing required SSM analysis JSON files')
 previous=json.loads(first.read_text())
 summaries=json.loads(second.read_text())['patched_methods_summary']
 audit_doc=json.loads(third.read_text())
 sec_methods=audit_doc.get('security_critical_methods', {})
 require(isinstance(sec_methods, dict) and bool(sec_methods), 'empty security_critical_methods in SSM audit JSON')
 selected={(r['dex'],r['method']) for r in summaries}
 for n,section in previous['dex_analysis'].items():
  methods=section.get('methods',[])
  for record in (methods.values() if isinstance(methods,dict) else methods):
   signature=record.get('method',record.get('signature'))
   if signature: selected.add((n,signature))
 for sig, rec in sec_methods.items():
  dex_name = rec.get('dex', 'classes.dex')
  selected.add((dex_name, sig))
 cert_sha1=extract_apk_cert_sha1(source)
 before={};after={}; incoming={}; after_incoming={}; dex_plans={}
 with zipfile.ZipFile(source) as src,zipfile.ZipFile(output) as dst:
  for name in src.namelist():
   if not (name.startswith('classes') and name.endswith('.dex')):continue
   before[name]=DexFile(src.read(name));after[name]=DexFile(dst.read(name))
   if name in DEX:
    dex_plans[name]=plan_dex(name, before[name].data, cert_sha1)
   for dex,edges in ((before[name],incoming),(after[name],after_incoming)):
    for m in dex.methods:
     if not m.code_off:continue
     dex.decode_method(m)
     for relative,off,_,op,_,ref in m.insns:
      if op in (*range(0x6e,0x73),*range(0x74,0x79)):
       edges.setdefault(ref,[]).append(dict(dex=name,method=m.signature,file_offset=hex(off),byte_offset=relative))
   for m in before[name].methods:
    if any(m.insns_off<=o<m.insns_off+2*m.insns_size for o,_,_ in dex_plans.get(name,[])):
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
  require(name in before, f'missing DEX {name} for {signature}')
  m=next((m for m in before[name].methods if m.signature==signature),None)
  require(m is not None and bool(m.code_off), f'missing code-bearing method {name}:{signature}')
  if m is None: raise AssertionError(signature)
  a=next((x for x in after[name].methods if x.signature==signature),None)
  require(a is not None and bool(a.code_off), f'missing patched method {name}:{signature}')
  if a is None: raise AssertionError(signature)
  patches=[dict(offset=hex(o),old=old,new=new) for o,old,new in dex_plans.get(name,[]) if m.insns_off<=o<m.insns_off+2*m.insns_size]
  tries=decode_tries(before[name].data, m, before[name])
  records.append(dict(dex=name,method=signature,code_item=hex(m.code_off),insns_start=hex(m.insns_off),
   header=dict(registers=m.registers_size,ins=m.ins_size,outs=m.outs_size,tries=m.tries_size,insns_size_cu=m.insns_size),
   try_blocks=tries,has_patch=bool(patches),patch_tuples=patches,
   before_instructions=instructions(m),after_instructions=instructions(a),
   unique_strings=sorted(m.strings),unique_calls=sorted(m.calls),unique_fields=sorted(m.fields),
   incoming_callers=incoming.get(signature,[]),after_incoming_callers=after_incoming.get(signature,[])))
 dex_analysis: dict[str, dict] = {}
 total_patches = sum(map(len, dex_plans.values()))
 evidence=dict(apk=Path(source).name,patch_tuple_count=total_patches,native_analysis=native,dex_analysis=dex_analysis)
 for name,patches in dex_plans.items():
  methods=[r for r in records if r['dex']==name]
  dex_analysis[name]=dict(original_sha256=hashlib.sha256(before[name].data).hexdigest(),patched_sha256=hashlib.sha256(after[name].data).hexdigest(),patch_tuples=[dict(offset=hex(o),old=old,new=new) for o,old,new in patches],method_count=len(methods),methods=methods)
 first.write_text(dump_analysis_json(evidence))
 second.write_text(dump_analysis_json(dict(patch_tuple_count=total_patches,incoming_callers_coverage='All explicit invoke sites across all APK DEX methods; no runtime dispatch or reflection inference',patched_methods_summary=records)))
 audit_doc.pop('patched_methods', None)
 audit_doc['patch_tuple_count']=total_patches
 by_sig={r['method']:r for r in records}
 for r in records:
  if r['has_patch'] and any(int(t['offset'], 16) in {o for o, _, _ in DEX['classes.dex'][50:]} for t in r['patch_tuples']):
   sec_methods.setdefault(r['method'], {'dex': r['dex']})
 for sig, rec in sec_methods.items():
  require(sig in by_sig, f'missing audit method record for {sig}')
  r = by_sig[sig]
  rec.pop('instructions', None)
  rec.pop('before', None)
  rec.pop('after', None)
  rec.pop('tries', None)
  rec['dex']=r['dex']
  rec['header']=r['header']
  rec['try_blocks']=r['try_blocks']
  rec['has_patch']=r['has_patch']
  rec['patch_tuples']=r['patch_tuples']
  rec['before_instructions']=r['before_instructions']
  rec['after_instructions']=r['after_instructions']
  rec['incoming_callers']=r['incoming_callers']
  rec['after_incoming_callers']=r['after_incoming_callers']
 third.write_text(dump_analysis_json(audit_doc))

def main():
 p=argparse.ArgumentParser();p.add_argument('source');p.add_argument('output');p.add_argument('--red',action='store_true');p.add_argument('--regenerate-analysis',action='store_true');a=p.parse_args()
 src=Path(a.source).resolve(); out=Path(a.output).resolve()
 require(src!=out and not out.exists(),'refusing overwrite')
 cert_sha1=extract_apk_cert_sha1(src)
 replacements={};plans={};dex_plans={}
 with zipfile.ZipFile(src) as z:
  replacements['AndroidManifest.xml'] = patch_manifest(z.read('AndroidManifest.xml'))
  for n in DEX:
   b=bytearray(z.read(n));require(dex_valid(b),(n,'invalid input DEX'))
   patches=plan_dex(n,b,cert_sha1)
   dex_plans[n]=patches
   for off,old,new in patches:
    before=bytes.fromhex(old);after=bytes.fromhex(new)
    require(len(before)==len(after), (n,hex(off),'width mismatch'))
    require(b[off:off+len(before)]==before,(n,hex(off),'original mismatch'))
    b[off:off+len(after)]=after
   validate_methods(b,patches)
   replacements[n]=fix_dex(b)
  for n in z.namelist():
   if not n.startswith('lib/') or not n.endswith('/libnative-lib.so'):continue
   b=z.read(n);elf=ELF(b);plans[n]=elf.patches()
   replacements[n]=patch_native(b, plans[n])
 require(len(plans)==4, 'expected 4 ABI native plans')
 if a.red:
  check(src,src,plans,dex_plans)
  raise AssertionError('RED expected failure did not occur')
 out.parent.mkdir(parents=True, exist_ok=True)
 stage_fd, stage_name = tempfile.mkstemp(prefix=f'.{out.name}.tmp-', dir=str(out.parent))
 os.close(stage_fd)
 stage_path = Path(stage_name)
 try:
  with tempfile.TemporaryDirectory(prefix='ssm-build-') as tmp:
   tmp=Path(tmp);signed=tmp/'signed.apk';ks=DEFAULT_KEYSTORE
   build_signed_apk(src, signed, replacements, ks)
   check(src, signed, plans, dex_plans)
   verification=run('jarsigner','-verify',signed)
   require(b'jar verified.' in verification, 'jarsigner verification failed')
   print('v2 RSA signature verified with OpenSSL; Android platform verifier not executed')
   stage_path.write_bytes(signed.read_bytes())
  if a.regenerate_analysis:
   regenerate_analysis(src, stage_path)
  os.link(stage_path, out)
 finally:
  if stage_path.exists():
   stage_path.unlink()
 print('OUTPUT',out,'SHA256',hashlib.sha256(out.read_bytes()).hexdigest())
 print('Signed with existing local re_release keystore; cannot update an original-signed installation.')
if __name__=='__main__':main()
