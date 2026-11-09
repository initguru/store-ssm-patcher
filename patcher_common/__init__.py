"""Shared, fail-closed DEX, ELF and APK rebuilding primitives."""
import copy
import hashlib
import re
import struct
import subprocess
import tempfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REPO_root = REPO_ROOT
DEFAULT_KEYSTORE = REPO_ROOT / 'signing' / 're_release.keystore'
U = lambda b, o: struct.unpack_from('<I', b, o)[0]
H = lambda b, o: struct.unpack_from('<H', b, o)[0]


def uleb(b, o):
    v = 0
    for s in range(0, 35, 7):
        x = b[o]; o += 1; v |= (x & 127) << s
        if x < 128:
            return v, o
    raise ValueError('Invalid LEB128')


def sleb(b, o):
    v = 0
    for s in range(0, 35, 7):
        x = b[o]; o += 1; v |= (x & 127) << s
        if x < 128:
            return v - (1 << (s + 7)) if x & 64 else v, o
    raise ValueError('Invalid signed LEB128')


WIDTH = {op: 1 for op in range(0xe3) if op not in {*range(0x3e, 0x44), 0x73, 0x79, 0x7a}}
for ops, w in [('02 05 08 13 15 16 19 1a 1c 1f 20 22 23 29', 2), ('03 06 09 14 17 1b 24 25 26 2a 2b 2c', 3), ('18', 5)]:
    for op in ops.split(): WIDTH[int(op, 16)] = w
for a, b, w in [(0x2d,0x3e,2),(0x44,0x6e,2),(0x6e,0x73,3),(0x74,0x79,3),(0x90,0xb0,2),(0xd0,0xe3,2)]:
    for op in range(a,b): WIDTH[op] = w
KIND = {0x1a:'string', 0x1b:'string', **dict.fromkeys((0x1c,0x1f,0x20,0x22,0x23,0x24,0x25),'type'), **dict.fromkeys(range(0x52,0x6e),'field'), **dict.fromkeys((*range(0x6e,0x73),*range(0x74,0x79)),'method')}


@dataclass
class MethodDef:
    idx: int
    class_desc: str
    name: str
    proto: str
    return_type: str
    access_flags: int
    code_off: int
    insns_off: int = 0
    insns_size: int = 0
    registers_size: int = 0
    ins_size: int = 0
    outs_size: int = 0
    tries_size: int = 0
    strings: set = field(default_factory=set)
    calls: set = field(default_factory=set)
    fields: set = field(default_factory=set)
    consts: set = field(default_factory=set)
    insns: list = field(default_factory=list)

    @property
    def signature(self):
        return f'{self.class_desc}->{self.name}{self.proto}'


class DexFile:
    def __init__(self, data):
        self.data = bytes(data)
        d = self.data
        if len(d) < 112 or not d.startswith(b'dex\n'):
            raise ValueError('Not a DEX file')
        self.string_ids = []
        for i in range(U(d,56)):
            o = U(d,U(d,60)+4*i); _,o = uleb(d,o)
            self.string_ids.append(d[o:d.index(0,o)].replace(b'\xc0\x80',b'\0').decode('utf8','surrogatepass'))
        self.type_ids = [self.string_ids[U(d,U(d,68)+4*i)] for i in range(U(d,64))]
        self.proto_ids = []
        for i in range(U(d,72)):
            s,r,p = struct.unpack_from('<III',d,U(d,76)+12*i)
            params = [] if not p else [self.type_ids[H(d,p+4+2*j)] for j in range(U(d,p))]
            self.proto_ids.append(dict(shorty=self.string_ids[s], return_type=self.type_ids[r], params=params, signature='('+''.join(params)+')'+self.type_ids[r]))
        self.field_ids = []
        for i in range(U(d,80)):
            c,t,n = struct.unpack_from('<HHI',d,U(d,84)+8*i)
            self.field_ids.append(dict(class_type=self.type_ids[c],field_type=self.type_ids[t],name=self.string_ids[n],signature=f'{self.type_ids[c]}->{self.string_ids[n]}:{self.type_ids[t]}'))
        self.method_ids = []
        for i in range(U(d,88)):
            c,p,n = struct.unpack_from('<HHI',d,U(d,92)+8*i)
            self.method_ids.append(dict(class_type=self.type_ids[c],proto=self.proto_ids[p]['signature'],name=self.string_ids[n],signature=f'{self.type_ids[c]}->{self.string_ids[n]}{self.proto_ids[p]["signature"]}'))
        self.class_defs = []
        self.methods = []
        for i in range(U(d,96)):
            vals = struct.unpack_from('<8I',d,U(d,100)+32*i)
            cls: dict[str, object] = dict(zip(('class_idx','access_flags','superclass_idx','interfaces_off','source_file_idx','annotations_off','class_data_off','static_values_off'),vals))
            self.class_defs.append(cls)
            class_data_off = cls['class_data_off']
            assert isinstance(class_data_off, int)
            o = int(class_data_off)
            if not o: continue
            counts = []
            for _ in range(4): v,o = uleb(d,o); counts.append(v)
            fields = []
            for count in counts[:2]:
                idx = 0
                for _ in range(count):
                    delta,o=uleb(d,o); flags,o=uleb(d,o); idx+=delta; fields.append((idx,flags))
            defined = []
            for count in counts[2:]:
                idx = 0
                for _ in range(count):
                    delta,o=uleb(d,o); flags,o=uleb(d,o); co,o=uleb(d,o); idx+=delta
                    mid=self.method_ids[idx]
                    m=MethodDef(idx,mid['class_type'],mid['name'],mid['proto'],mid['proto'].split(')')[1],flags,co)
                    if co:
                        m.registers_size,m.ins_size,m.outs_size,m.tries_size=struct.unpack_from('<4H',d,co)
                        m.insns_size=U(d,co+12); m.insns_off=co+16
                    self.methods.append(m); defined.append(m)
            cls['class_data_item'] = dict(fields=fields,methods=defined)

    def decode_method(self, m):
        m.strings.clear(); m.calls.clear(); m.fields.clear(); m.consts.clear(); m.insns.clear()
        for u,o,w,op,raw,payload in _decode(self.data,m):
            ref = None
            if not payload and op in KIND:
                idx=U(raw,2) if op==0x1b else H(raw,2)
                table=getattr(self,KIND[op]+'_ids')
                assert idx<len(table), ('reference out of range',o)
                ref=table[idx]
                if isinstance(ref,dict): ref=ref.get('signature')
                if KIND[op]=='string': m.strings.add(ref)
                elif KIND[op]=='method': m.calls.add(ref)
                elif KIND[op]=='field': m.fields.add(ref)
            if op==0x12: m.consts.add((raw[1]>>4)-16 if raw[1]&128 else raw[1]>>4)
            elif op in (0x13,0x16): m.consts.add(struct.unpack_from('<h',raw,2)[0])
            elif op in (0x14,0x17): m.consts.add(struct.unpack_from('<i',raw,2)[0])
            elif op==0x18: m.consts.add(struct.unpack_from('<q',raw,2)[0])
            elif op in (0x15,0x19): m.consts.add(struct.unpack_from('<h',raw,2)[0] << (16 if op==0x15 else 48))
            m.insns.append((u*2,o,w*2,op,raw,ref))
        return m


def _decode(d,m):
    u=0
    while u<m.insns_size:
        o=m.insns_off+u*2; word=H(d,o); op=word&255
        assert op in WIDTH, ('illegal opcode',o,op)
        w=WIDTH[op]; payload=op==0 and word!=0
        if payload:
            assert u%2==0, ('unaligned payload',o)
            if word==0x100: w=4+2*H(d,o+2)
            elif word==0x200: w=2+4*H(d,o+2)
            elif word==0x300:
                size=H(d,o+2); count=U(d,o+4)
                assert count==0 or size in (1,2,4,8)
                w=4+(size*count+1)//2
            else: raise AssertionError(('invalid payload',o))
        assert u+w<=m.insns_size and o+2*w<=len(d), ('instruction overrun',o)
        yield u,o,w,op,d[o:o+2*w],payload
        u+=w


def find_unique_method(dex, rule_id, class_filter=None, name_filter=None, proto=None, required_strings=(), required_calls=(), required_fields=(), insns_size=None, registers_size=None, custom_predicate=None):
    if not isinstance(dex,DexFile): dex=DexFile(dex)
    def match(f,v): return f is None or (f(v) if callable(f) else bool(f.search(v)) if hasattr(f,'search') else f==v)
    matches=[]
    for m in dex.methods:
        if not match(class_filter,m.class_desc) or not match(name_filter,m.name): continue
        if proto is not None and proto!=m.proto: continue
        if insns_size is not None and insns_size!=m.insns_size: continue
        if registers_size is not None and registers_size!=m.registers_size: continue
        dex.decode_method(m)
        if not set(required_strings)<=m.strings or not set(required_calls)<=m.calls or not set(required_fields)<=m.fields: continue
        if custom_predicate is not None and not custom_predicate(m): continue
        matches.append(m)
    if len(matches)!=1: raise ValueError(f'Rule {rule_id}: expected 1 method, found {len(matches)}')
    return matches[0]


def find_unique_insn_offset(dex, method, rule_id, pattern=None, rel_off=None, opcode=None, ref=None):
    if not isinstance(dex,DexFile): dex=DexFile(dex)
    dex.decode_method(method)
    if isinstance(pattern,str): pattern=bytes.fromhex(pattern)
    matches=[o for r,o,_,op,_,s in method.insns if (rel_off is None or rel_off==r) and (opcode is None or opcode==op) and (ref is None or ref==s) and (pattern is None or dex.data[o:o+len(pattern)]==pattern)]
    if len(matches)!=1: raise ValueError(f'Rule {rule_id}: expected 1 instruction, found {len(matches)}')
    return matches[0]


def resolve_semantic_plan(dex, rules):
    if not isinstance(dex,DexFile): dex=DexFile(dex)
    result=[]
    for rule in rules:
        rid=rule['rule_id']; m=find_unique_method(dex,rid,**rule['method'])
        o=find_unique_insn_offset(dex,m,rid,**rule['instruction'])
        old,new=rule['old'],rule['new']
        a=bytes.fromhex(old) if isinstance(old,str) else bytes(old)
        b=bytes.fromhex(new) if isinstance(new,str) else bytes(new)
        if len(a)!=len(b) or dex.data[o:o+len(a)]!=a: raise ValueError(f'Rule {rid}: byte precondition failed')
        if any(o<x+len(bytes.fromhex(y)) and x<o+len(a) for x,y,_ in result): raise ValueError('Overlapping patches')
        result.append((o,a.hex(),b.hex()))
    return result


def _registers(raw,op):
    a=raw[1]; regs=[]; wide=set()
    if op==0 or op in (0x0e,0x28,0x29,0x2a): return regs,wide
    if op in (2,5,8): regs=[a,H(raw,2)]
    elif op in (3,6,9): regs=list(struct.unpack_from('<HH',raw,2))
    elif op in (*range(0x6e,0x73),0x24):
        count=a>>4; assert count<=5
        packed=H(raw,4); regs=([(packed>>(4*i))&15 for i in range(4)]+[a&15])[:count]
    elif op in (*range(0x74,0x79),0x25): regs=list(range(H(raw,4),H(raw,4)+a))
    elif op in (1,4,7,0x12,0x20,0x21,0x23) or 0x32<=op<=0x37 or 0x52<=op<=0x5f or 0x7b<=op<=0x8f or 0xb0<=op<=0xcf or 0xd0<=op<=0xd7: regs=[a&15,a>>4]
    elif 0x2d<=op<=0x31 or 0x44<=op<=0x51 or 0x90<=op<=0xaf: regs=[a,raw[2],raw[3]]
    elif 0xd8<=op<=0xe2: regs=[a,raw[2]]
    else: regs=[a]
    if op==0x12: regs=regs[:1]
    if op in (4,5,6): wide={0,1}
    elif op in (0xb,0x10,0x16,0x17,0x18,0x19,0x45,0x4c,0x53,0x5a,0x61,0x68): wide={0}
    elif op in (0x2f,0x30,0x31): wide={1,2}
    elif op in (0x7d,0x7e,0x80,0x86,0x8b): wide={0,1}
    elif op in (0x81,0x83,0x88,0x89): wide={0}
    elif op in (0x84,0x85,0x8a,0x8c): wide={1}
    elif 0x9b<=op<=0xa5: wide={0,1} if op>=0xa3 else {0,1,2}
    elif 0xab<=op<=0xaf: wide={0,1,2}
    elif 0xbb<=op<=0xc5: wide={0} if op>=0xc3 else {0,1}
    elif 0xcb<=op<=0xcf: wide={0,1}
    return regs,wide


def validate_methods(dex_bytes, patches):
    try:
        _validate_methods(bytes(dex_bytes),patches)
    except (IndexError,KeyError,ValueError,struct.error) as e:
        raise AssertionError(f'Malformed DEX: {e}') from e


def _validate_methods(d,patches):
    dex=DexFile(d); selected=[]
    for m in dex.methods:
        if m.code_off and any(m.insns_off<=p[0]<m.insns_off+2*m.insns_size for p in patches): selected.append(m)
    assert selected, 'No patched methods'
    for m in selected:
        records=list(_decode(d,m)); ordinary={u:(o,w,op,raw) for u,o,w,op,raw,p in records if not p}
        instruction_starts=set(ordinary); payloads={u:H(d,o) for u,o,*_,p in records if p}
        edges={}; padding_candidates={}
        payload_starts=set(payloads); branch_targets=set(); fallthrough=set(); handlers=set()
        assert 0 in instruction_starts and m.ins_size<=m.registers_size
        for u,(o,w,op,raw) in ordinary.items():
            regs,wide=_registers(raw,op)
            for i,v in enumerate(regs): assert 0<=v and v+(i in wide)<m.registers_size, ('register out of range',o,v)
            if op in KIND:
                idx=U(raw,2) if op==0x1b else H(raw,2)
                assert idx<len(getattr(dex,KIND[op]+'_ids')), ('reference out of range',o)
                if KIND[op]=='method':
                    mid=dex.method_ids[idx]; args=re.findall(r'\[*L[^;]+;|\[*[ZBSCIFJD]',mid['proto'].split(')')[0][1:])
                    widths=[1] * (op not in (0x71,0x77)) + [2 if x in ('J','D') else 1 for x in args]
                    assert len(regs)==sum(widths) and len(regs)<=m.outs_size
                    pos=0
                    for size in widths:
                        if size==2: assert regs[pos]+1==regs[pos+1] and regs[pos]+1<m.registers_size
                        pos+=size
            targets=[]
            if op==0x28: targets=[u+struct.unpack('<b',raw[1:2])[0]]
            elif op==0x29 or 0x32<=op<=0x3d: targets=[u+struct.unpack_from('<h',raw,2)[0]]
            elif op==0x2a: targets=[u+struct.unpack_from('<i',raw,2)[0]]
            elif op in (0x26,0x2b,0x2c):
                pu=u+struct.unpack_from('<i',raw,2)[0]
                assert pu in payload_starts and payloads[pu]=={0x26:0x300,0x2b:0x100,0x2c:0x200}[op]
                po=m.insns_off+pu*2; n=H(d,po+2)
                if op!=0x26:
                    to=po+8 if op==0x2b else po+4+4*n
                    targets=[u+struct.unpack_from('<i',d,to+4*i)[0] for i in range(n)]
            for target in targets: assert target in instruction_starts, ('invalid branch target',o,target)
            branch_targets.update(targets)
            edges[u]=set(targets)
            if op not in (0x0e,0x0f,0x10,0x11,0x27,0x28,0x29,0x2a):
                if u+w in instruction_starts:
                    fallthrough.add(u+w)
                    edges[u].add(u+w)
                elif op==0 and u+w in payload_starts:
                    padding_candidates[u]=o
                else:
                    assert False, ('invalid fallthrough',o)
            if 0x0e<=op<=0x11:
                r=m.return_type; expected=0x0e if r=='V' else 0x10 if r in ('J','D') else 0x11 if r.startswith(('L','[')) else 0x0f
                assert op==expected, ('return type mismatch',o,r)
        if m.tries_size:
            end=m.insns_off+2*m.insns_size; table=end+(m.insns_size%2)*2; base=table+8*m.tries_size
            count,pos=uleb(d,base); valid_handlers=set()
            for _ in range(count):
                valid_handlers.add(pos-base); size,pos=sleb(d,pos)
                for _ in range(abs(size)):
                    typ,pos=uleb(d,pos); addr,pos=uleb(d,pos)
                    assert typ<len(dex.type_ids) and addr in instruction_starts
                    handlers.add(addr)
                if size<=0:
                    addr,pos=uleb(d,pos); assert addr in instruction_starts; handlers.add(addr)
            for i in range(m.tries_size):
                start,count,ho=struct.unpack_from('<IHH',d,table+8*i)
                assert count>0 and start in instruction_starts and start+count in instruction_starts|{m.insns_size} and ho in valid_handlers
        reachable=set(); pending=list({0}|handlers)
        while pending:
            u=pending.pop()
            if u in reachable: continue
            reachable.add(u)
            pending.extend(edges[u]-reachable)
        reachable_fallthrough={u+ordinary[u][1] for u in reachable if u+ordinary[u][1] in edges[u] and ordinary[u][2] not in (0x28,0x29,0x2a)}
        for u,o in padding_candidates.items():
            assert u not in reachable, ('invalid fallthrough into payload',o)
        prev=None
        for u,(o,w,op,raw) in ordinary.items():
            if op in (0xa,0xb,0xc):
                assert prev is not None and prev[0]+prev[1]==u and prev[2] in (*range(0x6e,0x73),*range(0x74,0x79),0x24,0x25)
                assert u not in branch_targets and u not in handlers and u!=0
                pop,praw=prev[2],prev[3]
                r='[' if pop in (0x24,0x25) else dex.method_ids[H(praw,2)]['proto'].split(')')[1]
                assert r!='V' and op==(0xb if r in ('J','D') else 0xc if r.startswith(('L','[')) else 0xa)
            if op==0xd: assert u in handlers and u not in branch_targets and u not in reachable_fallthrough and u!=0
            prev=(u,w,op,raw)


def dex_valid(d):
    return len(d)>=112 and d[:4]==b'dex\n' and d[12:32]==hashlib.sha1(d[32:]).digest() and U(d,8)==zlib.adler32(d[12:])&0xffffffff


def fix_dex(d):
    b=bytearray(d); b[12:32]=hashlib.sha1(b[32:]).digest(); struct.pack_into('<I',b,8,zlib.adler32(b[12:])&0xffffffff)
    if isinstance(d,bytearray): d[:]=b
    return b


def verify_dex_exact(original,result,patches):
    expected=bytearray(original)
    for o,old,new in patches:
        old=bytes.fromhex(old) if isinstance(old,str) else bytes(old)
        new=bytes.fromhex(new) if isinstance(new,str) else bytes(new)
        assert len(old)==len(new) and 0<=o<=len(expected)-len(old) and expected[o:o+len(old)]==old
        expected[o:o+len(new)]=new
    assert bytes(result)==fix_dex(expected), 'Unexpected DEX modifications'
    assert dex_valid(result)
    validate_methods(result,patches)


def restore_crc(b,o,target):
    assert 0<=o<=len(b)-4 and 0<=target<=0xffffffff
    base=zlib.crc32(b)&0xffffffff; basis={}
    for bit in range(32):
        b[o+bit//8]^=1<<(bit%8); v=(zlib.crc32(b)&0xffffffff)^base; b[o+bit//8]^=1<<(bit%8); mask=1<<bit
        while v:
            k=v.bit_length()-1
            if k not in basis: basis[k]=(v,mask); break
            v0,m0=basis[k]; v^=v0; mask^=m0
    assert len(basis)==32
    v=base^target; mask=0
    while v:
        v0,m0=basis[v.bit_length()-1]; v^=v0; mask^=m0
    for bit in range(32):
        if mask>>bit&1: b[o+bit//8]^=1<<(bit%8)
    assert zlib.crc32(b)&0xffffffff==target


def correction_offset(b):
    assert b[:4]==b'\x7fELF' and b[5]==1 and b[4] in (1,2)
    wide=b[4]==2
    ph,sh=struct.unpack_from('<QQ' if wide else '<II',b,32 if wide else 28)
    pe,pn,se,sn,si=struct.unpack_from('<5H',b,54 if wide else 42)
    sections=[struct.unpack_from('<IIQQQQIIQQ' if wide else '<10I',b,sh+i*se) for i in range(sn)]
    st=sections[si]; names=b[st[4]:st[4]+st[5]]
    protected=[(0,64 if wide else 52),(ph,ph+pe*pn),(sh,sh+se*sn),(st[4],st[4]+st[5])]
    for i in range(pn):
        p=struct.unpack_from('<IIQQQQQQ' if wide else '<8I',b,ph+i*pe)
        if p[0]==1:
            o=p[2] if wide else p[1]; protected.append((o,o+p[5 if wide else 4]))
    for s in sections:
        if names[s[0]:].split(b'\0')[0]==b'.comment' and s[5]>=16:
            o=s[4]+8
            if o+4<=len(b) and all(o+4<=a or o>=e for a,e in protected): return o
    raise AssertionError('No safe .comment CRC correction slot')


def repack(src,dst,replacements=None,strip=False):
    with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst,'w') as zo:
        zo.comment=zi.comment
        for info in zi.infolist():
            if strip and re.match(r'^META-INF/(?:[^/]+\.(?:SF|RSA|DSA|EC)|MANIFEST\.MF)$',info.filename,re.I): continue
            data=(replacements or {}).get(info.filename)
            if data is None: data=zi.read(info)
            x=copy.copy(info); x.extra=b''
            if x.compress_type==zipfile.ZIP_STORED:
                alignment=4096 if x.filename.endswith('.so') else 4
                encoding='utf8' if x.flag_bits&0x800 or not x.filename.isascii() else 'ascii'
                assert zo.fp is not None
                base=zo.fp.tell()+30+len(x.filename.encode(encoding)); pad=(-base)%alignment
                if pad:
                    if pad<4: pad+=alignment
                    x.extra=struct.pack('<HH',0xd935,pad-4)+bytes(pad-4)
            zo.writestr(x,data)


def lp(b): return struct.pack('<I',len(b))+b

def run(*args): return subprocess.check_output([str(a) for a in args],stderr=subprocess.STDOUT)


def v2(src,dst,work):
    work=Path(work); b=Path(src).read_bytes(); e=None
    for off in range(len(b)-22,max(-1,len(b)-65558),-1):
        if b[off:off+4]==b'PK\x05\x06' and off+22+H(b,off+20)==len(b): e=off; break
    assert e is not None, 'Missing ZIP EOCD'
    cd=U(b,e+16); assert cd+U(b,e+12)==e and H(b,e+4)==H(b,e+6)==0, 'Unsupported ZIP layout'
    chunks=[]
    for section in (b[:cd],b[cd:e],b[e:]):
        for i in range(0,len(section),1048576):
            c=section[i:i+1048576]; chunks.append(hashlib.sha256(b'\xa5'+struct.pack('<I',len(c))+c).digest())
    digest=hashlib.sha256(b'\x5a'+struct.pack('<I',len(chunks))+b''.join(chunks)).digest()
    cert=run('openssl','x509','-in',work/'cert.pem','-outform','DER')
    pub=run('openssl','pkey','-in',work/'key.pem','-pubout','-outform','DER')
    signed=lp(lp(struct.pack('<I',0x103)+lp(digest)))+lp(lp(cert))+lp(b'')
    (work/'signed-data').write_bytes(signed)
    sig=run('openssl','dgst','-sha256','-sign',work/'key.pem',work/'signed-data')
    (work/'signature').write_bytes(sig); (work/'pub.pem').write_bytes(run('openssl','pkey','-in',work/'key.pem','-pubout'))
    assert b'Verified OK' in run('openssl','dgst','-sha256','-verify',work/'pub.pem','-signature',work/'signature',work/'signed-data')
    signer=lp(signed)+lp(lp(struct.pack('<I',0x103)+lp(sig)))+lp(pub)
    pair=struct.pack('<I',0x7109871a)+lp(lp(signer)); pair=struct.pack('<Q',len(pair))+pair
    size=len(pair)+24; block=struct.pack('<Q',size)+pair+struct.pack('<Q',size)+b'APK Sig Block 42'
    end=bytearray(b[e:]); struct.pack_into('<I',end,16,cd+len(block)); Path(dst).write_bytes(b[:cd]+block+b[cd:e]+end)


def build_signed_apk(source,output,replacements=None,keystore=DEFAULT_KEYSTORE,storepass='changeit',alias='re_release'):
    keystore=Path(keystore)
    if not keystore.is_file(): raise FileNotFoundError(keystore)
    with tempfile.TemporaryDirectory(prefix='apk-sign-') as tmp:
        work=Path(tmp)
        repack(source,work/'unsigned.apk',replacements,True)
        run('jarsigner','-keystore',keystore,'-storepass',storepass,'-sigalg','SHA256withRSA','-digestalg','SHA-256','-signedjar',work/'v1.apk',work/'unsigned.apk',alias)
        repack(work/'v1.apk',work/'aligned.apk')
        run('openssl','pkcs12','-in',keystore,'-passin','pass:'+storepass,'-nodes','-nocerts','-out',work/'key.pem')
        run('openssl','pkcs12','-in',keystore,'-passin','pass:'+storepass,'-clcerts','-nokeys','-out',work/'cert.pem')
        v2(work/'aligned.apk',output,work)
        run('jarsigner','-verify',output)
    return Path(output)
