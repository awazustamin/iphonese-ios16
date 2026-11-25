#!/usr/bin/env python3
"""audioport - reclaim two unused iPad audio drivers in the iPad 5 iOS 16.1
kernel for the iPhone SE (N69) codec (AppleCS42L71Audio) and amp
(AppleCS35L19Amp) drivers transplanted from the SE's iOS 15.8.8 kernel.

Usage:
    python3 patchsrc/audioport.py <dst_kernel_after_kextport> <se15_kernel> \
        <output> [--profiles audioport-profiles.json.gz] [--only cs42l71]

stdlib-only; runs with macOS /usr/bin/python3 (3.9+).
Engine derived from SevenUP (iOS 16.1 port for iPhone 7), BSD-3-Clause;
CS42L71 ABI data retargeted from SevenUP's reviewed profiles.
"""

import base64
import bisect
import collections
import copy
import gzip
import hashlib
import json
import re
import struct
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.sax.saxutils import escape

HERE = Path(__file__).resolve().parent

"""Legacy prelinked kernel reader; Apple XML IDREF support is required."""

def plist(data):
    root=ET.fromstring(data.rstrip(b'\0'))
    ids={e.attrib['ID']:e for e in root.iter() if 'ID' in e.attrib}
    def val(e):
        if 'IDREF' in e.attrib:return val(ids[e.attrib['IDREF']])
        if e.tag=='dict':
            a=list(e);return {a[i].text:val(a[i+1]) for i in range(0,len(a),2)}
        if e.tag in ('array','set'):return [val(x) for x in e]
        if e.tag=='integer':return int(e.text or '0',16 if (e.text or '').startswith('0x') else 10)
        if e.tag=='data':return base64.b64decode(e.text or '')
        if e.tag=='true':return True
        if e.tag=='false':return False
        return e.text or ''
    return val(root)

def macho(b,base):
    assert b[base:base+4]==bytes.fromhex('cffaedfe')
    off=base+32;out=[]
    for _ in range(struct.unpack_from('<I',b,base+16)[0]):
        cmd,size=struct.unpack_from('<II',b,off)
        if cmd==25:
            name=b[off+8:off+24].split(b'\0')[0].decode()
            va,vs,fo,fs,mx,prot,ns,flags=struct.unpack_from('<QQQQiiII',b,off+24)
            sec=[]
            for j in range(ns):
                q=off+72+80*j;sn=b[q:q+16].split(b'\0')[0].decode()
                sa,ss,sf=struct.unpack_from('<QQI',b,q+32)
                sec.append(dict(name=sn,addr=sa,size=ss,offset=sf))
            out.append(dict(name=name,addr=va,size=fs,offset=fo,vmsize=vs,sections=sec))
        off+=size
    return out

class KC:
    def __init__(self,p):
        self.data=Path(p).read_bytes();self.base=0
        if self.data[:4]==bytes.fromhex('cafebabe'):self.base=struct.unpack_from('>I',self.data,16)[0]
        self.segments=macho(self.data,self.base)
        s=next(s for s in self.segments if s['name']=='__PRELINK_INFO')
        self.xml=self.data[self.base+s['offset']:self.base+s['offset']+s['size']].rstrip(b'\0')
        self.kexts={k['CFBundleIdentifier']:k for k in plist(self.xml)['_PrelinkInfoDictionary']}
    def offset(self,va):
        for s in self.segments:
            if s['addr']<=va<s['addr']+s['size']:return self.base+s['offset']+va-s['addr']
        raise ValueError(hex(va))
    def ksegments(self,n):
        va=self.kexts[n].get('_PrelinkExecutableLoadAddr')
        return macho(self.data,self.offset(va)) if va else []
    def read(self,va,size):
        o=self.offset(va);return self.data[o:o+size]

"""Shared helpers vendored from SevenUP (BSD-3-Clause, jmx/SevenUP project).

Source: src/iphone7_port/{core,kernel_chestnut,kernel_base,kernel_maggie,
kernel_d2333,kernel_transplant}.py — logic unchanged; only consolidated here.
"""




def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def load_json(path):
    with open(path, 'rb') as f:
        return json.loads(f.read())


def commands(k, va=None):
    off = k.base if va is None else k.offset(va)
    q = off + 32
    for _ in range(struct.unpack_from('<I', k.data, off + 16)[0]):
        cmd, size = struct.unpack_from('<II', k.data, q)
        yield cmd, q, size
        q += size


def image_uuid(k, va):
    return next(k.data[q + 8:q + 24] for cmd, q, size in commands(k, va) if cmd == 27)


def relocations(k):
    d = plist(k.xml)['_PrelinkLinkKASLROffsets']
    words = list(struct.unpack('<' + 'I' * (len(d) // 4), d))
    require(words[0] == len(words) - 1, 'Invalid packed KASLR count')
    require(len(words[1:]) == len(set(words[1:])), 'Duplicate original KASLR slots')
    start = next(s['addr'] for s in k.segments if s['name'] == '__PRELINK_TEXT')
    return start, words[1:]


def xml_value(v):
    if isinstance(v, (bytes, bytearray)):
        return '<data>' + base64.b64encode(v).decode('ascii') + '</data>'
    if isinstance(v, dict):
        return '<dict>' + ''.join('<key>' + escape(k) + '</key>' + xml_value(x) for k, x in v.items()) + '</dict>'
    if isinstance(v, list):
        return '<array>' + ''.join(xml_value(x) for x in v) + '</array>'
    if isinstance(v, bool):
        return '<true/>' if v else '<false/>'
    if isinstance(v, int):
        return '<integer size="64">0x' + format(v, 'x') + '</integer>'
    if isinstance(v, str):
        return '<string>' + escape(v) + '</string>'
    raise TypeError(type(v))


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def adrp_page(word, pc):
    imm = ((word >> 29) & 3) | (((word >> 5) & 0x7ffff) << 2)
    return (pc & ~4095) + (signed(imm, 21) << 12)


def encode_adrp(word, pc, page):
    pages = (page - (pc & ~4095)) >> 12
    require(-(1 << 20) <= pages < (1 << 20), 'ADRP out of range')
    imm = pages & 0x1fffff
    return (word & ~0x60ffffe0) | ((imm & 3) << 29) | ((imm >> 2) << 5)


def branch(pc, target):
    delta = target - pc
    require(delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27), 'ARM64 branch is out of range.')
    return struct.pack('<I', 0x14000000 | ((delta >> 2) & 0x3ffffff))


def adr(pc, target, reg):
    delta = target - pc
    assert -(1 << 20) <= delta < (1 << 20)
    n = delta & 0x1fffff
    return (0x10000000 | ((n & 3) << 29) | ((n >> 2) << 5) | reg)


def bl(pc, target):
    return struct.pack('<I', struct.unpack('<I', branch(pc, target))[0] | 0x80000000)


def entry_range(xml, name):
    prefix = b'<dict><key>_PrelinkInfoDictionary</key><array>'
    require(xml.startswith(prefix), 'Unexpected XML')
    start = len(prefix)
    depth = 0
    begin = None
    for m in re.finditer(rb'<dict\b[^>]*>|</dict>', xml[start:]):
        tag = m[0]
        off = start + m.start()
        if tag.startswith(b'</'):
            depth -= 1
            if depth == 0 and name.encode() in xml[begin:start + m.end()]:
                return begin, start + m.end()
        elif not tag.endswith(b'/>'):
            if depth == 0:
                begin = off
            depth += 1
    raise RuntimeError('Missing prelink entry ' + name)


def fast_symbols(k):
    names, addresses = {}, collections.defaultdict(list)
    for cmd, q, _ in commands(k):
        if cmd != 2:
            continue
        off, count, strings, length = struct.unpack_from('<IIII', k.data, q + 8)
        st = k.data[k.base + strings:k.base + strings + length]
        for i in range(count):
            idx, typ, sect, desc, va = struct.unpack_from('<IBBHQ', k.data, k.base + off + i * 16)
            if not va or typ & 0xe0:
                continue
            name = st[idx:st.find(b'\0', idx)].decode()
            names[name] = va
            addresses[va].append(name)
    return names, addresses


def owner_ranges(k):
    return sorted((s['addr'], s['addr'] + s['size'], n, s['name'])
                  for n, e in k.kexts.items() if e.get('_PrelinkExecutableLoadAddr')
                  for s in k.ksegments(n) if s['size'])


def owner(ranges, va):
    i = bisect.bisect_right(ranges, (va, 1 << 65, '', '')) - 1
    if i >= 0 and ranges[i][0] <= va < ranges[i][1]:
        return ranges[i][2:]
    return ('XNU', None)


def plan_patches(d, plan):
    """kernel_abi.load_plan equivalent; plan is an already-loaded dict."""
    import hashlib
    patches = []
    for row in plan['instruction_fields']:
        address = int(row['address'], 16)
        raw = d.read(address, 4)
        require(hashlib.sha256(raw).hexdigest() == row['expected_sha256'],
                'ABI source word changed at %#x.' % address)
        old = struct.unpack('<I', raw)[0]
        if row['kind'] == 'scalar32':
            new = row['value']
        else:
            require(row['kind'] == 'instruction-immediate', 'Unknown ABI patch kind.')
            mask, shift = int(row['mask'], 16), row['shift']
            require(mask in {0xffff << 5, 4095 << 10, 127 << 15, 511 << 12},
                    'Unreviewed instruction immediate mask.')
            require((row['value'] << shift) & ~mask == 0, 'ABI immediate exceeds its field.')
            new = (old & ~mask) | (row['value'] << shift)
        patches.append({'va': address, 'old': old, 'new': new, 'reason': row['reason']})
    pairs = []
    for row in plan.get('pair_veneers', []):
        pairs.append({**row, 'old': struct.unpack('<I', d.read(row['va'], 4))[0]})
    require(len({p['va'] for p in patches}) == len(patches), 'Duplicate ABI instruction patch.')
    return patches, pairs

"""Source donor transplant engine with bounded allocation and ABI hooks.

Vendored from SevenUP (BSD-3-Clause) src/iphone7_port/kernel_transplant.py.
Changes vs upstream: the previous-stage version-marker rewrite is optional
(marker_source=None skips it) so the engine can run on a kernel that was not
produced by the SevenUP BT1 stage. Everything else is unchanged.
"""



PARTS = ['__TEXT', '__TEXT_EXEC', '__DATA', '__DATA_CONST']


def xml_replace_entry(k, name, entry):
    a, z = entry_range(k.xml, name)
    removed = k.xml[a:z]
    xml = k.xml[:a] + xml_value(entry).encode() + k.xml[z:]
    ids = set(re.findall(rb'\bID="([^"]+)"', removed))
    root = ET.fromstring(k.xml)
    defs = {e.attrib['ID']: e for e in root.iter() if 'ID' in e.attrib}
    def val(e):
        if 'IDREF' in e.attrib: return val(defs[e.attrib['IDREF']])
        if e.tag == 'dict':
            es = list(e); return {es[i].text: val(es[i + 1]) for i in range(0, len(es), 2)}
        if e.tag in ('array', 'set'): return [val(x) for x in e]
        if e.tag == 'integer': return int(e.text or '0', 0)
        if e.tag == 'data': return base64.b64decode(e.text or '')
        if e.tag == 'true': return True
        if e.tag == 'false': return False
        return e.text or ''
    inlined = 0
    for ident in ids:
        pattern = rb'<\w+\b[^>]*\bIDREF="' + re.escape(ident) + rb'"[^>]*/>'
        replacement = xml_value(val(defs[ident.decode()])).encode()
        xml, count = re.subn(pattern, lambda m: replacement, xml)
        inlined += count
    require(not ids & set(re.findall(rb'\bIDREF="([^"]+)"', xml)), 'Dangling removed XML definition')
    return xml, inlined


def transplant_apply(source, donor, work, OLD, NAME, marker_source=None, marker_target=None,
          preserve_text_span=True, registration_only=False, full_donor_metadata=True,
          private_bindings=None, private_review=None, slot_overrides=None,
          extra_donor_slots=None, donor_word_patches=None, finalize=None, non_instruction_words=None,
          skip_donor_slots=None, expanded_segments=None, entry_transform=None):
    OUT = work
    k, d = KC(source), KC(donor)
    old = {s['name']: s for s in k.ksegments(OLD)}
    ds = {s['name']: s for s in d.ksegments(NAME)}
    require(not any(OLD in e.get('OSBundleLibraries', {}) for e in k.kexts.values()), 'Orion has dependent bundle')
    require(NAME not in k.kexts, 'Amp already present')
    dst = {}
    for n in PARTS:
        pad = (ds[n]['addr'] - old[n]['addr']) % 4096
        dst[n] = old[n]['addr'] + (pad if ds[n]['size'] + pad <= old[n]['size'] else 0)
        if preserve_text_span and n == '__TEXT':
            dst[n] = old[n]['addr']
        require(dst[n] + ds[n]['size'] <= old[n]['addr'] + old[n]['size'], 'Image does not fit ' + n)
    def inside_old(a): return any(old[n]['addr'] <= a < old[n]['addr'] + old[n]['size'] for n in PARTS)
    def local(a):
        for n in PARTS:
            s = ds[n]
            if s['addr'] <= a < s['addr'] + s['size']: return dst[n] + a - s['addr']
        return None
    def page_owner(a):
        ns = [n for n in PARTS if ds[n]['addr'] & ~4095 <= a < (ds[n]['addr'] + ds[n]['size'] + 4095) & ~4095]
        require(len(ns) == 1, 'Ambiguous ADRP page ' + hex(a))
        return ns[0]
    out = bytearray(k.data)
    def write(a, blob):
        require(any(old[n]['addr'] <= a and a + len(blob) <= old[n]['addr'] + old[n]['size'] for n in PARTS),
                'Write outside reclaimed Orion allocation ' + hex(a))
        off = k.offset(a); out[off:off + len(blob)] = blob
    for n in PARTS:
        write(old[n]['addr'], bytes(old[n]['size']))
        write(dst[n], d.read(ds[n]['addr'], ds[n]['size']))
    db, dr = relocations(d); kb, kr = relocations(k)
    dn, da = fast_symbols(d); kn, ka = fast_symbols(k)
    ranges = owner_ranges(d)
    uuids = {}; ptrs = []; newrel = []
    for off in kr:
        a = kb + off
        if inside_old(a): continue
        v = struct.unpack('<Q', k.read(a, 8))[0]
        require(not inside_old(v), 'External pointer into Orion ' + hex(a))
        newrel.append(off)
    if extra_donor_slots:
        require(not set(extra_donor_slots) & set(dr), 'Extra donor relocation already exists')
        dr = dr + list(extra_donor_slots)
    for off in dr:
        a = db + off; na = local(a)
        if na is None or (skip_donor_slots and a in skip_donor_slots): continue
        v = struct.unpack('<Q', d.read(a, 8))[0]; nv = local(v); kind = 'internal'
        if slot_overrides is not None and a in slot_overrides:
            override = slot_overrides[a]
            nv = local(override['target']) if override['kind'] == 'donor-local' else override['target']
            require(nv is not None, 'Unmapped ABI override')
            write(na, struct.pack('<Q', nv)); newrel.append(na - kb)
            ptrs.append(dict(old_slot=hex(a), new_slot=hex(na), old_target=hex(v), new_target=hex(nv), kind='ABI vtable override: ' + override['kind']))
            continue
        if nv is None:
            vals = {kn[n] for n in da.get(v, []) if n in kn}
            if vals:
                require(len(vals) == 1, 'Conflicting XNU export aliases')
                nv = next(iter(vals)); kind = 'XNU export'
            else:
                dep, segname = owner(ranges, v)
                require(dep in d.kexts and dep in k.kexts, 'Unknown native dependency ' + hex(v))
                if private_bindings is not None and v in private_bindings:
                    nv = private_bindings[v]; kind = 'reviewed cross-version dependency'
                    write(na, struct.pack('<Q', nv)); newrel.append(na - kb)
                    ptrs.append(dict(old_slot=hex(a), new_slot=hex(na), old_target=hex(v), new_target=hex(nv), kind=kind))
                    continue
                du = image_uuid(d, d.kexts[dep]['_PrelinkExecutableLoadAddr'])
                ku = image_uuid(k, k.kexts[dep]['_PrelinkExecutableLoadAddr'])
                require(du == ku, 'Native dependency UUID differs ' + dep)
                shape = lambda ss: [(s['name'], s['size'], s['vmsize'],
                    [(t['name'], t['addr'] - s['addr'], t['size']) for t in s['sections']]) for s in ss]
                require(shape(d.ksegments(dep)) == shape(k.ksegments(dep)),
                        'Native dependency section layout differs ' + dep)
                a_seg = next(s for s in d.ksegments(dep) if s['name'] == segname)
                b_seg = next(s for s in k.ksegments(dep) if s['name'] == segname)
                require(v - a_seg['addr'] < b_seg['size'], 'Native dependency segment differs')
                nv = b_seg['addr'] + v - a_seg['addr']; kind = 'identical-UUID dependency'
                uuids[dep] = du.hex()
        write(na, struct.pack('<Q', nv)); newrel.append(na - kb)
        ptrs.append(dict(old_slot=hex(a), new_slot=hex(na), old_target=hex(v), new_target=hex(nv), kind=kind))
    dk = d.kexts[NAME]['_PrelinkKmodInfo']
    require(dk + 156 - db not in dr, 'kmod.address would receive a duplicate slide')
    write(local(dk) + 156, struct.pack('<Q', dst['__TEXT']))
    code = ds['__TEXT_EXEC']; raw = d.read(code['addr'], code['size'])
    tail = dst['__TEXT_EXEC'] + ((code['size'] + 3) & ~3)
    adrp = []
    for i in range(0, len(raw), 4):
        pc = code['addr'] + i; npc = local(pc); w = struct.unpack_from('<I', raw, i)[0]
        if w & 0x9f000000 == 0x90000000:
            page = adrp_page(w, pc); n = page_owner(page); reg = w & 31
            require(reg not in (30, 31), 'Unexpected ADRP destination')
            value = page + dst[n] - ds[n]['addr']
            if value % 4096 == 0:
                write(npc, struct.pack('<I', encode_adrp(w, npc, value)))
                adrp.append(dict(pc=hex(npc), value=hex(value), kind='page'))
            else:
                require(tail + 12 <= old['__TEXT_EXEC']['addr'] + old['__TEXT_EXEC']['size'], 'Veneer overflow')
                add = 0x91000000 | ((value & 4095) << 10) | (reg << 5) | reg
                write(tail, struct.pack('<II', encode_adrp(w, tail, value & ~4095), add) + branch(tail + 8, npc + 4))
                write(npc, branch(npc, tail))
                adrp.append(dict(pc=hex(npc), value=hex(value), veneer=hex(tail), kind='page-value-veneer'))
                tail += 12
        elif w & 0x7c000000 == 0x14000000:
            target = pc + signed(w & 0x3ffffff, 26) * 4
            require(code['addr'] <= target < code['addr'] + code['size'], 'External direct donor branch')
        elif w & 0x9f000000 == 0x10000000:
            delta = signed(((w >> 29) & 3) | (((w >> 5) & 0x7ffff) << 2), 21)
            require(local(pc + delta) == npc + delta, 'External donor ADR')
        elif w & 0x3b000000 == 0x18000000:
            delta = signed((w >> 5) & 0x7ffff, 19) * 4
            require(local(pc + delta) == npc + delta, 'External donor literal')
    adaptation = []
    for p in donor_word_patches or []:
        a = p['va']; require(d.read(a, 4) == struct.pack('<I', p['old']), 'Donor ABI instruction differs')
        require(bytes(out[k.offset(local(a)):k.offset(local(a)) + 4]) == d.read(a, 4), 'ABI patch overlaps relocated code/pointer')
        write(local(a), struct.pack('<I', p['new']))
        adaptation.append({**p, 'va': hex(a), 'destination': hex(local(a))})
    if finalize is not None:
        finished = finalize(k, d, out, local, dst, tail, write)
        require(len(finished) in (2, 3), 'Unexpected finalizer result')
        tail, extra = finished[:2]
        if len(finished) == 3:
            for va in finished[2]:
                require(inside_old(va) and va % 8 == 0, 'Invalid additional relocation')
                newrel.append(va - kb)
        adaptation.extend(extra)
    direct_audit = 0
    for n, e in k.kexts.items():
        if n == OLD or not e.get('_PrelinkExecutableLoadAddr'): continue
        for s in k.ksegments(n):
            if s['name'] != '__TEXT_EXEC': continue
            buf = k.read(s['addr'], s['size'])
            for i in range(0, len(buf) - 3, 4):
                w = struct.unpack_from('<I', buf, i)[0]
                if w & 0x7c000000 == 0x14000000:
                    target = s['addr'] + i + signed(w & 0x3ffffff, 26) * 4
                    if inside_old(target) and non_instruction_words and s['addr'] + i in non_instruction_words:
                        require(k.read(s['addr'] + i, 8).hex() == non_instruction_words[s['addr'] + i]['bytes'], 'Reviewed literal changed')
                        continue
                    require(not inside_old(target), 'External code branch into Orion')
                    direct_audit += 1
    head = dst['__TEXT']; header_len = 32 + struct.unpack('<I', d.read(ds['__TEXT']['addr'] + 20, 4))[0]
    header = bytearray(out[k.offset(head):k.offset(head) + header_len])
    for cmd, q, size in commands(d, ds['__TEXT']['addr']):
        if cmd != 25: continue
        q -= d.offset(ds['__TEXT']['addr']); n = header[q + 8:q + 24].split(b'\0')[0].decode()
        if n == '__LINKEDIT':
            require(ds[n]['size'] == 0, 'Nonempty donor LINKEDIT')
            va = dst['__DATA_CONST'] + ds['__DATA_CONST']['size']
        else: va = dst[n]
        vmsize = tail - va if n == '__TEXT_EXEC' else ds[n]['vmsize']
        filesize = tail - va if n == '__TEXT_EXEC' else ds[n]['size']
        if expanded_segments and n in expanded_segments:
            require(n not in ('__TEXT', '__TEXT_EXEC', '__LINKEDIT'), 'Unsupported segment expansion')
            require(ds[n]['size'] <= expanded_segments[n] <= old[n]['addr'] + old[n]['size'] - va, 'Expanded segment exceeds allocation')
            vmsize = filesize = expanded_segments[n]
        struct.pack_into('<QQ', header, q + 24, va, vmsize)
        struct.pack_into('<QQ', header, q + 40, va - head, filesize)
        if preserve_text_span and n == '__TEXT':
            struct.pack_into('<Q', header, q + 32, old[n]['vmsize'])
            struct.pack_into('<Q', header, q + 48, old[n]['size'])
        if preserve_text_span and n == '__LINKEDIT':
            original_q = next(z for c, z, sz in commands(k, old['__TEXT']['addr'])
                if c == 25 and k.data[z + 8:z + 24].split(b'\0')[0] == b'__LINKEDIT')
            header[q:q + size] = k.data[original_q:original_q + size]
        for j in range(struct.unpack_from('<I', header, q + 64)[0]):
            z = q + 72 + j * 80; oldva = struct.unpack_from('<Q', header, z + 32)[0]; va = local(oldva)
            require(va is not None, 'Unmapped embedded section')
            struct.pack_into('<Q', header, z + 32, va)
            if struct.unpack_from('<I', header, z + 48)[0]: struct.pack_into('<I', header, z + 48, va - head)
    write(head, header)
    entry = {n: copy.deepcopy(d.kexts[NAME][n]) for n in ['CFBundleIdentifier', 'CFBundleName', 'CFBundleExecutable',
        'CFBundleVersion', 'CFBundlePackageType', 'OSBundleLibraries', 'IOKitPersonalities', '_PrelinkBundlePath', '_PrelinkExecutableSize']}
    if full_donor_metadata:
        entry = copy.deepcopy(d.kexts[NAME])
    entry.update(_PrelinkExecutableLoadAddr=head, _PrelinkExecutableSourceAddr=head,
                 _PrelinkKmodInfo=local(dk), OSBundleRequired='Root')
    if preserve_text_span:
        entry['_PrelinkExecutableSize'] = old['__TEXT']['size']
    if full_donor_metadata:
        if 'OSBundleRequired' not in d.kexts[NAME]: entry.pop('OSBundleRequired', None)
    if registration_only:
        entry.pop('IOKitPersonalities', None)
        entry.pop('OSBundleRequired', None)
    if entry_transform is not None:
        entry_transform(entry)
    xml, inlined = xml_replace_entry(k, OLD, entry)
    require(len(newrel) == len(set(newrel)), 'Duplicate relocation slots')
    packed = struct.pack('<I', len(newrel)) + struct.pack('<' + 'I' * len(newrel), *newrel)
    xml, count = re.subn(rb'(<key>_PrelinkLinkKASLROffsets</key><data>)[A-Za-z0-9+/=\s]*(</data>)',
        lambda m: m[1] + base64.b64encode(packed) + m[2], xml)
    require(count == 1, 'Missing KASLR offset array')
    original = plist(k.xml); parsed = plist(xml)
    expected = copy.deepcopy(original)
    expected['_PrelinkInfoDictionary'] = [entry if e['CFBundleIdentifier'] == OLD else e for e in expected['_PrelinkInfoDictionary']]
    expected['_PrelinkLinkKASLROffsets'] = packed
    require(parsed == expected, 'Unrelated metadata changed')
    info = next(s for s in k.segments if s['name'] == '__PRELINK_INFO')
    require(len(xml) <= info['size'], 'Prelink XML exceeds existing allocation')
    at = k.offset(info['addr']); out[at:at + info['size']] = xml.ljust(info['size'], b'\0')
    allowed = [(k.offset(old[n]['addr']), k.offset(old[n]['addr']) + old[n]['size']) for n in PARTS]
    allowed += [(at, at + info['size'])]
    if marker_source is not None:
        marker = marker_source
        newmarker = marker_target or (b'\x1b[35mAU3:%.128s\x1b[0m\n\0' if preserve_text_span
                   else b'\x1b[35mAU2:%.128s\x1b[0m\n\0')
        require(k.data.count(marker) == 1, 'AG1 version marker differs')
        ma = k.data.index(marker); out[ma:ma + len(marker)] = newmarker
        allowed.append((ma, ma + len(marker)))
    restored = bytearray(out)
    for a, z in allowed: restored[a:z] = k.data[a:z]
    require(restored == k.data and len(out) == len(k.data), 'Changed bytes outside explicit allocations')
    (OUT / 'kernelcache.raw').write_bytes(out)
    v = KC(OUT / 'kernelcache.raw')
    require(v.segments == k.segments and len(v.kexts) == len(k.kexts), 'Outer Mach-O layout changed')
    for n in k.kexts:
        if n == OLD: continue
        require(v.kexts[n] == k.kexts[n], 'Unrelated metadata differs')
        for s in k.ksegments(n):
            if s['size'] and s['addr']:
                require(v.read(s['addr'], s['size']) == k.read(s['addr'], s['size']), 'Unrelated driver bytes differ ' + n)
    return bytes(out), {
        'replaced_bundle': OLD, 'donor_bundle': NAME, 'identical_UUID_dependencies': uuids,
        'XML_bytes': len(xml), 'XML_capacity': info['size'], 'shared_XML_references_inlined': inlined,
        'rebound_pointer_count': len(ptrs), 'relocation_count': len(newrel),
        'destination': {n: {'addr': hex(dst[n]), 'size': ds[n]['size'], 'capacity': old[n]['addr'] + old[n]['size'] - dst[n]} for n in PARTS},
        'veneer_end': hex(tail), 'allowed_raw_ranges': allowed, 'private_dependency_review': private_review,
        'ABI_adaptation': adaptation, 'other_driver_direct_branches_checked': direct_audit,
    }

"""Apply the additional switch-only CS42L71 ABI accesses (MC2 semantics).

Vendored from SevenUP (BSD-3-Clause) src/iphone7_port/kernel_mc2.py.
Changes vs upstream: patch count, marker needle/replacement and extra string
renames come from the switch profile instead of hard-coded values; a rename
with required=false is skipped when its needle is absent.
"""




class Edits:
    def __init__(self, path):
        self.k = KC(path)
        self.output = bytearray(self.k.data)
        self.records = []

    def put(self, address, old, new, reason, owner=None):
        require(len(old) == len(new), 'An in-place base patch must preserve size.')
        offset = self.k.offset(address)
        require(bytes(self.output[offset:offset + len(old)]) == old, 'Unexpected original bytes at %#x.' % address)
        if owner:
            require(any(s['name'] == '__TEXT_EXEC' and s['addr'] <= address and
                        address + len(old) <= s['addr'] + s['size'] for s in self.k.ksegments(owner)),
                    'Patch is outside the executable allocation for %s.' % owner)
        self.output[offset:offset + len(new)] = new
        self.records.append({'address': hex(address), 'offset': offset, 'size': len(old), 'reason': reason})

    def string(self, old, new, *, owner=None):
        formats = re.compile(rb'%(?:[-+ #0]*)(?:\d+)?(?:\.\d+)?(?:ll|l|z|h)?[diuoxXpsc]')
        require(formats.findall(old) == formats.findall(new), 'A log format changes printf arguments.')
        require(len(new) <= len(old), 'A replacement string exceeds its allocation.')
        if owner:
            sections = [sec for s in self.k.ksegments(owner) for sec in s['sections'] if sec['name'] == '__cstring']
            require(len(sections) == 1, 'Ambiguous driver string section.')
            start = self.k.offset(sections[0]['addr'])
            data = self.k.read(sections[0]['addr'], sections[0]['size'])
        else:
            start, data = 0, self.k.data
        require(data.count(old + b'\0') == 1, 'Log format is not unique: %r' % old)
        offset = start + data.index(old + b'\0')
        segment = next(s for s in self.k.segments if self.k.base + s['offset'] <= offset < self.k.base + s['offset'] + s['size'])
        address = segment['addr'] + offset - self.k.base - segment['offset']
        self.put(address, old + b'\0', new + bytes(len(old) + 1 - len(new)), 'Preserve printf arguments while labeling the console')


def mc2_apply(source, donor, plan, work):
    """source: path to post-MC1 kernel; donor: path to donor kernel;
    plan: loaded switch-abi profile dict; work: output directory Path."""
    edits, d = Edits(source), KC(donor)
    params = plan['params']
    name = params['name']
    old = {s['name']: s for s in d.ksegments(name)}
    new = {s['name']: s for s in edits.k.ksegments(name)}
    def local(address):
        return next(new[n]['addr'] + address - s['addr'] for n, s in old.items()
                    if s['addr'] <= address < s['addr'] + s['size'])
    patches, pairs = plan_patches(d, plan)
    require(len(patches) == params['patch_count'] and not pairs, 'MC2 additional ABI plan changed.')
    for row in patches:
        edits.put(local(row['va']), struct.pack('<I', row['old']), struct.pack('<I', row['new']), row['reason'])
    for spec in params['markers']:
        needle = spec['needle'].encode('latin1')
        replacement = spec['replacement'].encode('latin1')
        count = edits.k.data.count(needle)
        if count == 0 and not spec.get('required', True):
            continue
        require(count == spec['count'], 'MC1 class markers changed.')
        start = 0
        for _ in range(count):
            offset = edits.k.data.index(needle, start)
            start = offset + len(needle)
            segment = next(s for s in edits.k.segments if edits.k.base + s['offset'] <= offset < edits.k.base + s['offset'] + s['size'])
            address = segment['addr'] + offset - edits.k.base - segment['offset']
            edits.put(address, needle, replacement, spec.get('reason', 'Retain fixed-size stage markers'))
    for spec in params.get('string_renames', []):
        old = spec['old'].encode('latin1')
        new = spec['new'].encode('latin1')
        if edits.k.data.count(old + b'\0') == 0 and not spec.get('required', True):
            continue
        edits.string(old, new)
    out = bytes(edits.output)
    (work / 'kernelcache.raw').write_bytes(out)
    return out, {'edits': edits.records, 'additional_instruction_count': len(patches)}

"""CS42L71 source transplant: rebuild native-parent vtables and typed metadata.

Vendored from SevenUP (BSD-3-Clause) src/iphone7_port/kernel_microphone.py.
Changes vs upstream: every kernel-specific address, layout offset, mic_slot index
and marker string comes from the translated profile (the `params` section)
instead of hard-coded iPhone 7 / iPad 7 values. Class-name constants
(MIC_MAIN/MIC_MIKEY/MIC_AUDIO) are unchanged. Trace marker text is profile-driven.
"""


MIC_MAIN = 'AppleCS42L71Audio'
MIC_MIKEY = 'AppleCS42L71Mikey'
MIC_AUDIO = 'AppleCSCodecMikeyBusAudio'
MIC_NAME = 'com.apple.driver.AppleCS42L71Audio'
MIC_OLD = 'com.apple.driver.AppleANXDPTX'
MIC_PARTS = ('__TEXT', '__TEXT_EXEC', '__DATA', '__DATA_CONST')


def mic_slot(typ, i):
    if typ in (MIC_MAIN, 'AppleCSSPIv2Audio'):
        assert i not in (331, 332), ('Removed EmbeddedAudio virtual', typ, i)
        return i if i < 180 else i + 3 if i < 331 else i + 1
    if typ in (MIC_MIKEY, 'AppleCSHTDCodecMikey'): return i if i < 205 else i + 2
    return i


def mic_prepare(d, k, plan_data):
    params = plan_data['params']
    dc, nc = plan_data['classes15'], plan_data['classes16']
    dc[MIC_AUDIO].update(vtable=params['audio_vtable'], virtual_slots=params['audio_virtual_slots'])
    own = {n: c for n, c in dc.items() if c['bundle'] == MIC_NAME}
    bymeta = {int(c['metaclass'], 16): n for n, c in dc.items()}
    ds = {s['name']: s for s in d.ksegments(MIC_NAME)}; os = {s['name']: s for s in k.ksegments(MIC_OLD)}
    dest = {}
    for n in MIC_PARTS:
        pad = (ds[n]['addr'] - os[n]['addr']) % 4096
        dest[n] = os[n]['addr'] + (pad if ds[n]['size'] + pad <= os[n]['size'] else 0)
    dest['__TEXT'] = os['__TEXT']['addr']
    assert all(dest[n] + ds[n]['size'] <= os[n]['addr'] + os[n]['size'] for n in MIC_PARTS)
    def local(a):
        for n in MIC_PARTS:
            if ds[n]['addr'] <= a < ds[n]['addr'] + ds[n]['size']: return dest[n] + a - ds[n]['addr']
        raise ValueError(hex(a))
    def vt(c): return int(c['vtable'], 16) + 16
    def vals(c, k): return list(struct.unpack('<' + 'Q' * c['virtual_slots'], k.read(vt(c), c['virtual_slots'] * 8)))
    layout = params['layout']
    const_extra = dest['__DATA_CONST'] + layout['data_const_extra']
    moved_header = const_extra + layout['moved_header_delta']
    moved_vt = const_extra + layout['moved_vtable_delta']
    parser = dest['__TEXT_EXEC'] + layout['parser_off']
    trace = dest['__TEXT_EXEC'] + layout['trace_off']
    marker = dest['__TEXT_EXEC'] + layout['marker_off']
    assert marker + 256 <= os['__TEXT_EXEC']['addr'] + os['__TEXT_EXEC']['size']
    raw = plan_data
    private = {int(a, 16): int(b, 16) for a, b in raw['bindings'].items()}
    for a, b in params['extra_private_bindings'].items():
        private[int(a, 16)] = int(b, 16)
    for a, b in params.get('extra_private_verify', {}).items():
        assert d.read(int(a, 16), b) == k.read(private[int(a, 16)], b)
    decoder = params['legacy_decoder']
    private[int(decoder['va'], 16)] = parser
    nn, _ = fast_symbols(k); on, oa = fast_symbols(d)
    # Rebuild all local class virtual tables from the native16 root parents.
    tables = {}; table_reports = {}
    pending = dict(own)
    while pending:
        progressed = False
        for name, c in list(pending.items()):
            parent = bymeta[int(c['super_metaclass'], 16)]
            if parent in pending: continue
            old_table = vals(c, d); old_parent = vals(dc[parent], d)
            if parent in tables: table = list(tables[parent])
            else: table = [{'kind': 'native', 'target': x} for x in vals(nc[parent], k)]
            overrides = []
            for i, x in enumerate(old_table):
                if i < len(old_parent) and x == old_parent[i]: continue
                j = mic_slot(name, i)
                if ds['__TEXT_EXEC']['addr'] <= x < ds['__TEXT_EXEC']['addr'] + ds['__TEXT_EXEC']['size']:
                    value = {'kind': 'donor-local', 'target': x}
                else:
                    targets = {nn[n] for n in oa.get(x, []) if n in nn}
                    assert len(targets) == 1, (name, i, hex(x))
                    value = {'kind': 'native', 'target': targets.pop()}
                if j < len(table): table[j] = value
                else: assert j == len(table); table.append(value)
                overrides.append({'old_slot': i, 'new_slot': j, 'function': hex(x)})
            assert len(table) == c['virtual_slots'] + (1 if name == MIC_MAIN else 2 if name == MIC_MIKEY else 0)
            tables[name] = table
            table_reports[name] = {'parent': parent, 'old_slots': len(old_table), 'new_slots': len(table), 'overrides': overrides}
            del pending[name]; progressed = True
        assert progressed
    # Traced start and handleStart call the real adapted methods.
    ts = params['trace']
    tables[MIC_MAIN][ts['start_slot']] = {'kind': 'native', 'target': trace}
    tables[MIC_MAIN][mic_slot(MIC_MAIN, ts['handle_slot_index'])] = {'kind': 'native', 'target': trace + ts['wrapper_gap']}
    special = {}; extra = []; skip = set()
    base, fix = relocations(d); fixset = {base + x for x in fix}
    for n, table in tables.items():
        a = vt(dc[n])
        if n == MIC_MIKEY:
            skip.update(range(a, a + dc[n]['virtual_slots'] * 8, 8))
            continue
        for i, v in enumerate(table):
            p = a + i * 8; special[p] = v
            if p not in fixset: assert d.read(p, 8) == bytes(8); extra.append(p - base)
    # Redirect every absolute pointer to the expanded Mikey table. Constructor
    # address materializations are handled separately, at the exact ADD PC.
    old_header = int(dc[MIC_MIKEY]['vtable'], 16); old_vt = old_header + 16
    redirects = []
    for off in fix:
        p = base + off
        if p in skip or not any(s['addr'] <= p < s['addr'] + s['size'] for s in ds.values()): continue
        x = struct.unpack('<Q', d.read(p, 8))[0]
        if old_header - 16 <= x < old_vt:
            assert p not in special
            special[p] = {'kind': 'native', 'target': moved_header + x - old_header}; redirects.append(hex(p))
    rows = {s['addr'] + i: {'raw': struct.unpack('<I', d.read(s['addr'] + i, 4))[0], 'op': 'adrp' if struct.unpack('<I', d.read(s['addr'] + i, 4))[0] & 0x9f000000 == 0x90000000 else ''} for s in d.ksegments(MIC_NAME) if s['name'] == '__TEXT_EXEC' for i in range(0, s['size'] - 3, 4)}
    materializations = []
    for p, r in rows.items():
        if r['op'] != 'adrp' or p + 4 not in rows: continue
        w = r['raw']; v = rows[p + 4]['raw']; reg = w & 31
        if v & 0xffc003ff != 0x91000000 | (reg << 5) | reg: continue
        target = adrp_page(w, p) + ((v >> 10) & 4095)
        if old_header - 16 <= target < old_vt + 8:
            materializations.append({'pc': p + 4, 'reg': reg, 'old_target': target,
                                     'new_target': moved_header + target - old_header})
    assert [hex(p['pc']) for p in materializations] == params['materialization_pcs'], materializations
    # Typed allocation signatures describe pointer/nonpointer words. Rebuild
    # native parent prefixes as well as updating the byte counts; do not leave
    # a392-word signature attached to the new393-word main object.
    def signatures(obj, bundles):
        found = {}
        for bundle in bundles:
            for s in obj.ksegments(bundle):
                for t in s['sections']:
                    if t['name'] != '__kalloc_type': continue
                    for a in range(t['addr'], t['addr'] + t['size'], 64):
                        namep = struct.unpack('<Q', obj.read(a + 16, 8))[0]
                        name = obj.read(namep, 128).split(b'\0')[0].decode().removeprefix('site.')
                        sigp = struct.unpack('<Q', obj.read(a + 32, 8))[0]
                        sig = obj.read(sigp, 2048).split(b'\0')[0]
                        found[name] = (a, sig)
        return found
    parents = {bymeta[int(c['super_metaclass'], 16)] for c in own.values()} - own.keys()
    bundles = {dc[n]['bundle'] for n in parents}
    old_sig = signatures(d, bundles | {MIC_NAME}); native_sig = signatures(k, bundles)
    rebuilt = {}; pending = dict(own); signature_pool = bytearray(); signature_records = []
    while pending:
        progressed = False
        for n, c in list(pending.items()):
            parent = bymeta[int(c['super_metaclass'], 16)]
            if parent in pending: continue
            a, sig = old_sig[n]; parent_old = old_sig[parent][1]
            assert sig.startswith(parent_old), (n, parent)
            parent_new = rebuilt[parent]if parent in rebuilt else native_sig[parent][1]
            sig = parent_new + sig[len(parent_old):]
            expected = (c['instance_size'] + (8 if n in (MIC_MAIN, MIC_AUDIO)else 0) + 7) // 8
            assert len(sig) == expected, (n, len(sig), expected)
            new_address = dest['__TEXT'] + layout['sig_pool_off'] + len(signature_pool)
            special[a + 32] = {'kind': 'native', 'target': new_address}
            signature_records.append({'class': n, 'descriptor': hex(local(a)), 'signature': hex(new_address), 'words': len(sig)})
            signature_pool.extend(sig + b'\0'); rebuilt[n] = sig; del pending[n]; progressed = True
        assert progressed
    assert layout['sig_pool_off'] + len(signature_pool) < os['__TEXT']['size']
    patches, pairs = plan_patches(d, plan_data)
    plan = plan_data
    assert not pairs
    init_text = params['markers']['init_text'].encode('latin1')
    def finalize(k, d, out, local, dst, tail, write):
        records = []; newfix = []
        def edit(a, b, why): write(a, b); records.append({'address': hex(a), 'size': len(b), 'reason': why})
        edit(dest['__TEXT'] + layout['sig_pool_off'], signature_pool, 'Typed allocation word signatures with native16 parent layouts')
        for p in materializations:
            assert tail + 12 < parser
            target = p['new_target']; reg = p['reg']; pc = local(p['pc'])
            code = struct.pack('<II', encode_adrp(0x90000000 | reg, tail, target & ~4095),
                                      0x91000000 | ((target & 4095) << 10) | (reg << 5) | reg) + branch(tail + 8, pc + 4)
            edit(tail, code, 'Materialize expanded Mikey vtable; preserve exact source register')
            edit(pc, branch(pc, tail), 'Redirect exact vtable ADD, retaining relocated ADRP before it'); tail += 12
        # New Mikey vtable has its own association pair and zero Itanium header.
        edit(local(old_vt), bytes(dc[MIC_MIKEY]['virtual_slots'] * 8), 'Erase unreferenced legacy Mikey table; no stale unrelocated donor pointers')
        prefix = struct.pack('<QQQQ', local(int(dc[MIC_MIKEY]['metaclass'], 16)), int(nc[params['mikey_parent_class']]['metaclass'], 16), 0, 0)
        values = [local(v['target']) if v['kind'] == 'donor-local'else v['target'] for v in tables[MIC_MIKEY]]
        blob = prefix + struct.pack('<' + 'Q' * len(values), *values)
        edit(const_extra, blob, 'Native285-mic_slot Mikey table outside unchanged original tables')
        newfix.extend([const_extra, const_extra + 8]); newfix.extend(range(moved_vt, moved_vt + len(values) * 8, 8))
        assert const_extra + len(blob) <= os['__DATA_CONST']['addr'] + os['__DATA_CONST']['size']
        # Preserve the original legacy decoder, including cases removed in16.
        start = int(decoder['va'], 16); size = decoder['size']; raw = bytearray(d.read(start, size)); words = list(struct.unpack('<%dI' % (size // 4), raw))
        strings = {}; pool = bytearray(); targets = set()
        for i, w in enumerate(words):
            pc = start + 4 * i
            if w & 0x7c000000 == 0x14000000: targets.add(pc + 4 * signed(w & 0x3ffffff, 26))
            elif w & 0xff000010 == 0x54000000 or w & 0x7e000000 == 0x34000000: targets.add(pc + 4 * signed((w >> 5) & 0x7ffff, 19))
        for i, w in enumerate(words):
            pc = start + 4 * i; npc = parser + 4 * i
            if w & 0x9f000000 == 0x90000000:
                v = words[i + 1]; reg = w & 31; assert v & 0xffc003ff == 0x91000000 | (reg << 5) | reg
                target = adrp_page(w, pc) + ((v >> 10) & 4095); assert pc + 4 not in targets
                if target not in strings:
                    s = d.read(target, 256).split(b'\0')[0] + b'\0'; assert len(s) < 256
                    strings[target] = parser + size + len(pool); pool.extend(s)
                struct.pack_into('<II', raw, 4 * i, adr(npc, strings[target], reg), 0xd503201f)
            elif w & 0x7c000000 == 0x14000000:
                target = pc + 4 * signed(w & 0x3ffffff, 26)
                if start <= target < start + size: continue
                a, b, _ = struct.unpack('<III', d.read(target, 12)); assert a & 0x9f000000 == 0x90000000 and b & 0xffc00000 == 0xf9400000
                real = struct.unpack('<Q', d.read(adrp_page(a, target) + ((b >> 10) & 4095) * 8, 8))[0]
                vals = {nn[n] for n in oa.get(real, []) if n in nn}
                if vals: assert len(vals) == 1; value = vals.pop()
                else:
                    assert real == int(params['decoder_fallback']['donor'], 16); value = int(params['decoder_fallback']['target'], 16)
                struct.pack_into('<I', raw, 4 * i, struct.unpack('<I', bl(npc, value))[0])
        assert parser + len(raw) + len(pool) < trace
        edit(parser, bytes(raw) + pool, 'Retain all original CS codec configuration decoder cases')
        def trace_wrapper(a, real, name):
            # Preserve all eight integer arguments. Stack remains16-byte aligned.
            code = struct.pack('<III', 0xa9ba7bfd, 0x910003fd, 0xa90107e0)
            code += struct.pack('<III', 0xa9020fe2, 0xa90317e4, 0xa9041fe6)
            begin = a + 0x100; okay = a + 0x140; fail = a + 0x180
            code += struct.pack('<I', adr(a + len(code), begin, 0)); code += bl(a + len(code), nn['_IOLog'])
            code += struct.pack('<IIII', 0xa94107e0, 0xa9420fe2, 0xa94317e4, 0xa9441fe6)
            code += bl(a + len(code), local(real)); code += struct.pack('<I', 0xf9002be0)
            code += struct.pack('<I', 0x34000060) # cbz w0, +12
            code += struct.pack('<I', adr(a + len(code), okay, 0)); code += branch(a + len(code), a + len(code) + 8)
            code += struct.pack('<I', adr(a + len(code), fail, 0)); code += bl(a + len(code), nn['_IOLog'])
            code += struct.pack('<III', 0xf9402be0, 0xa8c67bfd, 0xd65f03c0)
            assert len(code) < 0x100
            edit(a, code, 'Call real ' + name + ' with all x0-x7 arguments preserved; trace boolean return')
            for addr, label in [(begin, ' begin'), (okay, ' success'), (fail, ' failure')]:
                edit(addr, b'\x1b[36m' + ts['label'].encode() + b' ' + name.encode() + label.encode() + b'\x1b[0m\n\0', 'Cyan hardware path checkpoint')
        trace_wrapper(trace, int(ts['start_fn'], 16), 'start')
        trace_wrapper(trace + ts['wrapper_gap'], int(ts['handle_fn'], 16), 'handleStart')
        init = next(t for s in ds.values() for t in s['sections'] if t['name'] == '__mod_init_func')
        original = struct.unpack('<Q', d.read(init['addr'] + 8, 8))[0]
        text = init_text
        code = struct.pack('<II', 0xa9bf7bfd, 0x910003fd) + bl(marker + 8, local(original))
        code += struct.pack('<I', adr(marker + 12, marker + 28, 0)) + bl(marker + 16, nn['_IOLog']) + struct.pack('<II', 0xa8c17bfd, 0xd65f03c0) + text
        edit(marker, code, 'Yellow registration marker after all8 real metaclass initializers')
        edit(local(init['addr'] + 8), struct.pack('<Q', marker), 'Retain initializer through marker wrapper')
        records.append({'marker': hex(marker), 'trace': hex(trace), 'parser': hex(parser), 'moved_mikey_table': hex(moved_vt),
                        'table_counts': {n: len(v) for n, v in tables.items()}})
        return marker + len(code), records, newfix
    report = {'status': 'DRAFT; FINAL IMAGE AND NATIVE EXECUTION AUDIT REQUIRED', 'classes': table_reports,
            'field_instruction_and_size_patches': len(patches), 'reclaimed_bundle': MIC_OLD,
            'Mikey_expanded_table': hex(moved_vt), 'Mikey_materializations': materializations,
            'Mikey_absolute_redirects': redirects, 'legacy_decoder_cloned': True,
            'typed_allocation_signatures': signature_records,
            'unresolved_foreign_dispatches': plan['unresolved_dispatches']}
    return private, report, special, patches, extra, skip, finalize

"""CS35L19 amp transplant: rebuild native-parent vtable and typed metadata.

Companion to microphone.py for the second SE audio driver. Single own class
(AppleCS35L19Amp), no Mikey table, no legacy decoder. The derived amp_slot map
differs from SevenUP's amp_slot() for AppleEmbeddedAudio descendants: iOS 16 did
not remove slots 331/332 but moved them to 180/181 (proven by signature
identity).
"""


AMP_MAIN = 'AppleCS35L19Amp'
AMP_NAME = 'com.apple.driver.AppleCS35L19Amp'
AMP_OLD = 'com.apple.driver.AppleCS42L81Audio'
AMP_PARTS = ('__TEXT', '__TEXT_EXEC', '__DATA', '__DATA_CONST')


def amp_slot(typ, i):
    if i == 331: return 180
    if i == 332: return 181
    return i if i < 180 else i + 3 if i < 331 else i + 1


def amp_prepare(d, k, plan_data):
    params = plan_data['params']
    dc, nc = plan_data['classes15'], plan_data['classes16']
    own = {n: c for n, c in dc.items() if c['bundle'] == AMP_NAME}
    require(list(own) == [AMP_MAIN], 'unexpected own class set: %s' % list(own))
    bymeta = {int(c['metaclass'], 16): n for n, c in dc.items()}
    ds = {s['name']: s for s in d.ksegments(AMP_NAME)}; os = {s['name']: s for s in k.ksegments(AMP_OLD)}
    dest = {}
    for n in AMP_PARTS:
        pad = (ds[n]['addr'] - os[n]['addr']) % 4096
        dest[n] = os[n]['addr'] + (pad if ds[n]['size'] + pad <= os[n]['size'] else 0)
    dest['__TEXT'] = os['__TEXT']['addr']
    assert all(dest[n] + ds[n]['size'] <= os[n]['addr'] + os[n]['size'] for n in AMP_PARTS)
    def local(a):
        for n in AMP_PARTS:
            if ds[n]['addr'] <= a < ds[n]['addr'] + ds[n]['size']: return dest[n] + a - ds[n]['addr']
        raise ValueError(hex(a))
    def vt(c): return int(c['vtable'], 16) + 16
    def vals(c, k): return list(struct.unpack('<' + 'Q' * c['virtual_slots'], k.read(vt(c), c['virtual_slots'] * 8)))
    # Trace + marker live in the reclaimed __TEXT_EXEC slack after the donor
    # code (dest is 4096-aligned within it); marker is last, trace before it.
    trace = dest['__TEXT_EXEC'] + ds['__TEXT_EXEC']['size'] + (-ds['__TEXT_EXEC']['size'] % 4096) + 0x800
    marker = trace + 0x200
    assert marker + 256 <= os['__TEXT_EXEC']['addr'] + os['__TEXT_EXEC']['size']
    raw = plan_data
    private = {int(a, 16): int(b, 16) for a, b in raw['bindings'].items()}
    for a, b in params['extra_private_bindings'].items():
        private[int(a, 16)] = int(b, 16)
    nn, _ = fast_symbols(k); on, oa = fast_symbols(d)
    # Rebuild the single own-class vtable from the native16 parent.
    tables = {}; table_reports = {}
    pending = dict(own)
    while pending:
        progressed = False
        for name, c in list(pending.items()):
            parent = bymeta[int(c['super_metaclass'], 16)]
            if parent in pending: continue
            old_table = vals(c, d); old_parent = vals(dc[parent], d)
            if parent in tables: table = list(tables[parent])
            else: table = [{'kind': 'native', 'target': x} for x in vals(nc[parent], k)]
            overrides = []
            for i, x in enumerate(old_table):
                if i < len(old_parent) and x == old_parent[i]: continue
                j = amp_slot(name, i)
                if ds['__TEXT_EXEC']['addr'] <= x < ds['__TEXT_EXEC']['addr'] + ds['__TEXT_EXEC']['size']:
                    value = {'kind': 'donor-local', 'target': x}
                else:
                    if x in private:
                        value = {'kind': 'native', 'target': private[x]}
                    else:
                        targets = {nn[n] for n in oa.get(x, []) if n in nn}
                        assert len(targets) == 1, (name, i, hex(x))
                        value = {'kind': 'native', 'target': targets.pop()}
                if j < len(table): table[j] = value
                else: assert j == len(table); table.append(value)
                overrides.append({'old_slot': i, 'new_slot': j, 'function': hex(x)})
            tables[name] = table
            table_reports[name] = {'parent': parent, 'old_slots': len(old_table), 'new_slots': len(table), 'overrides': overrides}
            del pending[name]; progressed = True
        assert progressed
    ts = params['trace']
    tables[AMP_MAIN][amp_slot(AMP_MAIN, ts['start_slot'])] = {'kind': 'native', 'target': trace}
    special = {}; extra = []; skip = set()
    base, fix = relocations(d); fixset = {base + x for x in fix}
    for n, table in tables.items():
        a = vt(dc[n])
        for i, v in enumerate(table):
            p = a + i * 8; special[p] = v
            if p not in fixset: assert d.read(p, 8) == bytes(8); extra.append(p - base)
    # Typed allocation signature rebuild with native16 parent prefix.
    def signatures(obj, bundles):
        found = {}
        for bundle in bundles:
            for s in obj.ksegments(bundle):
                for t in s['sections']:
                    if t['name'] != '__kalloc_type': continue
                    for a in range(t['addr'], t['addr'] + t['size'], 64):
                        namep = struct.unpack('<Q', obj.read(a + 16, 8))[0]
                        name = obj.read(namep, 128).split(b'\0')[0].decode().removeprefix('site.')
                        sigp = struct.unpack('<Q', obj.read(a + 32, 8))[0]
                        sig = obj.read(sigp, 2048).split(b'\0')[0]
                        found[name] = (a, sig)
        return found
    parents = {bymeta[int(c['super_metaclass'], 16)] for c in own.values()} - own.keys()
    bundles = {dc[n]['bundle'] for n in parents}
    old_sig = signatures(d, bundles | {AMP_NAME}); native_sig = signatures(k, bundles)
    sig_pool_off = ds['__TEXT']['size']
    rebuilt = {}; pending = dict(own); signature_pool = bytearray(); signature_records = []
    while pending:
        progressed = False
        for n, c in list(pending.items()):
            parent = bymeta[int(c['super_metaclass'], 16)]
            if parent in pending: continue
            a, sig = old_sig[n]; parent_old = old_sig[parent][1]
            assert sig.startswith(parent_old), (n, parent)
            parent_new = rebuilt[parent] if parent in rebuilt else native_sig[parent][1]
            sig = parent_new + sig[len(parent_old):]
            expected = (c['instance_size'] + 8 + 7) // 8
            assert len(sig) == expected, (n, len(sig), expected)
            new_address = dest['__TEXT'] + sig_pool_off + len(signature_pool)
            special[a + 32] = {'kind': 'native', 'target': new_address}
            signature_records.append({'class': n, 'descriptor': hex(local(a)), 'signature': hex(new_address), 'words': len(sig)})
            signature_pool.extend(sig + b'\0'); rebuilt[n] = sig; del pending[n]; progressed = True
        assert progressed
    assert sig_pool_off + len(signature_pool) < os['__TEXT']['size']
    patches, pairs = plan_patches(d, plan_data)
    assert not pairs
    init_text = params['markers']['init_text'].encode('latin1')
    def finalize(k, d, out, local, dst, tail, write):
        records = []; newfix = []
        def edit(a, b, why): write(a, b); records.append({'address': hex(a), 'size': len(b), 'reason': why})
        edit(dest['__TEXT'] + sig_pool_off, signature_pool, 'Typed allocation word signatures with native16 parent layouts')
        def trace_wrapper(a, real, name):
            code = struct.pack('<III', 0xa9ba7bfd, 0x910003fd, 0xa90107e0)
            code += struct.pack('<III', 0xa9020fe2, 0xa90317e4, 0xa9041fe6)
            begin = a + 0x100; okay = a + 0x140; fail = a + 0x180
            code += struct.pack('<I', adr(a + len(code), begin, 0)); code += bl(a + len(code), nn['_IOLog'])
            code += struct.pack('<IIII', 0xa94107e0, 0xa9420fe2, 0xa94317e4, 0xa9441fe6)
            code += bl(a + len(code), local(real)); code += struct.pack('<I', 0xf9002be0)
            code += struct.pack('<I', 0x34000060)
            code += struct.pack('<I', adr(a + len(code), okay, 0)); code += branch(a + len(code), a + len(code) + 8)
            code += struct.pack('<I', adr(a + len(code), fail, 0)); code += bl(a + len(code), nn['_IOLog'])
            code += struct.pack('<III', 0xf9402be0, 0xa8c67bfd, 0xd65f03c0)
            assert len(code) < 0x100
            edit(a, code, 'Call real ' + name + ' with all x0-x7 arguments preserved; trace boolean return')
            for addr, label in [(begin, ' begin'), (okay, ' success'), (fail, ' failure')]:
                edit(addr, b'\x1b[36m' + ts['label'].encode() + b' ' + name.encode() + label.encode() + b'\x1b[0m\n\0', 'Cyan hardware path checkpoint')
        trace_wrapper(trace, int(ts['start_fn'], 16), 'start')
        init = next(t for s in ds.values() for t in s['sections'] if t['name'] == '__mod_init_func')
        original = struct.unpack('<Q', d.read(init['addr'] + 8, 8))[0]
        text = init_text
        code = struct.pack('<II', 0xa9bf7bfd, 0x910003fd) + bl(marker + 8, local(original))
        code += struct.pack('<I', adr(marker + 12, marker + 28, 0)) + bl(marker + 16, nn['_IOLog']) + struct.pack('<II', 0xa8c17bfd, 0xd65f03c0) + text
        edit(marker, code, 'Yellow registration marker after all real metaclass initializers')
        edit(local(init['addr'] + 8), struct.pack('<Q', marker), 'Retain initializer through marker wrapper')
        records.append({'marker': hex(marker), 'trace': hex(trace),
                        'table_counts': {n: len(v) for n, v in tables.items()}})
        return marker + len(code), records, newfix
    report = {'status': 'DRAFT; FINAL IMAGE AND NATIVE EXECUTION AUDIT REQUIRED', 'classes': table_reports,
            'field_instruction_and_size_patches': len(patches), 'reclaimed_bundle': AMP_OLD,
            'typed_allocation_signatures': signature_records}
    return private, report, special, patches, extra, skip, finalize

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def macho_sha256(path):
    with open(path, 'rb') as f:
        data = f.read()
    ncmds = struct.unpack_from('<I', data, 16)[0]
    off, end = 32, 0
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, off)
        if cmd == 0x19:
            fileoff, filesize = struct.unpack_from('<QQ', data, off + 40)
            end = max(end, fileoff + filesize)
        off += size
    return hashlib.sha256(data[:end]).hexdigest()


def main(argv):
    if len(argv) < 4:
        sys.stderr.write(__doc__)
        return 2
    dst, donor, output = Path(argv[1]), Path(argv[2]), Path(argv[3])
    profiles = Path(argv[argv.index('--profiles') + 1]) if '--profiles' in argv \
        else HERE / 'audioport-profiles.json.gz'
    with gzip.open(profiles, 'rb') as f:
        plans = json.loads(f.read())
    abi = plans['cs42l71']
    switch = plans['cs42l71_switch']
    only = argv[argv.index('--only') + 1] if '--only' in argv else None
    amp_abi = None if only == 'cs42l71' else plans['cs35l19']
    expected = abi['source_kernels']
    # img4 (macOS build) drops data trailing the Mach-O that pyimg4 keeps, so
    # also accept a hash of the Mach-O extent only.
    require(sha256(donor) == expected['donor_sha256'] or
            macho_sha256(donor) == expected['donor_macho_sha256'],
            'Donor kernel does not match the profiled SE 15.8.8 kernel')
    if sha256(dst) != expected['target_sha256']:
        # The profiled target is the pre-kextport ipad6f kernel; the pipeline
        # feeds us the kextport output, which legitimately differs.
        sys.stderr.write('note: input is not the profiled target kernel '
                         '(expected after kextport/pmuhax stages)\n')
    if output.exists():
        sys.stderr.write('refusing to overwrite %s\n' % output)
        return 2
    d_kc, k_kc = KC(donor), KC(dst)
    # Target-side verification: every target address the engine relies on must
    # still hold the bytes recorded when the profile was generated (VAs of
    # existing kexts are unchanged by pmuhax/kextport, so raw-byte equality is
    # the right check; any drift here means the input is not the kernel we
    # profiled).
    fps = abi['params'].get('target_fingerprints', {})
    for addr, fp in fps.items():
        got = hashlib.sha256(k_kc.read(int(addr, 16), fp['bytes'])).hexdigest()
        require(got == fp['sha256'],
                'Target fingerprint mismatch at %s (input kernel does not '
                'match the profiled target at this address)' % addr)
    sys.stderr.write('target fingerprints verified: %d\n' % len(fps))
    private, review, slots, patches, extra, skip, finish = mic_prepare(d_kc, k_kc, abi)
    with tempfile.TemporaryDirectory(prefix='audioport-') as td:
        stage1 = Path(td) / 'mc1'
        stage1.mkdir()
        params = abi['params']
        data, report = transplant_apply(
            dst, donor, stage1,
            OLD=MIC_OLD, NAME=MIC_NAME,
            marker_source=(params['markers']['source'].encode('latin1')
                           if params['markers'].get('source') else None),
            marker_target=(params['markers']['target'].encode('latin1')
                           if params['markers'].get('target') else None),
            private_bindings=private, private_review=review,
            slot_overrides=slots, donor_word_patches=patches,
            finalize=finish, extra_donor_slots=extra, skip_donor_slots=skip,
            expanded_segments={n: int(v, 16) for n, v in params['expanded_segments'].items()},
            non_instruction_words={int(a, 16): v for a, v in
                                   params.get('non_instruction_words', {}).items()})
        stage2 = Path(td) / 'mc2'
        stage2.mkdir()
        if amp_abi is not None:
            ap, areview, aslots, apatches, aextra, askip, afinalize = amp_prepare(d_kc, k_kc, amp_abi)
            stage3 = Path(td) / 'amp'
            stage3.mkdir()
            data, amp_report = transplant_apply(
                stage1 / 'kernelcache.raw', donor, stage3,
                OLD=AMP_OLD, NAME=AMP_NAME,
                marker_source=None, marker_target=None,
                private_bindings=ap, private_review=areview,
                slot_overrides=aslots, donor_word_patches=apatches,
                finalize=afinalize, extra_donor_slots=aextra, skip_donor_slots=askip,
                expanded_segments={}, non_instruction_words={})
            mc2_in = stage3 / 'kernelcache.raw'
        else:
            amp_report = None
            mc2_in = stage1 / 'kernelcache.raw'
        final, mc2_report = mc2_apply(mc2_in, donor, switch, stage2)
    output.write_bytes(final)
    summary = {'transplant': {k: v for k, v in report.items()
                              if k not in ('allowed_raw_ranges', 'ABI_adaptation',
                                           'private_dependency_review')},
               'amp': None if amp_report is None else
                      {k: v for k, v in amp_report.items()
                       if k not in ('allowed_raw_ranges', 'ABI_adaptation',
                                    'private_dependency_review')},
               'mc2': {'additional_instruction_count': mc2_report['additional_instruction_count'],
                       'edit_count': len(mc2_report['edits'])},
               'output': str(output), 'output_sha256': hashlib.sha256(final).hexdigest()}
    print(json.dumps(summary, indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
