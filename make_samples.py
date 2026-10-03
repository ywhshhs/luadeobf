#!/usr/bin/env python3
"""make_samples — generate 5 Luau samples with obfuscation difficulty 1-5.

Every sample prints something random on completion. Keys/strings/junk are
randomized on every generation so deobfuscation is never the same twice.

  L1  escaped strings + string.char + arithmetic-constant soup          (easy)
  L2  mangled names + XOR string table + dead branches + folded math    (medium)
  L3  escaped loadstring layer + checksum gate + junk anti-tamper       (hard)
  L4  3-layer chain: base64(XOR) loader -> escaped chunk -> final       (harder)
  L5  custom register VM: encrypted constant pool + encrypted opcode
      stream with polynomial per-position keys; plaintext never exists
      statically; dispatch loop like real VM obfuscators                (hardest)
"""

import base64
import os
import random
import string

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "obf_samples")

WORDS = ["ember", "quartz", "raven", "cascade", "obsidian", "zephyr", "onyx",
         "nebula", "cinder", "vortex", "pyre", "glacier", "specter", "flux"]


def rname(n=6):
    return "_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def rkey():
    return random.randint(7, 249)


def esc(s, style=None):
    """Escape raw bytes as a Luau literal, random escape style.
    latin-1 so bytes >=128 stay single bytes (no UTF-8 double-encode)."""
    style = style or random.choice(["dec", "hex", "mix"])
    out = []
    for b in (s.encode("latin-1", "replace") if isinstance(s, str) else s):
        if style == "dec":
            out.append("\\%03d" % b)
        elif style == "hex":
            out.append("\\x%02x" % b)
        else:
            out.append(random.choice(["\\%03d" % b, "\\x%02x" % b]))
    return '"' + "".join(out) + '"'


def arith(n):
    """Obfuscate a number as a small arithmetic expression."""
    t = random.randint(2, 4)
    parts = [random.randint(1, 200) for _ in range(t + 1)]
    expr = str(parts[0])
    ops = ["+", "-", "*"]
    for i in range(1, t + 1):
        op = random.choice(ops[:2]) if i < t else random.choice(ops)
        expr += f"{random.choice([' ', ''])}{op}{parts[i]}"
    # wrap so it evaluates to exactly n: prefix with (n - eval)? simpler: use a known-op layout
    a, b = random.randint(1, 500), None
    style = random.choice(["add", "sub", "mul", "mix3"])
    if style == "add":
        b = n - a
        return f"({a}+({b}))"
    if style == "sub":
        b = a - n
        return f"({a}-({b}))"
    if style == "mul":
        f_ = random.choice([2, 3, 5, 7])
        return f"({n}*{f_}/{f_})"
    # mix3: (a + b*c - d) constructed to equal n
    b, c = random.randint(1, 40), random.randint(2, 30)
    d = a + b * c - n
    return f"({a}+{b}*{c}-({d}))"


def lua_str_lit(s):
    """Readable (non-obfuscated) literal for building nested layers."""
    out = []
    for ch in s:
        if ch in '"\\\n':
            out.append("\\%03d" % ord(ch))
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        else:
            out.append("\\%03d" % ord(ch))
    return '"' + "".join(out) + '"'


# ----------------------------------------------------------------------------
# L1 — easy
# ----------------------------------------------------------------------------

def level1():
    key_msg = random.choice(WORDS)
    code = random.randint(1000, 9999)
    final = f"L1 complete {key_msg}-{code:04x}"

    v1, v2, v3 = rname(), rname(), rname()
    return f"""-- difficulty 1
local {v1},{v2}={esc(key_msg)},{arith(code)}
local {v3}={{[{arith(1)}]={esc('L1 complete ')},[{arith(2)}]={v1},[{arith(3)}]={esc('-')}}}
print({v3}[{arith(1)}]..{v1}..{v3}[{arith(3)}]..string.format("%04x",{v2}))
"""


# ----------------------------------------------------------------------------
# L2 — medium: XOR string table
# ----------------------------------------------------------------------------

def level2():
    secret = f"L2 complete {random.choice(WORDS)}-{random.randint(0x1000, 0xffff):04x}"
    k = rkey()  # single key shared by encoder + decoder below
    enc = [b ^ k for b in secret.encode()]
    nums = ", ".join(str(e) for e in enc)
    v_tab, v_dec, v_out, v_junk = rname(), rname(), rname(), rname()
    jm = random.randint(2, 9)
    junk = "".join(random.choice(" \t") for _ in range(0))
    return f"""-- difficulty 2
local {v_tab}={{{nums}}}
local {v_dec}={k}
local function {v_out}(t,kk) local _={{}} for i=1,#t do _[#_+1]=string.char(t[i]~(kk+{random.randint(0,0)})~0+0*#{v_tab}) end return table.concat(_) end
local {v_junk}=function(x) return x*{jm}+1 end
if {v_junk}(3)=={3 * jm + 1} then print({v_out}({v_tab},{v_dec})) else print({esc('nope')}) end
"""


# ----------------------------------------------------------------------------
# L3 — hard: escaped loadstring layer + checksum gate
# ----------------------------------------------------------------------------

def level3():
    final = f"L3 complete {random.choice(WORDS)}-{random.randint(0x1000, 0xffff):04x}"
    payload = f"local w={random.randint(1,99)} print({lua_str_lit(final)}) "
    adler = _adler32(payload)
    loader = f"""-- difficulty 3
local src={esc(payload, 'dec')}
local function sum(s) local a,b=1,0 for i=1,#s do a=(a+string.byte(s,i))%65521 b=(b+a)%65521 end return b*65536+a end
local function tier(s) return s end
local ok,vals=pcall(function() local f=loadstring(tier(src),'=L3') if not f then error('bad') end return f() end)
if ok==true and sum(src)=={adler} then return vals end
"""
    return loader


def _adler32(s):
    a, b = 1, 0
    data = s.encode()
    for byte in data:
        a = (a + byte) % 65521
        b = (b + a) % 65521
    return b * 65536 + a


# ----------------------------------------------------------------------------
# L4 — harder: base64(XOR) loader -> escaped chunk -> final
# ----------------------------------------------------------------------------




def level4():
    final = f"L4 complete {random.choice(WORDS)}-{random.randint(0x1000, 0xffff):04x}"
    layer3 = f"print({lua_str_lit(final)})"
    k3 = rkey()
    esc3 = esc(layer3, "dec")
    layer2 = f"local k={k3} loadstring({esc3})() "
    while len(layer2) % 3 != 0:      # avoid b64 padding: Lua decoder is padding-free
        layer2 += " "
    k2 = rkey()
    x2 = bytes(b ^ k2 for b in layer2.encode())
    b2 = base64.b64encode(x2).decode("ascii")
    n_tabs = random.choice(["table.concat", "table[" + lua_str_lit("concat") + "]"])

    return f"""-- difficulty 4
local D={lua_str_lit(b2)}
local K2={k2}
local function un(s) local o={{}} local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' for i=1,#s do local c=s:sub(i,i) local p=b:find(c,1,true) if p then o[#o+1]=p-1 end end local out={{}} for i=1,#o,4 do local a,c,d,e=o[i],o[i+1] or 0,o[i+2] or 0,o[i+3] or 0 local n=a*262144+c*4096+d*64+e out[#out+1]=string.char(math.floor(n/65536)%256,math.floor(n/256)%256,n%256) end return {n_tabs}(out) end
local raw=un(D)
local dec={{}}
for i=1,#raw do dec[#dec+1]=string.char(string.byte(raw,i)~K2) end
loadstring(table.concat(dec))()
"""


# ----------------------------------------------------------------------------
# L5 — hardest: custom register VM, everything encrypted
# ----------------------------------------------------------------------------

def level5():
    # --- assemble a tiny program ---
    # ops: 1=LOADK r,k  2=LOADRAND r,k(words split by |)  3=LOADNUM r n
    #      4=FMTHEX r a (a -> %04x)  5=CONCAT r a b  6=PRINT r  7=HALT
    words = "|".join(WORDS)
    cpool = ["L5 complete ", words, "-"]  # 1: prefix, 2: words, 3: dash
    prog = [
        (2, 1, 2),                     # r1 = random word from c2
        (3, 2, random.randint(0x1000, 0xFFFF)),  # r2 = random number
        (4, 3, 2),                     # r3 = format(r2, %04x)
        (1, 4, 1),                     # r4 = c1 ("L5 complete ")
        (5, 4, 4, 1),                  # r4 = r4 .. r1
        (1, 5, 3),                     # r5 = c3 ("-")
        (5, 4, 4, 5),                  # r4 = r4 .. r5
        (5, 4, 4, 3),                  # r4 = r4 .. r3
        (6, 4),                        # print r4
        (7,),                          # halt
    ]
    # encode opcode stream with polynomial position key (like Clyde)
    A, B, C = (random.randint(1, 99) for _ in range(3))
    def poskey(i):  # 1-indexed
        return (A + i * B + i * i * C) & 0xFF
    enc_ops = []
    for ins in prog:
        op = ins[0]
        ops_byte = op ^ poskey(len(enc_ops) + 1)
        args = ins[1:]
        enc_ops.append(ops_byte)
        for a_ in range(3):
            v = (ins[a_ + 1] if a_ + 1 < len(ins) else 0)
            enc_ops.append(v ^ poskey(len(enc_ops) + 1))
    # encrypt constant pool: each string XOR with (k + 7*i) stream
    ck = rkey()
    enc_pool = []
    for s in cpool:
        data = s.encode()
        out = []
        for j, byte in enumerate(data):
            out.append(byte ^ ((ck + 7 * (j + 1)) & 0xFF))
        enc_pool.append(out)

    def lua_bytestr(bytes_):
        return "{" + ",".join(str(b) for b in bytes_) + "}"

    pool_tbl = ",\n  ".join(lua_bytestr(b) for b in enc_pool)
    ops_tbl = ",".join(str(b) for b in enc_ops)
    v = [rname(3) for _ in range(8)]
    pool_lit = ",\n".join(esc(bytes(b).decode("latin-1"), "dec") for b in enc_pool)

    # decode pool at runtime via escaped strings of raw bytes
    return f"""-- difficulty 5
local {v[0]}={{{pool_lit}}}
local {v[1]}={ck}
local function {v[2]}(t) local o={{}} for j=1,#t do o[j]=string.char(string.byte(t,j)~(({v[1]}+7*j)%256)) end return table.concat(o) end
local {v[5]}={{{ops_tbl}}}
local {v[6]},{v[7]}=1,{{}}
local function pk(i) return ({A}+i*{B}+i*i*{C})&0xFF end
local R={{}}
while true do
local op={v[5]}[{v[6]}]~pk({v[6]})
local a={v[5]}[{v[6]}+1]~pk({v[6]}+1)
local b={v[5]}[{v[6]}+2]~pk({v[6]}+2)
local c={v[5]}[{v[6]}+3]~pk({v[6]}+3)
if op==1 then R[a]={v[2]}({v[0]}[b]);{v[6]}+=4
elseif op==2 then local w={v[2]}({v[0]}[b]); local parts={{}}; local s=w; local n=0; for wq in s:gmatch("[^|]+") do n=n+1; parts[n]=wq end; R[a]=parts[math.random(1,n)];{v[6]}+=4
elseif op==3 then R[a]=math.random(0,65535);{v[6]}+=4
elseif op==4 then R[a]=string.format("%04x",R[b]);{v[6]}+=4
elseif op==5 then R[a]=(R[b] or '')..(R[c] or '');{v[6]}+=4
elseif op==6 then print(R[a]);{v[6]}+=4
elseif op==7 then break end
end
"""


# ----------------------------------------------------------------------------

def main():
    os.makedirs(OUT, exist_ok=True)
    import sys
    only = [int(x) for x in sys.argv[1:]] if len(sys.argv) > 1 else None
    samples = {k: fn() for k, fn in ({1: level1, 2: level2, 3: level3, 4: level4, 5: level5,
                                      **ALL_LEVELS}).items()
               if only is None or k in only}
    for lvl, code in samples.items():
        path = os.path.join(OUT, f"level{lvl}.lua")
        with open(path, "w") as f:
            f.write(code)
        print(f"{path}: {len(code)} bytes")
    # smoke: run each in the sandbox to confirm they print
    from luadeob.sandbox import Sandbox
    for lvl, code in samples.items():
        sb = Sandbox()
        ok, err = sb.run(code)
        d = sb.drain()
        prints = [n["value"] for n in d["notes"] if n["kind"] == "print"]
        print(f"  level{lvl}: ok={ok} prints={prints} err={(err or '')[:60]}")



# ----------------------------------------------------------------------------
# L6 — control-flow flattening + poly-key cipher + opaque predicates
# ----------------------------------------------------------------------------

def poly_enc(data, A, B, C):
    return bytes(b ^ ((A + i * B + i * i * C) & 0xFF) for i, b in enumerate(data))


def level6():
    secret = f"L6 complete {random.choice(WORDS)}-{random.randint(0x1000, 0xffff):04x}"
    A, B, C = (random.randint(3, 89) for _ in range(3))
    enc = poly_enc(secret.encode(), A, B, C)
    tbl = "{" + ",".join(arith(b) for b in enc) + "}"
    v = [rname() for _ in range(6)]
    return f"""-- difficulty 6
local {v[0]}={tbl}
local function {v[1]}(i) return ({A}+i*{B}+i*i*{C})&0xFF end
local function {v[2]}(x) local y=x*{random.randint(3,13)}+7 return y==y end
local {v[3]}={{}} local {v[4]}=1
while true do
  if {v[4]}==1 then
    if {v[2]}({random.randint(5,50)}) then {v[4]}+=3 else {v[4]}+=9 end
  elseif {v[4]}==4 then
    for i=1,#{v[0]} do {v[3]}[i]=string.char(string.byte({v[0]},i)~{v[1]}(i)) end
    {v[4]}+=2
    continue
  elseif {v[4]}==6 then
    print(table.concat({v[3]})) {v[4]}+=93
  elseif {v[4]}==12 then
    print({esc('nope')}) {v[4]}+=87
  elseif {v[4]}>=99 then break end
end
"""


# ----------------------------------------------------------------------------
# L7 — 4-layer chain: arith-array -> running-key XOR -> reversed+add -> final
# ----------------------------------------------------------------------------

def level7():
    final = f"L7 complete {random.choice(WORDS)}-{random.randint(0x1000, 0xffff):04x}"

    # layer4: plain
    l4 = f"print({lua_str_lit(final)}) "
    # layer3: reverse + per-byte add
    k3 = random.randint(5, 60)
    l3_data = bytes((b + k3) & 0xFF for b in l4.encode()[::-1])
    l3 = ("local s={" + ",".join(str(b) for b in l3_data) + "} "
          "local o={} for i=1,#s do o[#o+1]=string.char((s[#s-i+1]-" + str(k3) + ")%256) end "
          "loadstring(table.concat(o))() ")
    # layer2: running-key XOR (start + step)
    s2, step = random.randint(20, 230), random.randint(7, 60)
    l2_data = bytes(b ^ ((s2 + i * step) & 0xFF) for i, b in enumerate(l3.encode()))
    l2 = ("local s={" + ",".join(str(b) for b in l2_data) + "} "
          f"local a={s2} local o={{}} for i=1,#s do o[i]=string.char(s[i]~(a&255)) a=a+{step} end "
          "loadstring(table.concat(o))() ")
    # layer1 (the file): arith-encoded byte array of layer2
    l1_body = ("local s={" + ",".join(arith(b) for b in l2.encode()) + "} "
               "local o={} for i=1,#s do o[i]=string.char(s[i]) end "
               "loadstring(table.concat(o))() ")
    return "-- difficulty 7\n" + l1_body


# ----------------------------------------------------------------------------
# L8 — Luau dialect abuse (+=, continue, if-expr, interp, string.pack)
# ----------------------------------------------------------------------------

def level8():
    secret = f"L8 complete {random.choice(WORDS)}-{random.randint(0x1000, 0xffff):04x}"
    k = rkey()
    enc = [b ^ k for b in secret.encode()]
    packed = ", ".join(str(e) for e in enc)
    n1, n2 = random.randint(2, 9), random.randint(2, 9)
    v = [rname() for _ in range(5)]
    return f"""-- difficulty 8
local {v[0]}={{{packed}}}
local {v[1]}=string.pack("I2I2",{n1},{k})
local {v[2]}=string.unpack("I2",string.pack("I2",{k}))
local {v[3]}={{}} local {v[4]}=0
for i=1,#{v[0]} do
  if ({v[0]}[i]~{v[2]})%2==0 then {v[4]}+=1 else {v[4]}+=0 end
  {v[3]}[i]=string.char({v[0]}[i]~{v[2]})
  if {v[4]}>100000 then continue end
end
local msg=table.concat({v[3]})
local extra=if {n1}*{n2}>{n1} then string.rep("!",0) else string.rep(" ",0)
print(`{{msg}}{{extra}}`)
"""


# ----------------------------------------------------------------------------
# L9 — VM-in-VM: outer VM builds + runs an inner VM payload
# ----------------------------------------------------------------------------

def _vm_encode(prog, A, B, C, init_xor=None):
    """positional-poly-encrypted opcode stream, 4 slots per instruction"""
    def pk(i):
        return (A + i * B + i * i * C) & 0xFF
    out = []
    for ins in prog:
        for slot in range(4):
            v = ins[slot] if slot < len(ins) else 0
            out.append(v ^ pk(len(out) + 1))
    return out


def level9():
    inner_secret = f"L9 complete {random.choice(WORDS)}-{random.randint(0x1000, 0xffff):04x}"
    # ---- inner VM: fixed-XOR constants, different opcode numbering ----
    ik = rkey()
    inner_consts = [inner_secret, "done"]
    inner_enc = [[b ^ ik for b in s.encode()] for s in inner_consts]
    # inner ops: 40=LOADK r,c  50=PRINT r  60=HALT
    inner_prog = [(40, 1, 1), (50, 1), (60, 0, 0)]
    inner_ops = []
    for ins in inner_prog:
        for slot in range(3):
            v = ins[slot] if slot < len(ins) else 0
            inner_ops.append(v ^ (ik + len(inner_ops)) & 0xFF if False else v ^ ((ik + len(inner_ops)) & 0xFF))
    inner_ops_tbl = "{" + ",".join(str(b) for b in inner_ops) + "}"
    inner_pool_tbl = "{" + ",".join("{" + ",".join(str(b) for b in enc) + "}" for enc in inner_enc) + "}"
    inner_src = (
        f"local P={inner_pool_tbl} local K={ik} local O={inner_ops_tbl} "
        "local R={} local pc=1 "
        "while pc<=#O do "
        "local op=O[pc]~((K+pc-1)&255) local a=O[pc+1]~((K+pc)&255) local b=O[pc+2]~((K+pc+1)&255) "
        "if op==40 then local s=P[a] local o={} for j=1,#s do o[j]=string.char(string.byte(s,j)~K) end R[a]=table.concat(o) "
        "elseif op==50 then print(R[a]) "
        "elseif op==60 then break end "
        "pc+=3 end ")

    # ---- outer VM: poly-key constants, builds inner_src via LOADK pieces + loadstring ----
    A, B, C = (random.randint(3, 89) for _ in range(3))
    pieces = [inner_src[i:i + 40] for i in range(0, len(inner_src), 40)]
    outer_enc = [poly_enc(p.encode(), A, B, C) for p in pieces]
    outer_pool = "{" + ",".join("{" + ",".join(str(b) for b in e) + "}" for e in outer_enc) + "}"
    # outer ops: 1=LOADKDEC r,c (decode poly const into reg)  2=APPEND r (acc ..= reg)  3=ACC r  4=RUN  5=HALT
    outer_prog = [(3, 1)] + [(1, 2, i + 1) for i in range(len(pieces))] + [(2, 2), (2, 1)] * 0 + [(4, 0), (5, 0, 0)]
    # simpler: build acc by explicit APPENDs
    outer_prog = [(3, 1)]
    for i in range(len(pieces)):
        outer_prog += [(1, 2, i + 1), (2, 1, 2)]
    outer_prog += [(4, 0, 0), (5, 0, 0)]
    outer_ops = _vm_encode(outer_prog, A, B, C)

    v = [rname(3) for _ in range(6)]
    return f"""-- difficulty 9
local {v[0]}={outer_pool}
local function {v[1]}(i) return ({A}+i*{B}+i*i*{C})&0xFF end
local {v[2]}={{{",".join(str(b) for b in outer_ops)}}}
local {v[3]},{v[4]}=1,""
local R={{}}
while true do
  local op={v[2]}[{v[3]}]~{v[1]}({v[3]})
  local a={v[2]}[{v[3]}+1]~{v[1]}({v[3]}+1)
  local b={v[2]}[{v[3]}+2]~{v[1]}({v[3]}+2)
  if op==1 then
    local s={v[0]}[b] local o={{}} for j=1,#s do o[j]=string.char(string.byte(s,j)~{v[1]}(j)) end R[a]=table.concat(o)
    {v[3]}+=4
  elseif op==2 then {v[4]}={v[4]}..R[a]..R[b]; {v[3]}+=4
  elseif op==3 then {v[4]}=""; {v[3]}+=4
  elseif op==4 then local f=loadstring({v[4]})() {v[3]}+=4
  elseif op==5 then break end
end
"""


# ----------------------------------------------------------------------------
# L10 — the works: SBOX + poly opcode cipher + string.pack blob + anti-tamper
# ----------------------------------------------------------------------------

def level10():
    secret = f"L10 complete {random.choice(WORDS)}-{random.randint(0x1000, 0xffff):04x}"
    # sbox: random byte permutation
    sbox = list(range(256))
    random.shuffle(sbox)
    inv = [0] * 256
    for i, s in enumerate(sbox):
        inv[s] = i
    A, B, C = (random.randint(3, 89) for _ in range(3))
    def pk(i):
        return (A + i * B + i * i * C) & 0xFF
    # constants: sbox-substituted + poly-xor
    k = rkey()
    enc_const = []
    for j, b in enumerate(secret.encode()):
        x = inv[(b ^ k) & 0xFF]
        enc_const.append(x ^ pk(j + 1))
    # program (packed via string.pack at runtime? keep bytes literal, obfuscated via arith)
    # ops: 1=LOADDEC r (decode secret into reg r) 2=PRINT r 3=HALT
    prog = [(1, 1, 0), (2, 1, 0), (3, 0, 0)]
    ops = []
    for ins in prog:
        for slot in range(3):
            v = ins[slot] if slot < len(ins) else 0
            ops.append(inv[v] ^ pk(len(ops) + 1))  # VM decodes with sbox
    # the VM must sbox-decode constants too: constants were encoded with inv
    # (b ^ k) -> sbox-substituted; decode side uses inv? no: encode=inv[...],
    # decode=sbox[...]
    blob = ",".join(str(b) for b in ops)
    const_tbl = "{" + ",".join(str(b) for b in enc_const) + "}"
    sbox_tbl = "{" + ",".join(str(b) for b in sbox) + "}"
    # anti-tamper: checksum of ops table must match
    cksum = sum(ops) & 0xFFFF
    v = [rname(3) for _ in range(7)]
    return f"""-- difficulty 10
local {v[0]}={const_tbl}
local {v[1]}={sbox_tbl}
local {v[2]}={{{blob}}}
local {v[3]}=0 for i=1,#{v[2]} do {v[3]}+={v[2]}[i] end {v[3]}={v[3]}&65535
local function {v[4]}(i) return ({A}+i*{B}+i*i*{C})&0xFF end
if {v[3]}~={cksum} then print({esc('tampered')}) return end
if checkcaller and checkcaller() then print({esc('nope')}) return end
local {v[5]}={{}} local {v[6]}=1
local pk={{}}
local packed=string.pack("I2",{cksum})
local okk,unp=string.unpack("I2",packed)
while true do
  local op={v[1]}[{v[2]}[{v[6]}]~{v[4]}({v[6]})]
  local a={v[2]}[{v[6]}+1]~{v[4]}({v[6]}+1)
  if op==1 then
    local o={{}} for j=1,#{v[0]} do
      o[j]=string.char({v[1]}[string.byte({v[0]},j)~{v[4]}(j)]~{k})
    end
    {v[5]}[a]=table.concat(o) {v[6]}+=3
  elseif op==2 then print({v[5]}[a]) {v[6]}+=3
  elseif op==3 then break end
end
"""


ALL_LEVELS = {6: level6, 7: level7, 8: level8, 9: level9, 10: level10}

if __name__ == "__main__":
    main()
