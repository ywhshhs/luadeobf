"""luadeob rbxenv — full Roblox environment stub for the Lua sandbox.

This module builds a complete, permissive Roblox executor-style environment
inside a lupa LuaRuntime. Design principles (learned from clyde_decompiler.py
and the Deobfuscator-Luraph-V15 runtime/envlog.luau):

  * EVERYTHING resolves. `game.Players.LocalPlayer.Character.Humanoid.WalkSpeed = 200`
    works; unknown members return chained callables/auto-objects. Obfuscated
    scripts probe dozens of APIs before ever reaching their payload — the env
    must not crash on any of them.
  * CAPTURE, don't block. loadstring/HttpGet/writefile/queue_on_teleport record
    into a capture log instead of executing (loadstring) or the network.
  * Datatypes are REAL math. Vector3/CFrame/Color3/UDim2 etc. implement proper
    arithmetic so scripts doing CFrame math or GUI layout don't error out.
  * Known hard gotchas, encoded here so they never regress:
      - bit32.bxor/band/bor MUST be variadic (a 2-arg shim corrupts in-flight
        opcode decryption in VM obfuscators -> garbage payloads).
      - do NOT stub the `debug` table (Clyde's anti-tamper compares debug.info
        against numbers; a string stub aborts the payload decrypt).
      - Luraph fingerprints the utf8 table KEY SET: utf8.graphemes,
        utf8.nfcnormalize, utf8.nfdnormalize must exist.
      - Lua 5.5 (lupa) natively has string.pack/unpack — Clyde's layer0 uses
        string.pack; on LuaJIT-only builds a shim would be required.
"""

from __future__ import annotations

import base64 as _b64
import json as _json
import math as _math
import os
import time as _time
import urllib.request

# ----------------------------------------------------------------------------
# Virtual filesystem
# ----------------------------------------------------------------------------

class VirtualFS:
    """In-memory FS for writefile/readfile. Optionally read-through to disk."""

    def __init__(self, root=None):
        self.root = os.path.abspath(root) if root else None
        self.writes = {}          # path -> content (str)
        self.reads = []

    def _safe(self, path):
        p = os.path.normpath(path.lstrip("/\\"))
        if self.root:
            full = os.path.abspath(os.path.join(self.root, p))
            # read-through allowed only inside root
            if full.startswith(self.root):
                return full
        return None

    def write(self, path, content):
        self.writes[path] = content
        return True

    def read(self, path):
        self.reads.append(path)
        if path in self.writes:
            return self.writes[path]
        full = self._safe(path)
        if full and os.path.isfile(full):
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
            except OSError:
                pass
        return None

    def exists(self, path):
        return path in self.writes or (self._safe(path) and os.path.isfile(self._safe(path))) is True

    def isfile(self, path):
        return self.exists(path)

    def isfolder(self, path):
        full = self._safe(path)
        return bool(full and os.path.isdir(full))

    def listdir(self, path):
        full = self._safe(path)
        if full and os.path.isdir(full):
            try:
                return os.listdir(full)
            except OSError:
                return []
        return []

    def delete(self, path):
        self.writes.pop(path, None)
        return True


# ----------------------------------------------------------------------------
# Real HTTP fetch (opt-in)
# ----------------------------------------------------------------------------

def real_fetch(url, timeout=6, method="GET", body=None, headers=None):
    try:
        h = {"User-Agent": "Roblox/WinInet", "Accept": "*/*"}
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, data=body.encode() if isinstance(body, str) else body,
                                     headers=h, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001 — network is best-effort
        return "-- [luadeob] FETCH FAILED: %s" % e


# ----------------------------------------------------------------------------
# The environment builder — mostly Lua, assembled from Python
# ----------------------------------------------------------------------------

_DATATYPES_LUA = r"""
-- ===== datatypes with real math =====
local function clamp01(x) if x < 0 then return 0 elseif x > 1 then return 1 end return x end

local V3mt = {}
Vector3 = {}
function Vector3.new(x, y, z)
  x, y, z = tonumber(x) or 0, tonumber(y) or 0, tonumber(z) or 0
  local v = {X = x, Y = y, Z = z}
  function v.Dot(a, b) return a.X*b.X + a.Y*b.Y + a.Z*b.Z end
  function v.Cross(a, b) return Vector3.new(a.Y*b.Z - a.Z*b.Y, a.Z*b.X - a.X*b.Z, a.X*b.Y - a.Y*b.X) end
  function v:Lerp(goal, t) return Vector3.new(self.X + (goal.X-self.X)*t, self.Y + (goal.Y-self.Y)*t, self.Z + (goal.Z-self.Z)*t) end
  function v.__tostring(s) return string.format("%g, %g, %g", s.X, s.Y, s.Z) end
  return setmetatable(v, {
    __index = function(t, k)
      if k == 'Magnitude' then return math.sqrt(t.X^2 + t.Y^2 + t.Z^2) end
      if k == 'Unit' then local m = math.sqrt(t.X^2+t.Y^2+t.Z^2); if m == 0 then return Vector3.new(0,0,0) end return Vector3.new(t.X/m, t.Y/m, t.Z/m) end
      return V3mt[k]
    end,
    __add = function(a,b) return Vector3.new(a.X+b.X, a.Y+b.Y, a.Z+b.Z) end,
    __sub = function(a,b) return Vector3.new(a.X-b.X, a.Y-b.Y, a.Z-b.Z) end,
    __mul = function(a,b)
      if type(b) == 'number' then return Vector3.new(a.X*b, a.Y*b, a.Z*b) end
      if type(a) == 'number' then return Vector3.new(a*b.X, a*b.Y, a*b.Z) end
      return Vector3.new(a.X*b.X, a.Y*b.Y, a.Z*b.Z)
    end,
    __div = function(a,b) if type(b) == 'number' then return Vector3.new(a.X/b, a.Y/b, a.Z/b) end return Vector3.new(a.X/b.X, a.Y/b.Y, a.Z/b.Z) end,
    __unm = function(a) return Vector3.new(-a.X, -a.Y, -a.Z) end,
    __eq  = function(a,b) return a.X==b.X and a.Y==b.Y and a.Z==b.Z end,
    __tostring = function(a) return '<vector>' end,
  })
end
Vector3.zero = Vector3.new(0,0,0)
Vector3.one = Vector3.new(1,1,1)
Vector3.xAxis = Vector3.new(1,0,0)
Vector3.yAxis = Vector3.new(0,1,0)
Vector3.zAxis = Vector3.new(0,0,1)

local V2mt = {}
Vector2 = {}
function Vector2.new(x, y)
  x, y = tonumber(x) or 0, tonumber(y) or 0
  local v = {X = x, Y = y}
  function v:Lerp(goal, t) return Vector2.new(self.X + (goal.X-self.X)*t, self.Y + (goal.Y-self.Y)*t) end
  return setmetatable(v, {
    __index = function(t, k) if k == 'Magnitude' then return math.sqrt(t.X^2 + t.Y^2) end if k == 'Unit' then local m = math.sqrt(t.X^2+t.Y^2); if m == 0 then return Vector2.new(0,0) end return Vector2.new(t.X/m, t.Y/m) end return V2mt[k] end,
    __add = function(a,b) return Vector2.new(a.X+b.X, a.Y+b.Y) end,
    __sub = function(a,b) return Vector2.new(a.X-b.X, a.Y-b.Y) end,
    __mul = function(a,b) if type(b) == 'number' then return Vector2.new(a.X*b, a.Y*b) elseif type(a) == 'number' then return Vector2.new(a*b.X, a*b.Y) end return Vector2.new(a.X*b.X, a.Y*b.Y) end,
    __div = function(a,b) if type(b) == 'number' then return Vector2.new(a.X/b, a.Y/b) end return Vector2.new(a.X/b.X, a.Y/b.Y) end,
    __unm = function(a) return Vector2.new(-a.X, -a.Y) end,
    __eq = function(a,b) return a.X==b.X and a.Y==b.Y end,
    __tostring = function(a) return '<vector>' end,
  })
end
Vector2.zero = Vector2.new(0,0)
Vector2.one = Vector2.new(1,1)

local C3mt = {}
Color3 = {}
function Color3.new(r, g, b) return setmetatable({R = tonumber(r) or 0, G = tonumber(g) or 0, B = tonumber(b) or 0}, {
  __index = function(t, k)
    if k == 'RGB' then return t.R, t.G, t.B end
    return C3mt[k]
  end,
  __eq = function(a,b) return a.R==b.R and a.G==b.G and a.B==b.B end,
  __tostring = function(a) return string.format("%g, %g, %g", a.R, a.G, a.B) end,
}) end
function Color3.fromRGB(r, g, b) return Color3.new((tonumber(r) or 0)/255, (tonumber(g) or 0)/255, (tonumber(b) or 0)/255) end
function Color3.fromHSV(h, s, v)
  h = (tonumber(h) or 0) % 1
  local i = math.floor(h * 6); local f = h * 6 - i
  local p, q, t = v*(1-s), v*(1-f*s), v*(1-(1-f)*s)
  local r, g, b
  if i == 0 then r,g,b = v,t,p elseif i == 1 then r,g,b = q,v,p elseif i == 2 then r,g,b = p,v,t
  elseif i == 3 then r,g,b = p,q,v elseif i == 4 then r,g,b = t,p,v else r,g,b = v,p,q end
  return Color3.new(r, g, b)
end
function Color3.toHSV(c)
  local r, g, b = c.R, c.G, c.B
  local mx, mn = math.max(r,g,b), math.min(r,g,b); local d = mx - mn
  if d == 0 then return 0, 0, mx end
  local h
  if mx == r then h = ((g-b)/d) % 6 elseif mx == g then h = (b-r)/d + 2 else h = (r-g)/d + 4 end
  return h/6, mx == 0 and 0 or d/mx, mx
end

-- ===== CFrame: full 3x3 rotation-matrix composition =====
local CFmt = {}
CFrame = {}
local function cf(p, m)
  return setmetatable({p = p, m = m}, CFmt)
end
local function cframe(pos, rot)
  local x, y, z = 0, 0, 0
  if type(pos) == 'table' then x, y, z = pos.X or pos[1] or 0, pos.Y or pos[2] or 0, pos.Z or pos[3] or 0
  else x, y, z = tonumber(pos) or 0, tonumber(rot) or 0, tonumber(rot) or 0 end
  -- careful: CFrame.new(x,y,z) is the common form
  return cf(Vector3.new(x, y, z), {1,0,0, 0,1,0, 0,0,1})
end
local function mulmat(a, b)
  -- a,b are 3x3 row-major {r11,r12,r13, r21,...}
  local out = {}
  for i = 0, 2 do
    for j = 0, 2 do
      out[i*3+j+1] = a[i*3+1]*b[j+1] + a[i*3+2]*b[3+j+1] + a[i*3+3]*b[6+j+1]
    end
  end
  return out
end
local function rotX(a) local c, s = math.cos(a), math.sin(a) return {1,0,0, 0,c,-s, 0,s,c} end
local function rotY(a) local c, s = math.cos(a), math.sin(a) return {c,0,s, 0,1,0, -s,0,c} end
local function rotZ(a) local c, s = math.cos(a), math.sin(a) return {c,-s,0, s,c,0, 0,0,1} end
local function fromMatrix(m, pos) return cf(pos or Vector3.new(0,0,0), m) end

function CFrame.new(a, b, c)
  if type(a) == 'table' and a.p then  -- copy
    return cf(a.p, a.m)
  end
  if type(a) == 'table' and a.X then  -- Vector3
    return cf(a, {1,0,0, 0,1,0, 0,0,1})
  end
  if Vector3 and type(b) == 'table' and b.X and type(c) == 'table' and c.X then
    -- CFrame.new(eye, target): lookAt
    return CFrame.lookAt(a, b)
  end
  local x, y, z = tonumber(a) or 0, tonumber(b) or 0, tonumber(c) or 0
  return cf(Vector3.new(x, y, z), {1,0,0, 0,1,0, 0,0,1})
end
function CFrame.fromMatrix(v, r, u, b) return cf(v, {r.X,r.Y,r.Z, u.X,u.Y,u.Z, (b and b.X) or 0,(b and b.Y) or 0,(b and b.Z) or 0}) end
function CFrame.fromEulerAnglesXYZ(rx, ry, rz)
  local m = mulmat(mulmat(rotZ(rz), rotY(ry)), rotX(rx))
  return cf(Vector3.new(0,0,0), m)
end
CFrame.Angles = CFrame.fromEulerAnglesXYZ
CFrame.fromOrientation = CFrame.fromEulerAnglesXYZ
function CFrame.lookAt(eye, target, up)
  up = up or Vector3.new(0,1,0)
  local f = (target - eye).Unit
  local r = f:Cross(up).Unit
  local u = r:Cross(f)
  return cf(eye, {r.X,r.Y,r.Z, u.X,u.Y,u.Z, f.X,f.Y,f.Z})
end
function CFrame.identity() return CFrame.new(0,0,0) end

CFmt.__index = function(t, k)
  local m = t.m
  if k == 'LookVector' then return Vector3.new(m[7], m[8], m[9]) end
  if k == 'RightVector' then return Vector3.new(m[1], m[2], m[3]) end
  if k == 'UpVector' then return Vector3.new(m[4], m[5], m[6]) end
  if k == 'XVector' then return Vector3.new(m[1], m[2], m[3]) end
  if k == 'YVector' then return Vector3.new(m[4], m[5], m[6]) end
  if k == 'ZVector' then return Vector3.new(m[7], m[8], m[9]) end
  if k == 'Position' then return t.p end
  if k == 'X' then return t.p.X end
  if k == 'Y' then return t.p.Y end
  if k == 'Z' then return t.p.Z end
  if k == 'GetComponents' or k == 'Components' then
    return function(s) return s.p.X,s.p.Y,s.p.Z, m[1],m[2],m[3], m[4],m[5],m[6], m[7],m[8],m[9] end
  end
  if CFmethods and CFmethods[k] then return CFmethods[k] end
  return CFmt[k]
end
CFmethods = {
  PointToWorldSpace = function(s, v) local m = s.m; return s.p + Vector3.new(m[1]*v.X+m[4]*v.Y+m[7]*v.Z, m[2]*v.X+m[5]*v.Y+m[8]*v.Z, m[3]*v.X+m[6]*v.Y+m[9]*v.Z) end,
  ToWorldSpace = function(s, o) return cf(s.p + o.p, mulmat(s.m, o.m)) end,
  ToObjectSpace = function(s, o) return cf(o.p - s.p, mulmat(transpose3(s.m), o.m)) end,
  PointToObjectSpace = function(s, v) local m = transpose3(s.m); local lp = v - s.p; return Vector3.new(m[1]*lp.X+m[4]*lp.Y+m[7]*lp.Z, m[2]*lp.X+m[5]*lp.Y+m[8]*lp.Z, m[3]*lp.X+m[6]*lp.Y+m[9]*lp.Z) end,
  Inverse = function(s) return cf(-s.p, transpose3(s.m)) end,
  Lerp = function(s, o, t) return cf(s.p:Lerp(o.p, t), s.m) end,
  GetFullName = function() return 'CFrame' end,
}
function CFmt.__mul(a, b)
  if type(b) == 'table' and b.p then   -- CFrame * CFrame
    return a:ToWorldSpace(b)
  end
  return a:PointToWorldSpace(b)        -- CFrame * Vector3
end
function CFmt.__add(a, v) return cf(a.p + v, a.m) end
function CFmt.__sub(a, v) return cf(a.p - v, a.m) end
function CFmt.__tostring(a) return string.format("%g, %g, %g", a.p.X, a.p.Y, a.p.Z) end
function transpose3(m) return {m[1],m[4],m[7], m[2],m[5],m[8], m[3],m[6],m[9]} end

-- ===== UDim / UDim2 =====
UDim = {}
function UDim.new(s, o) return setmetatable({Scale = tonumber(s) or 0, Offset = tonumber(o) or 0}, {
  __add = function(a,b) return UDim.new(a.Scale+b.Scale, a.Offset+b.Offset) end,
  __sub = function(a,b) return UDim.new(a.Scale-b.Scale, a.Offset-b.Offset) end,
  __eq = function(a,b) return a.Scale==b.Scale and a.Offset==b.Offset end,
  __tostring = function(a) return string.format("{%g, %g}, {%g, %g}", a.Scale, a.Offset, a.Scale, a.Offset) end,
}) end

UDim2 = {}
function UDim2.new(xs, xo, ys, yo)
  if type(xs) == 'table' then -- UDim2.fromScale? or UDim2.new(UDim, UDim)
    xs, xo, ys, yo = 0, 0, 0, 0
  end
  local x = UDim.new(tonumber(xs) or 0, tonumber(xo) or 0)
  local y = UDim.new(tonumber(ys) or 0, tonumber(yo) or 0)
  return setmetatable({X = x, Y = y, XScale = x.Scale, XOffset = x.Offset, YScale = y.Scale, YOffset = y.Offset}, {
    __add = function(a,b) return UDim2.new(a.XScale+b.XScale, a.XOffset+b.XOffset, a.YScale+b.YScale, a.YOffset+b.YOffset) end,
    __sub = function(a,b) return UDim2.new(a.XScale-b.XScale, a.XOffset-b.XOffset, a.YScale-b.YScale, a.YOffset-b.YOffset) end,
    __tostring = function(a) return string.format("{%g, %g}, {%g, %g}", a.X.Scale, a.X.Offset, a.Y.Scale, a.Y.Offset) end,
  })
end
function UDim2.fromScale(xs, ys) return UDim2.new(xs, 0, ys, 0) end
function UDim2.fromOffset(xo, yo) return UDim2.new(0, xo, 0, yo) end

-- ===== misc datatypes =====
TweenInfo = {}
function TweenInfo.new(time, style, dir, reps, reverses, delay)
  return {Time = time or 1, EasingStyle = style or 'Quad', EasingDirection = dir or 'Out',
          RepeatCount = reps or 0, Reverses = reverses and true or false, DelayTime = delay or 0}
end
NumberRange = {}
function NumberRange.new(a, b) return {Min = a, Max = b or a} end
NumberSequence = {}
function NumberSequence.new(a, b)
  if b then return {Keypoints = {{Time=0,Value=a},{Time=1,Value=b}}} end
  return {Keypoints = {{Time=0,Value=a},{Time=1,Value=a}}}
end
NumberSequenceKeypoint = {}
function NumberSequenceKeypoint.new(t, v, e) return {Time = t, Value = v, Envelope = e or 0} end
ColorSequence = {}
function ColorSequence.new(a, b)
  b = b or a
  return {Keypoints = {{Time=0,Value=a},{Time=1,Value=b}}}
end
ColorSequenceKeypoint = {}
function ColorSequenceKeypoint.new(t, v) return {Time = t, Value = v} end
Rect = {}
function Rect.new(a,b,c,d)
  if type(a) == 'table' then return {Min = a, Max = b} end
  return {Min = Vector2.new(a or 0, b or 0), Max = Vector2.new(c or 0, d or 0)}
end
Ray = {}
function Ray.new(o, d) return {Origin = o, Direction = d,
  ClosestPoint = function(s, p) return s.Origin end,
  Distance = function(s, p) return 0 end} end
Random = {}
function Random.new(seed) local s = seed or os.time()
  local obj = {}
  obj.NextInteger = function(_, a, b) return math.floor(math.random() * (b - a + 1)) + a end
  obj.NextNumber = function(_, a, b) if a then return a + math.random()*(b-a) end return math.random() end
  obj.NextUnitVector = function() return Vector3.new(math.random()-0.5, math.random()-0.5, math.random()-0.5).Unit end
  obj.Clone = function() return obj end
  return obj end
BrickColor = {}
function BrickColor.new(c)
  if type(c) == 'number' then return {Name = tostring(c), Number = c, Color = Color3.new(0.5,0.5,0.5)} end
  return {Name = c or 'Medium stone grey', Number = 194, Color = Color3.new(0.63,0.63,0.63)}
end
function BrickColor.palette(n) return BrickColor.new(n) end
Font = {}
function Font.new(f, w) return {Family = f, Weight = w or 400, Style = 'Normal'} end
Font.fromEnum = function(e) return Font.new('rbxasset://fonts/families/SourceSansPro.json') end
Font.fromName = function(n, w) return Font.new(n, w) end
PhysicalProperties = {}
function PhysicalProperties.new(a,b,c,d,e)
  if type(a) == 'table' then return {Density=1, Friction=0.3, Elasticity=0.5, FrictionWeight=1, ElasticityWeight=1} end
  return {Density=a or 0.7, Friction=b or 0.3, Elasticity=c or 0.5, FrictionWeight=d or 1, ElasticityWeight=e or 1} end
Region3 = {}
function Region3.new(a, b) return {CFrame = CFrame.new((a.X+b.X)/2,(a.Y+b.Y)/2,(a.Z+b.Z)/2), Size = b - a} end
Faces = {}
function Faces.new() return setmetatable({}, {__index = function() return false end}) end
Axes = {}
function Axes.new() return setmetatable({}, {__index = function() return false end}) end
EnumRoot = {}
Enum = setmetatable({}, {__index = function(t, k)
  local svc = rawget(t, k)
  if svc then return svc end
  local leaf = setmetatable({}, {__index = function(tt, kk)
    local item = rawget(tt, kk)
    if item then return item end
    local e = {Name = kk, Value = kk, EnumType = k}
    rawset(tt, kk, e)
    return e
  end, __call = function() return nil end, __tostring = function() return 'Enum.'..k end})
  rawset(t, k, leaf)
  return leaf
end, __call = function() return nil end})
"""

# ----------------------------------------------------------------------------
# Sandbox core (pure Lua, no Roblox specifics)
# ----------------------------------------------------------------------------

_STDLIB_LUA = r"""
-- ===== Luau stdlib shims (Lua 5.5 runtime) =====
-- CRITICAL: real bit32 functions are VARIADIC. A 2-arg shim corrupts in-flight
-- opcode decryption in VM obfuscators (Clyde/Luraph) -> garbage payloads.
local function mkvariadic(f)
  return function(a, b, ...)
    if select('#', ...) == 0 then return f(a, b) end
    local r = f(a, b)
    for i = 1, select('#', ...) do r = f(r, (select(i, ...))) end
    return r
  end
end
local m32 = 0xFFFFFFFF
bit32 = bit32 or {}
bit32.bxor = mkvariadic(function(a, b) a, b = a & m32, b & m32; local r, p = 0, 1
  while a > 0 or b > 0 do if (a % 2) ~= (b % 2) then r = r + p end a = a // 2 b = b // 2 p = p * 2 end return r end)
bit32.band = mkvariadic(function(a, b) a, b = a & m32, b & m32; local r, p = 0, 1
  while a > 0 and b > 0 do if (a % 2) == 1 and (b % 2) == 1 then r = r + p end a = a // 2 b = b // 2 p = p * 2 end return r end)
bit32.bor = mkvariadic(function(a, b) a, b = a & m32, b & m32; local r, p = 0, 1
  while a > 0 or b > 0 do if (a % 2) == 1 or (b % 2) == 1 then r = r + p end a = a // 2 b = b // 2 p = p * 2 end return r end)
bit32.bnot = function(a) return (~a) & m32 end
bit32.lshift = function(a, n) return (a << (n & 31)) & m32 end
bit32.rshift = function(a, n) return (a & m32) >> (n & 31) end
bit32.arshift = function(a, n) n = n & 31; local r = (a & m32) >> n
  if n > 0 and a < 0 then r = r | (m32 << (32 - n)) & m32 end return r end
bit32.lrotate = function(a, n) n = n & 31; if n == 0 then return a & m32 end return ((a << n) | (a >> (32 - n))) & m32 end
bit32.rrotate = function(a, n) n = n & 31; if n == 0 then return a & m32 end return ((a & m32) >> n | (a << (32 - n))) & m32 end
bit32.countlz = function(a) a = a & m32; if a == 0 then return 32 end local n = 0
  local p = 0x80000000; while bit32.band(a, p) == 0 do n = n + 1; p = p >> 1 end return n end
bit32.countrz = function(a) a = a & m32; if a == 0 then return 32 end local n = 0
  while bit32.band(a, 1) == 0 do n = n + 1; a = a >> 1 end return n end
bit32.byteswap = function(a) a = a & m32
  return ((a & 0xFF) << 24) | ((a & 0xFF00) << 8) | ((a >> 8) & 0xFF00) | ((a >> 24) & 0xFF) end
bit32.extract = function(n, f, w) w = w or 1
  return (n >> f) & ((1 << w) - 1) end
bit32.replace = function(n, v, f, w) w = w or 1
  local mask = ((1 << w) - 1) << f
  return (n & ~mask) | ((v << f) & mask) end

table.create = table.create or function(n, v)
  local t = {}
  if n then for i = 1, n do t[i] = v end end
  return t
end
table.find = table.find or function(t, v, i)
  for j = (i or 1), #t do if t[j] == v then return j end end
  return nil
end
table.clear = table.clear or function(t) for k in pairs(t) do t[k] = nil end end
table.freeze = table.freeze or function(t) return t end
table.isfrozen = table.isfrozen or function() return false end
table.unpack = table.unpack or unpack
table.pack = table.pack or function(...) return {n = select('#', ...), ...} end
table.move = table.move or function(a1, f, t, d, a2)
  a2 = a2 or a1
  for i = f, t do a2[d + i - f] = a1[i] end
  return a2
end

string.split = string.split or function(s, sep)
  local out = {}
  if sep == nil then sep = ',' end
  local pat = '([^' .. sep .. ']*)' .. sep .. '?'
  for m in s:gmatch(pat) do if #m > 0 then out[#out+1] = m end end
  return out
end

-- Luraph fingerprints the utf8 table KEY SET: graphemes/nfcnormalize/nfdnormalize must exist.
utf8 = utf8 or {}
utf8.nlen = utf8.nlen or function(s, i) return #s end
utf8.graphemes = utf8.graphemes or function(s, i, j)
  local list = {}
  for p, c in utf8.codes(s) do list[#list+1] = {p, p + #utf8.char(c) - 1} end
  local n = 0
  return function() n = n + 1; return list[n] and list[n][1], list[n] and list[n][2] or nil end
end
utf8.nfcnormalize = utf8.nfcnormalize or function(s) return s end
utf8.nfdnormalize = utf8.nfdnormalize or function(s) return s end

math.clamp = math.clamp or function(x, a, b) return math.max(a, math.min(b, x)) end
math.round = math.round or function(x) return math.floor(x + 0.5) end
math.sign = math.sign or function(x) if x > 0 then return 1 elseif x < 0 then return -1 end return 0 end
math.noise = math.noise or function() return 0 end
math.map = math.map or function(x, a1, b1, a2, b2) return a2 + (x - a1) * (b2 - a2) / (b1 - a1) end

-- ===== pure-Lua JSON (HttpService.JSONEncode/JSONDecode; lupa cannot iterate
-- Lua tables from inside a Lua->Python callback, so no Python bridge here) =====
LUAJSON = (function()
  local esc = {['"'] = '\\"', ['\\'] = '\\\\', ['\b'] = '\\b', ['\f'] = '\\f',
               ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t'}
  local function enc(v, seen)
    local t = type(v)
    if t == 'string' then
      return '"' .. v:gsub('[%c"\\]', function(c) return esc[c] or string.format('\\u%04x', c:byte()) end) .. '"'
    elseif t == 'number' then
      return (v == math.floor(v) and math.abs(v) < 2^53) and string.format('%d', v) or tostring(v)
    elseif t == 'boolean' then return v and 'true' or 'false'
    elseif t == 'nil' then return 'null'
    elseif t == 'table' then
      if seen[v] then return '"[circular]"' end
      seen[v] = true
      local isarr, n = #v > 0, #v
      if not isarr then
        for _ in pairs(v) do n = n + 1 end
        isarr = (n == #v and #v > 0)
      end
      local parts = {}
      if isarr and #v > 0 then
        for i = 1, #v do parts[i] = enc(v[i], seen) end
        seen[v] = nil
        return '[' .. table.concat(parts, ',') .. ']'
      end
      for k, x in pairs(v) do
        local ks = type(k) == 'string' and k or tostring(k)
        parts[#parts + 1] = enc(ks, seen) .. ':' .. enc(x, seen)
      end
      seen[v] = nil
      return '{' .. table.concat(parts, ',') .. '}'
    end
    return '"' .. tostring(v) .. '"'
  end
  local function dec(s, i)
    i = i or 1
    local c = s:sub(i, i)
    while c == ' ' or c == '\t' or c == '\n' or c == '\r' do i = i + 1; c = s:sub(i, i) end
    if c == '{' then
      local obj = {}; i = i + 1
      while true do
        while s:sub(i,i):match('[%s,]') do i = i + 1 end
        if s:sub(i, i) == '}' then return obj, i + 1 end
        local k; k, i = dec(s, i)
        while s:sub(i,i):match('[%s:]') do i = i + 1 end
        local v; v, i = dec(s, i)
        obj[k] = v
      end
    elseif c == '[' then
      local arr = {}; i = i + 1
      while true do
        while s:sub(i,i):match('[%s,]') do i = i + 1 end
        if s:sub(i, i) == ']' then return arr, i + 1 end
        local v; v, i = dec(s, i)
        arr[#arr + 1] = v
      end
    elseif c == '"' then
      local out = {}; i = i + 1
      while true do
        local ch = s:sub(i, i)
        if ch == '\\' then
          local e = s:sub(i + 1, i + 1)
          local map = {n = '\n', t = '\t', r = '\r', b = '\b', f = '\f', ['"'] = '"', ['\\'] = '\\', ['/'] = '/'}
          if e == 'u' then
            out[#out + 1] = utf8.char(tonumber(s:sub(i + 2, i + 5), 16) or 0); i = i + 6
          else
            out[#out + 1] = map[e] or e; i = i + 2
          end
        elseif ch == '"' then return table.concat(out), i + 1
        else out[#out + 1] = ch; i = i + 1 end
      end
    elseif s:sub(i, i + 3) == 'true' then return true, i + 4
    elseif s:sub(i, i + 4) == 'false' then return false, i + 5
    elseif s:sub(i, i + 3) == 'null' then return nil, i + 4
    else
      local num = s:match('^-?%d+%.?%d*[eE]?-?%d*', i)
      if num then return tonumber(num), i + #num end
      return nil, i + 1
    end
  end
  return {
    encode = function(v) return enc(v, {}) end,
    decode = function(s) local v = dec(s); return v end,
  }
end)()
"""

# ----------------------------------------------------------------------------
# Roblox env: game / services / Instance / signals / executor globals (pure Lua)
# ----------------------------------------------------------------------------

_ENV_LUA = r"""
-- ===== capture plumbing (Python bridges) =====
-- PYLOAD(payload, chunkname)  loadstring capture
-- PYHTTP(url, kind, body)     http capture (kind: HttpGet/GetAsync/PostAsync/RequestAsync)
-- PYWRITE(path, content)      writefile capture
-- PYNOTE(kind, ...)           generic note (teleport/clipboard/etc)
-- PYDISP(vmid, op, pc)        dispatch-loop trace (from the dispatch pass)

-- ===== Instance proxy =====
Signal = {}
function Signal.new(name)
  local sig = {_classname = 'RBXScriptSignal', _name = name or 'Signal', _handlers = {}}
  function sig:Connect(fn)
    local conn = {Connected = true}
    function conn.Disconnect() conn.Connected = false end
    function conn:Disconnect2() conn.Connected = false end
    setmetatable(conn, {__iter = function() return function() end end})
    self._handlers[#self._handlers + 1] = {fn = fn, conn = conn}
    return conn
  end
  sig.Once = sig.Connect
  sig.ConnectParallel = sig.Connect
  sig.ConnectEx = sig.Connect
  function sig:Wait()
    -- fire once with stub payload, do NOT hang the sandbox
    local args = {Enum and Enum and {} or {}}
    return 0.03
  end
  function sig:Fire(...)
    for _, h in ipairs(self._handlers) do
      local ok, err = pcall(h.fn, ...)
      if not ok then PYNOTE('handler_error', tostring(err)) end
    end
  end
  return sig
end

local function autoClass(name)
  name = name or 'Instance'
  local props = {ClassName = name, Name = name, Parent = nil}
  local signals = {}
  local mt
  local obj = setmetatable({}, mt)
  mt = {
    __index = function(t, k)
      local v = props[k]
      if v ~= nil then return v end
      -- known method fallbacks
      local method = AUTO_METHODS[k]
      if method then return method(obj, props, signals) end
      -- signal properties
      if AUTO_SIGNALS[k] then
        signals[k] = signals[k] or Signal.new(k)
        return signals[k]
      end
      -- auto-vivify child instance
      local child = autoClass(k)
      child.Name = k
      child.Parent = obj
      props[k] = child
      return child
    end,
    __newindex = function(t, k, v)
      props[k] = v
      PYNOTE('prop', tostring(name) .. '.' .. tostring(k))
    end,
    __call = function(t, ...) return autoClass(name) end,
    __tostring = function() return name end,
    __eq = function(a, b) return a == b end,
  }
  setmetatable(obj, mt)
  return obj
end

AUTO_METHODS = {}
AUTO_SIGNALS = setmetatable({}, {__index = function(t, k)
  -- property names ending in common event names behave as signals
  local n = #k
  return (n > 4 and (k:sub(-7) == 'Changed' or k:sub(-3) == 'ded' or k:sub(-2) == 'ed')) or nil
end})

local function makeMethods()
  local M = AUTO_METHODS
  M.FindFirstChild = function(obj, props) return function(self, n, rec)
    local v = props[n]
    if v then return v end
    local c = autoClass(n); c.Name = n; c.Parent = self; props[n] = c
    return c
  end end
  M.FindFirstChildOfClass = M.FindFirstChild
  M.FindFirstChildWhichIsA = M.FindFirstChild
  M.FindFirstAncestor = function(obj, props) return function(self, n) return autoClass(n) end end
  M.WaitForChild = function(obj, props) return function(self, n, t)
    local v = props[n]
    if v then return v end
    local c = autoClass(n); c.Name = n; c.Parent = self; props[n] = c
    return c
  end end
  M.GetChildren = function(obj, props) return function()
    local out = {}
    for k, v in pairs(props) do
      if type(v) == 'table' and rawget(v, '_instance') then out[#out+1] = v end
    end
    return out
  end end
  M.GetDescendants = M.GetChildren
  M.IsA = function(obj, props) return function(self, cls) return cls == 'Instance' or cls == props.ClassName end end
  M.IsAncestorOf = function() return function() return false end end
  M.Destroy = function() return function() end end
  M.Clone = function(obj, props) return function(self) return autoClass(props.ClassName) end end
  M.ClearAllChildren = function() return function() end end
  M.GetAttribute = function(obj, props) return function(self, n) return props['_attr_' .. n] end end
  M.SetAttribute = function(obj, props) return function(self, n, v) props['_attr_' .. n] = v end end
  M.GetAttributes = function() return function() return {} end end
  M.GetPropertyChangedSignal = function(obj, props, signals) return function(self, n)
    signals[n] = signals[n] or Signal.new(n); return signals[n]
  end end
  M.GetEngineFeature = function() return function() return true end end
  M.GetService = function(obj) return function(self, n) return GAME:GetService(n) end end
  M.getPlayerFromCharacter = nil
  M.GetPlayerFromCharacter = function() return function(self, c) return GAME.Players.LocalPlayer end end
  M.GetMouse = function() return function()
    return autoClass('Mouse')
  end end
  M.getPropertyChangedSignal = M.GetPropertyChangedSignal
  M.isA = M.IsA
  M.destroy = M.Destroy
  M.clone = M.Clone
  M.wait = M.WaitForChild
  return M
end
makeMethods()

-- ===== game / DataModel =====
GAME = nil
local services = {}

local function mkService(name)
  if services[name] then return services[name] end
  local svc
  svc = autoClass(name)
  services[name] = svc
  return svc
end

local function playerStub()
  local p = autoClass('Player')
  p.Name = 'LocalPlayer'
  p.DisplayName = 'LocalPlayer'
  p.UserId = 12345
  p.AccountAge = 365
  p.MembershipType = Enum.MembershipType.Premium
  p.Character = autoClass('Model')
  local char = p.Character
  char.Name = 'LocalPlayer'
  local hrp = autoClass('BasePart')
  hrp.Name = 'HumanoidRootPart'
  hrp.Size = Vector3.new(2, 2, 1)
  hrp.Position = Vector3.new(0, 3, 0)
  hrp.CFrame = CFrame.new(0, 3, 0)
  hrp.Velocity = Vector3.new(0, 0, 0)
  char.HumanoidRootPart = hrp
  local hum = autoClass('Humanoid')
  hum.Health = 100; hum.MaxHealth = 100; hum.WalkSpeed = 16; hum.JumpPower = 50
  char.Humanoid = hum
  p.CharacterAdded = Signal.new('CharacterAdded')
  p.CharacterRemoving = Signal.new('CharacterRemoving')
  p.Chatted = Signal.new('Chatted')
  return p
end

function GAME_INDEX(t, k)
  return nil
end

GAME = setmetatable({}, {
  __index = function(t, k)
    local kl = string.lower(k or '')
    -- executor-ish properties on game
    if kl == 'httpget' or kl == 'httpgetasync' then
      return function(self, url, ...) PYHTTP(url, 'HttpGet', nil) return HTTP_MOCK_BODY end
    end
    if kl == 'httppost' or kl == 'httppostasync' then
      return function(self, url, data, ...) PYHTTP(url, 'HttpPost', data) return HTTP_MOCK_BODY end
    end
    if kl == 'placeid' then return 0 end
    if kl == 'jobid' then return 'sandbox-job' end
    if kl == 'gameid' then return 0 end
    if kl == 'workspace' then return services['Workspace'] or mkService('Workspace') end
    if kl == 'creatorid' then return 0 end
    if kl == 'creationtime' then return 0 end
    if kl == 'getservice' then
      return function(self, name) return mkService(name) end
    end
    if kl == 'findservice' then return function(self, name) return mkService(name) end end
    if kl == 'findfirstchild' then return function(self, n) return mkService(n) end end
    if kl == 'getchildren' then return function() return {} end end
    -- anything else: a service-like child (game.Something, game.ReplicatedStorage.Foo)
    return mkService(k)
  end,
  __newindex = function() error('game is read-only in sandbox') end,
  __tostring = function() return 'DataModel' end,
})
HTTP_MOCK_BODY = "return 'luadeob sandbox mock'"

-- ===== executor globals =====
GENV = {}
_G = _G
_SHARED = {}
shared = _SHARED
GenvTable = {}
function getgenv() return GENV end
function getfenv(f) return _G end

function identifyexecutor() return 'luadeob Sandbox', '1.0' end
function getexecutorname() return 'luadeob Sandbox' end
function checkcaller() return false end
function iscclosure(f) return type(f) == 'function' end
function islclosure(f) return type(f) == 'function' end
function isLclosure(f) return type(f) == 'function' end
function newcclosure(f) return f end
function clonefunction(f) return f end
function replaceclosure(f, g) return f end
function hookfunction(f, g) return f end
function hookmetamethod(obj, k, fn) return fn end
function setreadonly(t, v) return true end
function getrawmetatable(t) return getmetatable(t) end
function setrawmetatable(t, mt) return setmetatable(t, mt) end
function isreadonly() return false end
function getcallingscript() return SCRIPT end
function getloadedmodules() return {} end
function getsenv(s) return _G end
function getmstring() return '' end
function msgbox() return nil end
function gethui() return GAME:GetService('CoreGui') end
function gethwid() return 'LUADEOB-SANDBOX' end
function setclipboard(s) PYNOTE('clipboard', s) end
function toclipboard(s) PYNOTE('clipboard', s) end
function queue_on_teleport(s) PYNOTE('teleport_queue', s) end
function queueonteleport(s) PYNOTE('teleport_queue', s) end
function firetouchinterest(a, b) PYNOTE('firetouchinterest') end
function fireclickdetector(d) PYNOTE('fireclickdetector') end
function fireproximityprompt(p) PYNOTE('fireproximityprompt') end
function fireinput(input) PYNOTE('fireinput') end
function getconnections(sig) return {} end
function isfile(p) return VFS.isfile(p) end
function isfolder(p) return VFS.isfolder(p) end
function listfiles(p) return VFS.listdir(p) end
function delfile(p) return VFS.delete(p) end
function delfolder() return true end
function readfile(p) local c = VFS.read(p); if c == nil then error('readfile: no such file ' .. tostring(p)) end return c end
function writefile(p, c) VFS.write(p, c); PYWRITE(p, SANITIZE(c)) end
function loadstring(src, cn)
  PYLOAD(SANITIZE(src), cn)
  local f, err = load(src, cn)
  if not f then return nil, err end
  return function(...) return f(...) end
end
-- request family: capture (or real-fetch with --fetch)
function request(opts)
  local url = type(opts) == 'table' and (opts.Url or opts.url) or opts
  local body = type(opts) == 'table' and (opts.Body or opts.body) or nil
  local headers = type(opts) == 'table' and (opts.Headers or opts.headers) or nil
  local method = type(opts) == 'table' and (opts.Method or opts.method) or 'GET'
  PYHTTP(url, 'request(' .. tostring(method) .. ')', body)
  if not HTTP_FETCH_REAL then
    return {Success = true, StatusCode = 200, Body = HTTP_MOCK_BODY, Headers = {}}
  end
  return {Success = true, StatusCode = 200, Body = real_fetch(url, 20, method, body, headers), Headers = {}}
end
http_request = request
httpRequest = request
http = {request = request}
syn = {request = request, websocket = {connect = function() return {Send = function() end, Close = function() end, OnMessage = Signal.new()} end}}

-- websocket (generic)
websocket = {connect = function(url)
  PYNOTE('websocket', url)
  return {Send = function() end, Close = function() end, OnMessage = Signal.new('OnMessage'), OnClose = Signal.new('OnClose')}
end}

crypt = {
  base64encode = function(s) return PYB64(s, true) end,
  base64decode = function(s) return PYB64(s, false) end,
  base64 = {encode = function(s) return PYB64(s, true) end, decode = function(s) return PYB64(s, false) end},
}

-- ===== tasks =====
task = {
  spawn = function(f, ...) local a = {...} local c = coroutine.create(f) local ok, err = coroutine.resume(c, table.unpack(a)); if not ok then PYNOTE('task_error', tostring(err)) end return c end,
  defer = task and (function(f, ...) return task.spawn(f, ...) end) or nil,
  delay = function(t, f, ...) return task.spawn(f, ...) end,
  cancel = function() end,
  wait = function(t) return 0.03 end,
}
function wait(t) return 0.03 end
function spawn(f, ...) return task.spawn(f, ...) end
function delay(t, f, ...) return task.spawn(f, ...) end
function tick() return os.clock() end
-- capture print() output (agents see what the script printed) while still
-- forwarding to the real print for stdout.
-- SANITIZE: strings with bytes >=128 or control bytes cannot cross into
-- Python (lupa decodes Lua strings as UTF-8) — escape them as \ddd text.
function SANITIZE(s)
  if type(s) ~= 'string' then return s end
  local needs = false
  for i = 1, #s do
    local b = string.byte(s, i)
    if b >= 128 or (b < 32 and b ~= 9) then needs = true break end
  end
  if not needs then return s end
  local out = {}
  for i = 1, #s do
    local b = string.byte(s, i)
    if b >= 32 and b < 127 then out[#out + 1] = string.char(b)
    elseif b == 9 then out[#out + 1] = '\\t'
    elseif b == 10 then out[#out + 1] = '\\n'
    else out[#out + 1] = '\\' .. b end
  end
  return table.concat(out)
end
local _realprint = print
print = function(...)
  local n = select('#', ...)
  local parts = {}
  for i = 1, n do parts[i] = SANITIZE(tostring((select(i, ...)))) end
  PYNOTE('print', table.concat(parts, '\t'))
  return _realprint(...)
end
warn = function(...)
  local n = select('#', ...)
  local parts = {}
  for i = 1, n do parts[i] = SANITIZE(tostring((select(i, ...)))) end
  PYNOTE('warn', table.concat(parts, '\t'))
end
function time() return os.clock() end

-- ===== globals assembly =====
Instance = {}
function Instance.new(class, parent)
  local i = autoClass(class)
  if parent then i.Parent = parent end
  return i
end
game = GAME
workspace = mkService('Workspace')
Workspace = workspace
script = autoClass('Script')
script.Name = 'SandboxScript'
workspace.CurrentCamera = autoClass('Camera')
workspace.CurrentCamera.FieldOfView = 70
workspace.CurrentCamera.CFrame = CFrame.new(0, 10, 0)
workspace.CurrentCamera.ViewportSize = Vector2.new(1920, 1080)
workspace.Gravity = 196.2
Players = game:GetService('Players')
Players.LocalPlayer = playerStub()
ReplacedStorage = nil
ReplicatedStorage = game:GetService('ReplicatedStorage')
RunService = game:GetService('RunService')
UserInputService = game:GetService('UserInputService')
HttpService = game:GetService('HttpService')
TweenService = game:GetService('TweenService')
Lighting = game:GetService('Lighting')
StarterGui = game:GetService('StarterGui')
CoreGui = game:GetService('CoreGui')
-- service specific extras
Players.PlayerAdded = Signal.new('PlayerAdded')
Players.PlayerRemoving = Signal.new('PlayerRemoving')
RunService.Heartbeat = Signal.new('Heartbeat')
RunService.RenderStepped = Signal.new('RenderStepped')
RunService.PreRender = Signal.new('PreRender')
RunService.PostSimulation = Signal.new('PostSimulation')
RunService.Stepped = Signal.new('Stepped')
RunService.IsClient = function() return true end
RunService.IsRunMode = function() return false end
RunService.IsServer = function() return false end
RunService.IsStudio = function() return false end
UserInputService.InputBegan = Signal.new('InputBegan')
UserInputService.InputEnded = Signal.new('InputEnded')
UserInputService.InputChanged = Signal.new('InputChanged')
UserInputService.IsKeyDown = function() return false end
UserInputService.WindowFocused = Signal.new('WindowFocused')
HttpService.JSONEncode = function(_, v) return LUAJSON.encode(v) end
HttpService.JSONDecode = function(_, s) return LUAJSON.decode(s) end
HttpService.GenerateGUID = function(b) return PYGUID(b) end
HttpService.GetAsync = function(self, url) PYHTTP(url, 'GetAsync', nil) return HTTP_MOCK_BODY end
HttpService.PostAsync = function(self, url, data) PYHTTP(url, 'PostAsync', data) return HTTP_MOCK_BODY end
HttpService.RequestAsync = function(self, opts) return request(opts) end
TweenService.Create = function(self, inst, info, props)
  local tween = {Instance = inst, TweenInfo = info, Props = props}
  tween.Play = function() end
  tween.Cancel = function() end
  tween.Pause = function() end
  tween.Completed = Signal.new('Completed')
  return tween
end
TweenService.GetValue = function() return 0 end
MarketplaceService = game:GetService('MarketplaceService')
MarketplaceService.GetProductInfo = function() return {Name = 'Sandbox Game', Price = 0, Description = ''} end
MarketplaceService.PlayerOwnsAsset = function() return false end
Stats = game:GetService('Stats')
Stats.Network = {ServerStatsItem = setmetatable({}, {__index = function() return {GetValueString = function() return '10 ms' end} end})}
TeleportService = game:GetService('TeleportService')
TeleportService.Teleport = function(self, placeId) PYNOTE('teleport', placeId) end
local DEOBFUNC = nil
"""
