import subprocess
import tempfile
import os
import re
import struct
import base64
import asyncio
from flask import Flask, request, jsonify
from lupa import LuaRuntime

app = Flask(__name__)
LUA_BIN = os.environ.get('LUA_BIN', 'lua5.1')
ANTHROPIC_KEY = os.environ.get('ANTHROPIC_API_KEY', '')

# ========== detection ==========

OBFUSCATOR_PATTERNS = {
    'luraph':     [r'loadstring\s*\(\s*\(function', r'bytecode\s*=\s*["\'][A-Za-z0-9+/=]{50,}'],
    'moonsec':    [r'local\s+\w+\s*=\s*\{[\d\s,]{20,}\}', r'_moon\s*=\s*function'],
    'ironbrew':   [r'local\s+\w+\s*=\s*\{\s*"\\x[0-9a-fA-F]{2}', r'\bIronBrew\b', r'bit\.bxor'],
    'ironbrew2':  [r'while\s+true\s+do\s+local\s+\w+\s*=\s*\w+\[\w+\]'],
    'wearedevs':  [r'show_\w+\s*=\s*function', r'getfenv\s*\(\s*\)', r'string\.reverse\s*\('],
    'prometheus': [r'Prometheus', r'number_to_bytes'],
    'custom_vm':  [r'mkexec', r'constTags', r'protoFormats'],
    'synapse':    [r'syn\.\w+\s*=\s*', r'syn\.protect'],
    'luaarmor':   [r'__*armor*', r'LuaArmor'],
    'psu':        [r'ProtectedString', r'ByteCode\s*='],
    'aurora':     [r'__aurora\s*=\s*', r'Aurora\s*=\s*'],
    'sentinel':   [r'Sentinel\s*=\s*', r'V3'],
    'obfuscated': [r'string\.char\s*\(', r'\\x[0-9a-fA-F]{2}'],
}

def detect_obfuscator(text):
    scores = {}
    for name, pats in OBFUSCATOR_PATTERNS.items():
        s = sum(1 for p in pats if re.search(p, text, re.IGNORECASE))
        if s:
            scores[name] = s
    return max(scores, key=lambda k: scores[k]) if scores else 'generic'

# ========== static decoding ==========

def static_clean(code):
    code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), code)
    code = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)
    def sc(m):
        nums = re.findall(r'\d+', m.group(1))
        try:
            return '"' + ''.join(chr(int(n)) for n in nums if int(n) < 256) + '"'
        except:
            return m.group(0)
    code = re.sub(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', sc, code)
    return code

def beautify(code):
    out = []
    indent = 0
    for line in code.split('\n'):
        s = line.strip()
        if not s:
            out.append('')
            continue
        if re.match(r'^(end\b|else\b|elseif\b|until\b)', s):
            indent = max(0, indent - 1)
        out.append('    ' * indent + s)
        if re.match(r'^(if\b|for\b|while\b|repeat\b|do\b)', s) and not s.endswith('end'):
            indent += 1
        if re.match(r'^(function\b|local\s+function\b)', s):
            indent += 1
    return '\n'.join(out)

# ========== bytecode constants ==========

class BytecodeParser:
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.strings = []
        self.numbers = []

    def u8(self):
        v = self.data[self.pos]; self.pos += 1; return v

    def u32(self):
        v = struct.unpack_from('<I', self.data, self.pos)[0]; self.pos += 4; return v

    def f64(self):
        v = struct.unpack_from('<d', self.data, self.pos)[0]; self.pos += 8; return v

    def lstring(self):
        n = self.u32()
        if n == 0:
            return ''
        s = self.data[self.pos:self.pos+n-1].decode('utf-8', errors='replace')
        self.pos += n
        return s

    def proto(self):
        self.lstring(); self.u32(); self.u32()
        self.u8(); self.u8(); self.u8(); self.u8()
        self.pos += self.u32() * 4
        for _ in range(self.u32()):
            t = self.u8()
            if t == 1:
                self.u8()
            elif t == 3:
                self.numbers.append(self.f64())
            elif t == 4:
                s = self.lstring()
                if s:
                    self.strings.append(s)
        for _ in range(self.u32()):
            self.proto()
        self.pos += self.u32() * 4
        for _ in range(self.u32()):
            self.lstring(); self.u32(); self.u32()
        for _ in range(self.u32()):
            self.lstring()

    def parse(self):
        if self.data[:4] != b'\x1bLua':
            return False
        self.pos = 12
        try:
            self.proto()
            return True
        except:
            return False

def extract_constants(source):
    candidates = []
    try:
        candidates.append(source.encode('latin-1'))
    except:
        pass
    for m in re.finditer(r'["\']([A-Za-z0-9+/=]{60,})["\']', source):
        try:
            candidates.append(base64.b64decode(m.group(1) + '=='))
        except:
            pass
    for data in candidates:
        if len(data) < 16:
            continue
        if data[:4] == b'\x1bLua':
            p = BytecodeParser(data)
            if p.parse():
                return {'strings': p.strings, 'numbers': p.numbers}
        for key in range(256):
            if bytes(b ^ key for b in data[:4]) == b'\x1bLua':
                full = bytes(b ^ key for b in data)
                p = BytecodeParser(full)
                if p.parse():
                    return {'strings': p.strings, 'numbers': p.numbers, 'xor_key': key}
    return None

# ========== Lupa sandbox with loadstring hook ==========

LUA_SANDBOX_SETUP = """
game             = setmetatable({}, {__index=function() return function() end end})
workspace        = game
script           = {}
Players          = {LocalPlayer={Name="Player",UserId=1}}
RunService       = {Heartbeat={Connect=function()end}}
UserInputService = {}
HttpService      = {JSONDecode=function() return {} end}
Instance         = {new=function() return setmetatable({},{__index=function()return function()end end}) end}
Vector3          = {new=function(...) return {} end}
CFrame           = {new=function(...) return {} end}
Color3           = {new=function(...) return {} end, fromRGB=function(...) return {} end}
UDim2            = {new=function(...) return {} end}
Enum             = setmetatable({},{__index=function() return setmetatable({},{__index=function() return 0 end}) end})
tick             = function() return 0 end
time             = function() return 0 end
wait             = function(n) return n or 0 end
spawn            = function() end
delay            = function() end
warn             = function() end
print            = function() end
error            = function(e) end
assert           = function(v,m) if not v then error(m or "assert") end return v end
shared           = {}
_G.game          = game
_G.workspace     = workspace
identifyexecutor = function() return "synapse","2.0" end
checkcaller      = function() return true end
writefile        = function() end
readfile         = function() return "" end
isfile           = function() return false end
makefolder       = function() end
request          = function() return {Body="",StatusCode=200} end
Drawing          = setmetatable({},{__index=function() return function() end end})
syn              = {protect_gui=function()end}
debug            = {traceback=function() return "" end}

bit = bit or {}
bit.bxor=function(a,b) local r,p=0,1 while a>0 or b>0 do if a%2~=b%2 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end
bit.band=function(a,b) local r,p=0,1 while a>0 and b>0 do if a%2==1 and b%2==1 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end
bit.bor =function(a,b) local r,p=0,1 while a>0 or b>0 do if a%2==1 or b%2==1 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end
bit.bnot=function(a) return -a-1 end
bit.rshift=function(a,b) return math.floor(a/(2^b)) end
bit.lshift=function(a,b) return math.floor(a*(2^b)) end
bit32 = bit

coroutine.wrap   = coroutine.wrap   or function(f) return f end
coroutine.create = coroutine.create or function(f) return f end
table.pack   = table.pack   or function(...) return {n=select('#',...), ...} end
table.unpack = table.unpack or unpack

local _realenv = {
    string=string, math=math, table=table, bit=bit, bit32=bit32,
    pairs=pairs, ipairs=ipairs, select=select, next=next,
    tostring=tostring, tonumber=tonumber, type=type,
    rawget=rawget, rawset=rawset, setmetatable=setmetatable,
    getmetatable=getmetatable, unpack=table.unpack,
    loadstring=loadstring, load=load, pcall=pcall, xpcall=xpcall,
    error=error, assert=assert, print=print, warn=warn,
    game=game, workspace=workspace, script=script,
    tick=tick, time=time, wait=wait, spawn=spawn,
    shared=shared, Drawing=Drawing, syn=syn,
    writefile=writefile, readfile=readfile, request=request,
    identifyexecutor=identifyexecutor, checkcaller=checkcaller,
    Instance=Instance, Vector3=Vector3, CFrame=CFrame,
    Color3=Color3, UDim2=UDim2, Players=Players,
    RunService=RunService, HttpService=HttpService
}
getfenv = function(n) return _realenv end
setfenv = function(n, t) for k,v in pairs(t) do _realenv[k]=v end return t end
_G = _realenv
_ENV = _realenv
"""

def sandbox_lupa(source, timeout=6):
    captured = []
    try:
        lua = LuaRuntime(unpack_returned_tuples=True)
        for name in ['io','os','require','dofile','loadfile','package','collectgarbage','newproxy','module']:
            try:
                lua.execute(f"{name} = nil")
            except:
                pass
        lua.execute(LUA_SANDBOX_SETUP)

        def safe_ls(code, *args):
            if callable(code):
                chunks = []
                try:
                    while True:
                        c = code()
                        if not c: break
                        chunks.append(str(c))
                except: pass
                code = ''.join(chunks)
            s = str(code) if code else ''
            if len(s.strip()) > 5:
                captured.append(s)
            return lua.eval("function(...) end")

        lua.globals()['loadstring'] = safe_ls
        lua.globals()['load'] = safe_ls

        lua.execute(source)
    except Exception:
        pass
    return captured

# ========== real Lua subprocess hook ==========

REAL_LUA_HOOK = """
local __captured = {}
local __outdir   = {OUTDIR}
local function __hook(code, ...)
  if type(code) == "string" and #code > 5 then
    local n = #__captured + 1
    __captured[n] = code
    local f = io.open(__outdir .. "/layer_" .. n .. ".lua", "w")
    if f then f:write(code); f:close() end
  end
  return function() end
end
loadstring = __hook
load       = __hook
local function __safe_getfenv(n)
  return {
    string=string, math=math, table=table, bit=bit or {},
    pairs=pairs, ipairs=ipairs, select=select, next=next,
    tostring=tostring, tonumber=tonumber, type=type,
    rawget=rawget, rawset=rawset, setmetatable=setmetatable,
    getmetatable=getmetatable, unpack=unpack or table.unpack,
    loadstring=loadstring, load=load, pcall=pcall, xpcall=xpcall,
    error=error, assert=assert, print=print
  }
end
getfenv = __safe_getfenv
setfenv = function(n, t) return t end
game             = setmetatable({}, {__index=function() return function() end end})
workspace        = game
script           = {}
Players          = {LocalPlayer={Name="Player",UserId=1}}
RunService       = {Heartbeat={Connect=function()end}}
UserInputService = {}
HttpService      = {JSONDecode=function() return {} end}
Instance         = {new=function() return setmetatable({},{__index=function()return function()end end}) end}
Vector3          = {new=function(...) return {} end}
CFrame           = {new=function(...) return {} end}
Color3           = {new=function(...) return {} end, fromRGB=function(...) return {} end}
UDim2            = {new=function(...) return {} end}
Enum             = setmetatable({},{__index=function() return setmetatable({},{__index=function() return 0 end}) end})
tick             = function() return 0 end
time             = function() return 0 end
wait             = function(n) return n or 0 end
spawn            = function() end
delay            = function() end
warn             = function() end
print            = function() end
error            = function(e) end
assert           = function(v,m) if not v then error(m or "assert") end return v end
shared           = {}
_G.game          = game
_G.workspace     = workspace
identifyexecutor = function() return "synapse","2.0" end
checkcaller      = function() return true end
writefile        = function() end
readfile         = function() return "" end
isfile           = function() return false end
makefolder       = function() end
request          = function() return {Body="",StatusCode=200} end
Drawing          = setmetatable({},{__index=function() return function() end end})
syn              = {protect_gui=function()end}
debug            = {traceback=function() return "" end}
if not bit then
  bit = {}
  bit.bxor=function(a,b) local r,p=0,1 while a>0 or b>0 do if a%2~=b%2 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end
  bit.band=function(a,b) local r,p=0,1 while a>0 and b>0 do if a%2==1 and b%2==1 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end
  bit.bor =function(a,b) local r,p=0,1 while a>0 or b>0 do if a%2==1 or b%2==1 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end
  bit.bnot=function(a) return -a-1 end
  bit.rshift=function(a,b) return math.floor(a/(2^b)) end
  bit.lshift=function(a,b) return math.floor(a*(2^b)) end
  bit32 = bit
end
coroutine.wrap   = coroutine.wrap   or function(f) return f end
coroutine.create = coroutine.create or function(f) return f end
table.pack   = table.pack   or function(...) return {n=select('#',...), ...} end
table.unpack = table.unpack or unpack
"""

def sandbox_real_lua(source, timeout=8):
    captured = []
    with tempfile.TemporaryDirectory() as tmpdir:
        outdir_escaped = tmpdir.replace('\\', '\\\\').replace('"', '\\"')
        hook = REAL_LUA_HOOK.replace('{OUTDIR}', f'"{outdir_escaped}"')
        full_script = hook + '\n' + source
        script_path = os.path.join(tmpdir, 'script.lua')
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(full_script)
        try:
            subprocess.run([LUA_BIN, script_path], timeout=timeout, capture_output=True, cwd=tmpdir)
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            return None, 'lua5.1 not found'
        except Exception as e:
            return None, str(e)
        i = 1
        while True:
            p = os.path.join(tmpdir, f'layer_{i}.lua')
            if not os.path.exists(p): break
            with open(p, 'r', encoding='utf-8', errors='replace') as f:
                data = f.read()
            if data.strip():
                captured.append(data)
            i += 1
    return captured, None

# ========== AI post‑processing ==========

async def ai_clean(code):
    if not ANTHROPIC_KEY:
        return code
    prompt = (
        "You are a Lua reverse engineer. Below is deobfuscated Lua. "
        "Rename cryptic variable names to meaningful names based on context. "
        "Add brief comments explaining each section. "
        "Preserve all logic exactly. Return ONLY Lua code, no markdown.\n\n"
        + code[:3500]
    )
    try:
        import httpx
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(
                'https://api.anthropic.com/v1/messages',
                headers={
                    'x-api-key': ANTHROPIC_KEY,
                    'anthropic-version': '2023-06-01',
                    'content-type': 'application/json'
                },
                json={
                    'model': 'claude-sonnet-4-20250514',
                    'max_tokens': 2048,
                    'messages': [{'role': 'user', 'content': prompt}]
                }
            )
            result = r.json()['content'][0]['text']
            if len(code) > 3500:
                result += '\n\n' + code[3500:]
            return result
    except:
        return code

# ========== deobfuscation pipeline ==========

def deobfuscate_engine(source):
    obf_type = detect_obfuscator(source)
    # static clean first
    cleaned = static_clean(source)
    layers = 0
    final = cleaned
    # attempt Lupa sandbox
    captured = sandbox_lupa(cleaned, timeout=6)
    if captured:
        best = max(captured, key=len)
        if len(best.strip()) > 10 and best != cleaned:
            final = best
            layers += 1
            # deeper layers
            deeper = sandbox_lupa(final, timeout=6)
            if deeper:
                best2 = max(deeper, key=len)
                if best2 != final and len(best2.strip()) > 10:
                    final = best2
                    layers += 1
    # if no layers, try real Lua subprocess
    if layers == 0:
        real_captured, err = sandbox_real_lua(cleaned, timeout=8)
        if real_captured:
            best = max(real_captured, key=len)
            if len(best.strip()) > 10 and best != cleaned:
                final = best
                layers += 1
    # static clean + beautify the final result
    final = static_clean(final)
    final = beautify(final)
    constants = extract_constants(source)
    return final, obf_type, layers, constants

# ========== Flask endpoints ==========

@app.route('/deobfuscate', methods=['POST'])
def deobfuscate_route():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file'}), 400
    file = request.files['file']
    try:
        text = file.read().decode('utf-8')
    except:
        try:
            text = file.read().decode('latin-1')
        except:
            return jsonify({'success': False, 'error': 'Decode failed'}), 400
    use_ai = '--ai' in (request.form.get('flags', '') or '')
    final, obf_type, layers, constants = deobfuscate_engine(text)
    if use_ai and ANTHROPIC_KEY:
        final = asyncio.run(ai_clean(final))
    return jsonify({
        'success': True,
        'code': final,
        'obfuscator': obf_type,
        'layers': layers,
        'constants': constants,
        'ai': use_ai and bool(ANTHROPIC_KEY)
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})
