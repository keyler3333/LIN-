import discord
import re
import io
import os
import asyncio
import struct
import base64
import httpx
from multiprocessing import Process, Queue
from discord.ext import commands

TOKEN = os.environ[‘DISCORD_BOT_TOKEN’]
ANTHROPIC_KEY = os.environ.get(‘ANTHROPIC_API_KEY’, ‘’)

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=’!’, intents=intents, help_command=None)

OBFUSCATOR_PATTERNS = {
‘luraph’:     [r’loadstring\s*(\s*(function’, r’bytecode\s*=\s*[”'][A-Za-z0-9+/=]{50,}’],
‘moonsec’:    [r’local\s+\w+\s*=\s*{[\d\s,]{20,}}’, r’*moon\s*=\s*function’],
‘ironbrew’:   [r’local\s+\w+\s*=\s*{\s*”\x[0-9a-fA-F]{2}’, r’getfenv\s*(\s*)\s*[’, r’\bIronBrew\b’],
‘ironbrew2’:  [r’while\s+true\s+do\s+local\s+\w+\s*=\s*\w+[\w+]’, r’local\s+\w+,\s*\w+,\s*\w+\s*=\s*\w+\s*&’],
‘wearedevs’:  [r’show*\w+\s*=\s*function’, r’getfenv\s*(\s*)’, r’string.reverse\s*(’],
‘prometheus’: [r’Prometheus’, r’number_to_bytes’],
‘custom_vm’:  [r’mkexec’, r’constTags’, r’protoFormats’],
‘synapse’:    [r’syn.\w+\s*=\s*’, r’syn.protect’],
‘luaarmor’:   [r’__*armor*’, r’LuaArmor’],
‘vmprotect’:  [r’local\s+f\s*=\s*loadstring’],
‘psu’:        [r’ProtectedString’, r’ByteCode\s*=’],
‘aurora’:     [r’__aurora\s*=\s*’, r’Aurora\s*=\s*’],
‘sentinel’:   [r’Sentinel\s*=\s*’],
‘obfuscated’: [r’string.char\s*(’, r’\x[0-9a-fA-F]{2}’],
}

def detect_obfuscator(text):
scores = {}
for name, pats in OBFUSCATOR_PATTERNS.items():
score = sum(1 for p in pats if re.search(p, text, re.IGNORECASE))
if score:
scores[name] = score
if not scores:
return ‘generic’
return max(scores, key=lambda k: scores[k])

class BytecodeParser:
def **init**(self, data):
self.data = data
self.pos = 0
self.strings = []
self.numbers = []

```
def u8(self):
    v = self.data[self.pos]; self.pos += 1; return v

def u32(self):
    v = struct.unpack_from('<I', self.data, self.pos)[0]; self.pos += 4; return v

def double(self):
    v = struct.unpack_from('<d', self.data, self.pos)[0]; self.pos += 8; return v

def lua_string(self):
    size = self.u32()
    if size == 0:
        return ''
    s = self.data[self.pos:self.pos + size - 1].decode('utf-8', errors='replace')
    self.pos += size
    return s

def parse_proto(self):
    self.lua_string(); self.u32(); self.u32()
    self.u8(); self.u8(); self.u8(); self.u8()
    self.pos += self.u32() * 4
    for _ in range(self.u32()):
        t = self.u8()
        if t == 1:
            self.u8()
        elif t == 3:
            self.numbers.append(self.double())
        elif t == 4:
            s = self.lua_string()
            if s:
                self.strings.append(s)
    for _ in range(self.u32()):
        self.parse_proto()
    self.pos += self.u32() * 4
    for _ in range(self.u32()):
        self.lua_string(); self.u32(); self.u32()
    for _ in range(self.u32()):
        self.lua_string()

def parse(self):
    if self.data[:4] != b'\x1bLua':
        return False
    self.pos = 12
    try:
        self.parse_proto()
        return True
    except:
        return False
```

def extract_constants(source):
candidates = []
try:
candidates.append(source.encode(‘latin-1’))
except:
pass
for m in re.finditer(r’[”']([A-Za-z0-9+/=]{60,})[”']’, source):
try:
candidates.append(base64.b64decode(m.group(1) + ‘==’))
except:
pass
for data in candidates:
if len(data) < 16:
continue
if data[:4] == b’\x1bLua’:
p = BytecodeParser(data)
if p.parse():
return {‘strings’: p.strings, ‘numbers’: p.numbers}
for key in range(256):
if bytes(b ^ key for b in data[:4]) == b’\x1bLua’:
full = bytes(b ^ key for b in data)
p = BytecodeParser(full)
if p.parse():
return {‘strings’: p.strings, ‘numbers’: p.numbers, ‘xor_key’: key}
return None

def _fold(m):
try:
a, op, b = float(m.group(1)), m.group(2), float(m.group(3))
r = {’+’: a+b, ‘-’: a-b, ‘*’: a*b,
‘/’: a/b if b else None, ‘%’: a%b if b else None}.get(op)
if r is None:
return m.group(0)
return str(int(r)) if r == int(r) else str(r)
except:
return m.group(0)

def static_clean(code):
code = re.sub(r’\x([0-9a-fA-F]{2})’, lambda m: chr(int(m.group(1), 16)), code)
code = re.sub(r’\(\d{1,3})’, lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)
code = re.sub(r’string.char\s*(\s*([\d,\s]+)\s*)’,
lambda m: ‘”’ + ‘’.join(chr(int(n)) for n in re.findall(r’\d+’, m.group(1)) if int(n) < 256) + ‘”’, code)
parts = re.split(r’(”(?:[^”\]|\.)*”|'(?:[^'\]|\.)*')’, code)
code = ‘’.join(
re.sub(r’\b(\d+(?:.\d+)?)\s*([+-*/%])\s*(\d+(?:.\d+)?)\b’, _fold, p) if i % 2 == 0 else p
for i, p in enumerate(parts)
)
code = re.sub(r’if\s+false\s+then.*?end’, ‘’, code, flags=re.DOTALL)
code = re.sub(r’while\s+false\s+do.*?end’, ‘’, code, flags=re.DOTALL)
return code

def beautify(code):
out, indent = [], 0
for line in code.split(’\n’):
s = line.strip()
if not s:
out.append(’’); continue
if re.match(r’^(end\b|else\b|elseif\b|until\b)’, s):
indent = max(0, indent - 1)
out.append(’    ’ * indent + s)
if re.match(r’^(if\b|for\b|while\b|repeat\b|do\b)’, s) and not s.endswith(‘end’):
indent += 1
if re.match(r’^(function\b|local\s+function\b)’, s):
indent += 1
return ‘\n’.join(out)

LUA_SANDBOX = “””
game             = setmetatable({}, {__index=function() return function() end end})
workspace        = game
script           = setmetatable({}, {__index=function() return “” end})
Players          = {LocalPlayer={Name=“Player”,UserId=1,Character={}}}
RunService       = {Heartbeat={Connect=function() end},RenderStepped={Connect=function() end}}
UserInputService = setmetatable({}, {__index=function() return function() end end})
TweenService     = setmetatable({}, {__index=function() return function() end end})
HttpService      = {JSONDecode=function() return {} end,JSONEncode=function() return “{}” end}
CFrame           = {new=function(…) return {} end,Angles=function(…) return {} end}
Vector3          = {new=function(…) return {} end}
Vector2          = {new=function(…) return {} end}
Color3           = {new=function(…) return {} end,fromRGB=function(…) return {} end}
UDim2            = {new=function(…) return {} end}
UDim             = {new=function(…) return {} end}
Enum             = setmetatable({}, {__index=function() return setmetatable({},{__index=function() return 0 end}) end})
Instance         = {new=function() return setmetatable({},{__index=function() return function() end end}) end}
Drawing          = setmetatable({}, {__index=function() return function() end end})
debug            = {traceback=function() return “” end,getinfo=function() return {} end,getupvalue=function() end,setupvalue=function() end}
syn              = {protect_gui=function() end,queue_on_teleport=function() end,request=function() return {Body=””,StatusCode=200} end}
rconsole         = {print=function() end,clear=function() end,settitle=function() end}
writefile        = function() end
readfile         = function() return “” end
isfile           = function() return false end
isfolder         = function() return false end
makefolder       = function() end
listfiles        = function() return {} end
delfile          = function() end
request          = function() return {Body=””,StatusCode=200,Success=true} end
http             = {request=function() return {Body=””,StatusCode=200} end}
identifyexecutor = function() return “synapse”,“2.0” end
getexecutorname  = function() return “synapse” end
checkcaller      = function() return true end
isrbxactive      = function() return true end
gethiddenproperty= function() return nil,false end
sethiddenproperty= function() end
getrawmetatable  = getmetatable
setrawmetatable  = setmetatable
hookmetamethod   = function() end
hookfunction     = function(a,b) return a end
newcclosure      = function(f) return f end
clonefunction    = function(f) return f end
isexecutorclosure= function() return false end
tick             = function() return 0 end
time             = function() return 0 end
elapsedtime      = function() return 0 end
wait             = function(n) return n or 0 end
spawn            = function(f) end
delay            = function(t,f) end
print            = function() end
warn             = function() end
error            = function(e) end
assert           = function(v,m) if not v then error(m or “assertion failed”) end return v end
select           = select
ipairs           = ipairs
pairs            = pairs
next             = next
tostring         = tostring
tonumber         = tonumber
type             = type
rawget           = rawget
rawset           = rawset
rawequal         = rawequal
rawlen           = rawlen
setmetatable     = setmetatable
getmetatable     = getmetatable
shared           = {}
_VERSION         = “Lua 5.1”

bit = {}
bit.bxor = function(a,b)
local r,p=0,1
while a>0 or b>0 do
if a%2~=b%2 then r=r+p end
a=math.floor(a/2); b=math.floor(b/2); p=p*2
end
return r
end
bit.band = function(a,b)
local r,p=0,1
while a>0 and b>0 do
if a%2==1 and b%2==1 then r=r+p end
a=math.floor(a/2); b=math.floor(b/2); p=p*2
end
return r
end
bit.bor = function(a,b)
local r,p=0,1
while a>0 or b>0 do
if a%2==1 or b%2==1 then r=r+p end
a=math.floor(a/2); b=math.floor(b/2); p=p*2
end
return r
end
bit.bnot   = function(a) return -a-1 end
bit.rshift = function(a,b) return math.floor(a/(2^b)) end
bit.lshift = function(a,b) return math.floor(a*(2^b)) end
bit.arshift= function(a,b) return math.floor(a/(2^b)) end
bit.btest  = function(a,b) return bit.band(a,b)~=0 end
bit.tobit  = function(a) return a end
bit.tohex  = function(a) return string.format(”%x”,a) end
bit32 = bit

coroutine = {
create =function(f) return f end,
resume =function(f,…) return pcall(f,…) end,
yield  =function(…) return … end,
wrap   =function(f) return f end,
status =function() return “dead” end,
running=function() return nil end
}

string.byte    = string.byte
string.char    = string.char
string.sub     = string.sub
string.rep     = string.rep
string.len     = string.len
string.find    = string.find
string.gsub    = string.gsub
string.match   = string.match
string.gmatch  = string.gmatch
string.format  = string.format
string.lower   = string.lower
string.upper   = string.upper
string.reverse = string.reverse
string.dump    = function() return “” end
string.split   = function(s,sep) local t={} for p in s:gmatch(”[^”..sep..”]+”) do t[#t+1]=p end return t end

math.abs   = math.abs
math.floor = math.floor
math.ceil  = math.ceil
math.max   = math.max
math.min   = math.min
math.sqrt  = math.sqrt
math.random= math.random
math.huge  = math.huge
math.pi    = math.pi
math.sin   = math.sin
math.cos   = math.cos
math.tan   = math.tan
math.log   = math.log
math.exp   = math.exp
math.fmod  = math.fmod
math.modf  = math.modf
math.pow   = function(a,b) return a^b end
math.log10 = function(a) return math.log(a)/math.log(10) end

table.insert = table.insert
table.remove = table.remove
table.sort   = table.sort
table.concat = table.concat
table.unpack = table.unpack or unpack
table.pack   = table.pack or function(…) return {n=select(’#’,…), …} end
table.move   = table.move or function(a,f,e,t,b) b=b or a for i=f,e do b[t+(i-f)]=a[i] end return b end

local _env = {
string=string, math=math, table=table, bit=bit, bit32=bit32,
coroutine=coroutine, pairs=pairs, ipairs=ipairs, select=select, next=next,
tostring=tostring, tonumber=tonumber, type=type,
rawget=rawget, rawset=rawset, rawequal=rawequal, rawlen=rawlen,
setmetatable=setmetatable, getmetatable=getmetatable,
unpack=table.unpack, loadstring=loadstring, load=load,
pcall=pcall, xpcall=xpcall, error=error, assert=assert,
print=print, warn=warn, game=game, workspace=workspace,
script=script, tick=tick, time=time, wait=wait, spawn=spawn,
shared=shared, Drawing=Drawing, syn=syn, bit=bit, bit32=bit32,
writefile=writefile, readfile=readfile, request=request,
identifyexecutor=identifyexecutor, checkcaller=checkcaller,
hookfunction=hookfunction, newcclosure=newcclosure,
Instance=Instance, Vector3=Vector3, Vector2=Vector2,
CFrame=CFrame, Color3=Color3, UDim2=UDim2, Enum=Enum,
Players=Players, RunService=RunService, HttpService=HttpService,
debug=debug, _VERSION=_VERSION
}
getfenv = function(n) return _env end
setfenv = function(n,t)
for k,v in pairs(t) do _env[k]=v end
return t
end
_G   = _env
_ENV = _env
“””

def _worker(source, q):
try:
from lupa import LuaRuntime

```
    captured = []

    lua = LuaRuntime(unpack_returned_tuples=True)

    for name in ['io', 'os', 'require', 'dofile', 'loadfile',
                 'package', 'collectgarbage', 'newproxy', 'module']:
        try:
            lua.execute(f"{name} = nil")
        except:
            pass

    lua.execute(LUA_SANDBOX)

    def safe_ls(code, *args):
        if callable(code):
            chunks = []
            try:
                while True:
                    c = code()
                    if not c:
                        break
                    chunks.append(str(c))
            except:
                pass
            code = ''.join(chunks)
        s = str(code) if code else ''
        if len(s.strip()) > 5:
            captured.append(s)
        return lua.eval("function(...) end")

    lua.globals()['loadstring'] = safe_ls
    lua.globals()['load']       = safe_ls

    try:
        lua.execute(source)
    except:
        pass

    q.put({'ok': True, 'captured': captured})

except Exception as e:
    q.put({'ok': False, 'captured': [], 'err': str(e)})
```

def sandbox_run(source, timeout=7):
q = Queue()
p = Process(target=_worker, args=(source, q), daemon=True)
p.start()
p.join(timeout)
if p.is_alive():
p.kill()
p.join()
return [], ‘timeout’
if not q.empty():
r = q.get()
return r.get(‘captured’, []), r.get(‘err’)
return [], ‘no_response’

def peel_layers(source, max_layers=8, timeout=7):
current = source
count   = 0
layers  = []
for _ in range(max_layers):
captured, err = sandbox_run(current, timeout)
if not captured:
break
best = max(captured, key=len)
if len(best.strip()) < 10 or best == current:
break
layers.append(best[:100].replace(’\n’, ’ ’))
current = best
count  += 1
return current, count, layers

async def ai_clean(code):
if not ANTHROPIC_KEY:
return code
prompt = (
“You are a Lua reverse engineer. Below is deobfuscated Lua. “
“Rename cryptic variables to meaningful names. “
“Add brief comments explaining each section. “
“Preserve all logic. Return only Lua code, no markdown.\n\n”
+ code[:3500]
)
try:
async with httpx.AsyncClient(timeout=30) as c:
r = await c.post(
‘https://api.anthropic.com/v1/messages’,
headers={‘x-api-key’: ANTHROPIC_KEY,
‘anthropic-version’: ‘2023-06-01’,
‘content-type’: ‘application/json’},
json={‘model’: ‘claude-sonnet-4-20250514’, ‘max_tokens’: 2048,
‘messages’: [{‘role’: ‘user’, ‘content’: prompt}]}
)
result = r.json()[‘content’][0][‘text’]
if len(code) > 3500:
result += ‘\n\n’ + code[3500:]
return result
except:
return code

@bot.command(name=‘deobf’)
async def deobf(ctx, flags: str = ‘’):
use_ai    = ‘–ai’   in flags
scan_only = ‘–scan’ in flags

```
if not ctx.message.attachments:
    return await ctx.send(
        '**Usage:**\n'
        '`!deobf` — deobfuscate `.lua` file\n'
        '`!deobf --ai` — deobf + AI rename variables\n'
        '`!deobf --scan` — scan only, no execution'
    )

att = ctx.message.attachments[0]
if not att.filename.lower().endswith(('.lua', '.txt', '.luac')):
    return await ctx.send('Attach a `.lua`, `.luac`, or `.txt` file.')

raw = await att.read()
try:
    text = raw.decode('utf-8')
except:
    try:
        text = raw.decode('latin-1')
    except:
        return await ctx.send('Cannot decode file.')

obf = detect_obfuscator(text)
em  = discord.Embed(title=f'Detected: `{obf}`', color=0x3498db)
em.add_field(name='File', value=att.filename, inline=True)
em.add_field(name='Size', value=f'{len(text):,} chars', inline=True)
msg = await ctx.send(embed=em)

consts = extract_constants(text)
if consts:
    preview = ', '.join(repr(s) for s in consts['strings'][:10])
    em.add_field(
        name='Bytecode constants',
        value=f"Strings: {preview or 'none'}\nXOR key: {consts.get('xor_key','none')}",
        inline=False
    )
    await msg.edit(embed=em)

if scan_only:
    em.title = f'Scan done: `{obf}`'
    em.color = 0x2ecc71
    await msg.edit(embed=em)
    return

em.description = 'Running sandbox...'
await msg.edit(embed=em)

result, layers, previews = await asyncio.to_thread(peel_layers, text, 8, 7)

if layers > 0:
    result = static_clean(result)
    result = beautify(result)
    em.description = f'Peeled {layers} layer(s).'
    em.color       = 0x2ecc71
    if previews:
        em.add_field(
            name='Layers',
            value='\n'.join(f'`{i+1}:` {p}...' for i, p in enumerate(previews))[:900],
            inline=False
        )
else:
    em.description = 'Sandbox got nothing — static clean only.'
    em.color       = 0xe67e22
    await msg.edit(embed=em)
    result = static_clean(text)
    result = beautify(result)
    em.add_field(
        name='Note',
        value='Custom VM or sandbox crash. Cannot fully reverse automatically.',
        inline=False
    )

if use_ai and ANTHROPIC_KEY:
    em.description += '\nAI pass running...'
    await msg.edit(embed=em)
    result = await ai_clean(result)
    em.add_field(name='AI', value='Done', inline=True)
elif use_ai:
    em.add_field(name='AI', value='No API key set', inline=True)

await msg.edit(embed=em)
await ctx.send(
    f'**Done** — {layers} layer(s) | {len(result):,} chars',
    file=discord.File(fp=io.StringIO(result), filename=f'deobf_{att.filename}')
)
```

@bot.command(name=‘constants’)
async def constants_cmd(ctx):
if not ctx.message.attachments:
return await ctx.send(‘Attach a file.’)
raw    = await ctx.message.attachments[0].read()
text   = raw.decode(‘latin-1’, errors=‘replace’)
consts = extract_constants(text)
if not consts:
return await ctx.send(‘No Lua 5.1 bytecode found.’)
out = ‘– Strings:\n’ + ‘’.join(f’–   {repr(s)}\n’ for s in consts[‘strings’])
out += ‘– Numbers:\n’ + ‘’.join(f’–   {n}\n’ for n in consts[‘numbers’])
if ‘xor_key’ in consts:
out += f’– XOR key: {consts[“xor_key”]}\n’
await ctx.send(file=discord.File(fp=io.StringIO(out), filename=‘constants.lua’))

@bot.command(name=‘info’)
async def info_cmd(ctx):
em = discord.Embed(title=‘Lua Deobfuscator’, color=0x3498db)
em.add_field(name=‘Commands’, value=(
‘`!deobf` — deobfuscate `.lua`\n’
‘`!deobf --ai` — deobf + AI rename\n’
‘`!deobf --scan` — scan only\n’
‘`!constants` — dump bytecode constants’
), inline=False)
em.add_field(name=‘Coverage’, value=(
‘✅ WeareDevs, IronBrew 1, basic Luraph\n’
‘✅ String encoding, loadstring layers\n’
‘✅ Bytecode constant extraction\n’
‘⚠️ IronBrew 2/3, modern Luraph — static only\n’
‘❌ Full custom VM — not reversible automatically’
), inline=False)
await ctx.send(embed=em)

@bot.event
async def on_ready():
print(f’Ready: {bot.user}’)

if **name** == ‘**main**’:
bot.run(TOKEN)
