import discord
import re
import io
import os
import asyncio
import struct
import base64
import subprocess
import tempfile
import httpx
from discord.ext import commands

TOKEN = os.environ['DISCORD_BOT_TOKEN']
ANTHROPIC_KEY = os.environ.get('ANTHROPIC_API_KEY', '')

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

LUA_BIN = os.environ.get('LUA_BIN', 'lua5.1')

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
    'obfuscated': [r'string\.char\s*\(', r'\\x[0-9a-fA-F]{2}'],
}

def detect_obfuscator(text):
    scores = {}
    for name, pats in OBFUSCATOR_PATTERNS.items():
        s = sum(1 for p in pats if re.search(p, text, re.IGNORECASE))
        if s:
            scores[name] = s
    return max(scores, key=lambda k: scores[k]) if scores else 'generic'

class BytecodeParser:
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.strings = []
        self.numbers = []

    def u8(self):
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u32(self):
        v = struct.unpack_from('<I', self.data, self.pos)[0]
        self.pos += 4
        return v

    def f64(self):
        v = struct.unpack_from('<d', self.data, self.pos)[0]
        self.pos += 8
        return v

    def lstring(self):
        n = self.u32()
        if n == 0:
            return ''
        s = self.data[self.pos:self.pos+n-1].decode('utf-8', errors='replace')
        self.pos += n
        return s

    def proto(self):
        self.lstring()
        self.u32()
        self.u32()
        self.u8()
        self.u8()
        self.u8()
        self.u8()
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
            self.lstring()
            self.u32()
            self.u32()
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

def static_decode(code):
    code = re.sub(r'\\x([0-9a-fA-F]{2})',
                  lambda m: chr(int(m.group(1), 16)), code)
    code = re.sub(r'\\(\d{1,3})',
                  lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)

    def sc(m):
        nums = re.findall(r'\d+', m.group(1))
        try:
            return '"' + ''.join(chr(int(n)) for n in nums if int(n) < 256) + '"'
        except:
            return m.group(0)
    code = re.sub(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', sc, code)

    def fold(m):
        try:
            a, op, b = float(m.group(1)), m.group(2), float(m.group(3))
            r = {'+': a+b, '-': a-b, '*': a*b,
                 '/': a/b if b else None,
                 '%': a%b if b else None}.get(op)
            if r is None:
                return m.group(0)
            return str(int(r)) if r == int(r) else str(r)
        except:
            return m.group(0)

    parts = re.split(r'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')', code)
    code = ''.join(
        re.sub(r'\b(\d+(?:\.\d+)?)\s*([+\-*/%])\s*(\d+(?:\.\d+)?)\b', fold, p)
        if i % 2 == 0 else p
        for i, p in enumerate(parts)
    )
    code = re.sub(r'if\s+false\s+then.*?end', '', code, flags=re.DOTALL)
    code = re.sub(r'while\s+false\s+do.*?end', '', code, flags=re.DOTALL)
    return code

def beautify(code):
    out, indent = [], 0
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

HOOK_TEMPLATE = """
local __captured = {}
local __outdir   = {OUTDIR}
local __real_ls  = loadstring
local __real_l   = load

local function __hook(code, ...)
  if type(code) == "string" and #code > 5 then
    local n = #__captured + 1
    __captured[n] = code
    local f = io.open(__outdir .. "/layer_" .. n .. ".lua", "w")
    if f then f:write(code) f:close() end
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

def sandbox_exec(source, timeout=8):
    captured = []
    with tempfile.TemporaryDirectory() as tmpdir:
        outdir_escaped = tmpdir.replace('\\', '\\\\').replace('"', '\\"')
        hook = HOOK_TEMPLATE.replace('{OUTDIR}', f'"{outdir_escaped}"')
        full_script = hook + '\n' + source

        script_path = os.path.join(tmpdir, 'script.lua')
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(full_script)

        try:
            subprocess.run(
                [LUA_BIN, script_path],
                timeout=timeout,
                capture_output=True,
                cwd=tmpdir
            )
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            return None, 'lua5.1 binary not found - install lua5.1 on the server'
        except Exception as e:
            return [], str(e)

        i = 1
        while True:
            layer_path = os.path.join(tmpdir, f'layer_{i}.lua')
            if not os.path.exists(layer_path):
                break
            with open(layer_path, 'r', encoding='utf-8', errors='replace') as f:
                data = f.read()
            if data.strip():
                captured.append(data)
            i += 1

    return captured, None

def peel_layers(source, max_layers=8, timeout=8):
    current = source
    count   = 0
    previews = []

    for _ in range(max_layers):
        captured, err = sandbox_exec(current, timeout)
        if captured is None:
            return current, count, previews, err
        if not captured:
            break
        best = max(captured, key=len)
        if len(best.strip()) < 10 or best == current:
            break
        previews.append(best[:100].replace('\n', ' '))
        current = best
        count  += 1

    return current, count, previews, None

async def ai_clean(code):
    if not ANTHROPIC_KEY:
        return code
    prompt = (
        "You are a Lua reverse engineer. Below is deobfuscated Lua. "
        "Rename cryptic variables to meaningful names based on context. "
        "Add brief comments explaining each section. "
        "Preserve all logic exactly. Return ONLY Lua code, no markdown.\n\n"
        + code[:3500]
    )
    try:
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

@bot.command(name='deobf')
async def deobf(ctx, flags: str = ''):
    use_ai    = '--ai'   in flags
    scan_only = '--scan' in flags

    if not ctx.message.attachments:
        return await ctx.send(
            '**Usage:**\n'
            '`!deobf` - deobfuscate `.lua` file\n'
            '`!deobf --ai` - deobf + AI rename variables\n'
            '`!deobf --scan` - scan only, no execution'
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

    obf  = detect_obfuscator(text)
    em   = discord.Embed(title=f'Detected: {obf}', color=0x3498db)
    em.add_field(name='File', value=att.filename, inline=True)
    em.add_field(name='Size', value=f'{len(text):,} chars', inline=True)
    msg  = await ctx.send(embed=em)

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
        em.title = f'Scan done: {obf}'
        em.color  = 0x2ecc71
        await msg.edit(embed=em)
        return

    em.description = 'Running Lua 5.1 sandbox...'
    await msg.edit(embed=em)

    result, layers, previews, err = await asyncio.to_thread(peel_layers, text, 8, 8)

    if err:
        em.description = f'Error: {err}'
        em.color = 0xe74c3c
        await msg.edit(embed=em)
        return

    if layers > 0:
        result = static_decode(result)
        result = beautify(result)
        em.description = f'Peeled {layers} layer(s) via loadstring intercept.'
        em.color       = 0x2ecc71
        if previews:
            em.add_field(
                name='Layers captured',
                value='\n'.join(f'{i+1}: {p}...' for i, p in enumerate(previews))[:900],
                inline=False
            )
    else:
        em.description = 'Sandbox got nothing - applying static transforms only.'
        em.color       = 0xe67e22
        await msg.edit(embed=em)
        result = static_decode(text)
        result = beautify(result)
        em.add_field(
            name='Note',
            value=(
                'Script likely uses a custom VM (Luraph 3, IronBrew 2/3). '
                'These compile Lua into a private instruction set - '
                'no automated tool can fully reverse this. '
                'String decoding and formatting were applied.'
            ),
            inline=False
        )

    if use_ai and ANTHROPIC_KEY:
        em.description += '\nAI rename pass running...'
        await msg.edit(embed=em)
        result = await ai_clean(result)
        em.add_field(name='AI', value='Variables renamed + comments added', inline=True)
    elif use_ai:
        em.add_field(name='AI', value='No ANTHROPIC_API_KEY env var set', inline=True)

    await msg.edit(embed=em)
    await ctx.send(
        f'Done - {layers} layer(s) | {len(result):,} chars',
        file=discord.File(fp=io.StringIO(result), filename=f'deobf_{att.filename}')
    )

@bot.command(name='constants')
async def constants_cmd(ctx):
    if not ctx.message.attachments:
        return await ctx.send('Attach a file.')
    raw    = await ctx.message.attachments[0].read()
    text   = raw.decode('latin-1', errors='replace')
    consts = extract_constants(text)
    if not consts:
        return await ctx.send('No Lua 5.1 bytecode found.')
    out  = '-- Strings:\n' + ''.join(f'--   {repr(s)}\n' for s in consts['strings'])
    out += '-- Numbers:\n' + ''.join(f'--   {n}\n' for n in consts['numbers'])
    if 'xor_key' in consts:
        out += f'-- XOR key: {consts["xor_key"]}\n'
    await ctx.send(file=discord.File(fp=io.StringIO(out), filename='constants.lua'))

@bot.command(name='info')
async def info_cmd(ctx):
    em = discord.Embed(title='Lua Deobfuscator', color=0x3498db)
    em.add_field(name='Commands', value=(
        '`!deobf` - deobfuscate `.lua`\n'
        '`!deobf --ai` - deobf + AI rename\n'
        '`!deobf --scan` - scan + constants only\n'
        '`!constants` - dump bytecode constants'
    ), inline=False)
    em.add_field(name='Coverage', value=(
        'WeareDevs, IronBrew 1, basic Luraph - real Lua 5.1 sandbox\n'
        'String encoding, nested loadstring up to 8 layers\n'
        'Bytecode constant extraction\n'
        'IronBrew 2/3, modern Luraph - static decode only\n'
        'Full custom VM - not reversible automatically'
    ), inline=False)
    em.add_field(name='Requirements', value='lua5.1 binary must be installed on the server', inline=False)
    await ctx.send(embed=em)

@bot.event
async def on_ready():
    try:
        subprocess.run([LUA_BIN, '-v'], capture_output=True, timeout=2)
        print(f'Ready: {bot.user} | Lua binary: {LUA_BIN} OK')
    except FileNotFoundError:
        print(f'Ready: {bot.user} | WARNING: {LUA_BIN} not found - install lua5.1')

if __name__ == '__main__':
    bot.run(TOKEN)
