import discord
import re
import io
import os
import asyncio
import struct
import base64
import json
import time
import httpx
from multiprocessing import e Process, Queue
from discord.ext import commands

TOKEN = os.environ['DISCORD_BOT_TOKEN']
ANTHROPIC_KEY = os.environ.get('ANTHROPIC_API_KEY', '')

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

OBFUSCATOR_PATTERNS = {
    'luraph': [
        r'loadstring\s*\(\s*\(function',
        r'bytecode\s*=\s*["\'][A-Za-z0-9+/=]{50,}',
        r'local\s+\w+\s*=\s*\{[^}]{0,30}\}\s*local\s+\w+\s*=\s*\{',
        r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}',
    ],
    'moonsec': [
        r'local\s+\w+\s*=\s*\{[\d\s,]{20,}\}',
        r'_moon\s*=\s*function',
        r'moon_\w+\s*=',
    ],
    'ironbrew': [
        r'local\s+\w+\s*=\s*\{\s*"\\x[0-9a-fA-F]{2}',
        r'getfenv\s*\(\s*\)\s*\[',
        r'\bIronBrew\b',
        r'bit\.bxor',
    ],
    'ironbrew2': [
        r'local\s+\w+\s*=\s*\{?\d+',
        r'while\s+true\s+do\s+local\s+\w+\s*=\s*\w+\[\w+\]',
        r'local\s+\w+,\s*\w+,\s*\w+\s*=\s*\w+\s*&',
    ],
    'wearedevs': [
        r'show_\w+\s*=\s*function',
        r'getfenv\s*\(\s*\)',
        r'string\.reverse\s*\(\s*',
        r'local\s+\w+\s*=\s*string\.rep',
    ],
    'prometheus': [
        r'Prometheus',
        r'local\s+\w+\s*=\s*\{\}\s*;\s*local\s+\w+\s*=\s*\{\}',
        r'number_to_bytes',
    ],
    'uglify': [
        r'local\s+[a-zA-Z]\s*=\s*[a-zA-Z]\s*\.\s*[a-zA-Z]',
        r'[a-z]\["[a-z]{1,3}"\]\(',
    ],
    'custom_vm': [
        r'mkexec',
        r'constTags',
        r'protoFormats',
        r'local\s+\w+\s*=\s*\{.*code\s*=\s*\{',
    ],
    'synapse': [
        r'syn\.\w+\s*=\s*',
        r'Bytecode',
        r'syn\.protect',
    ],
    'luaarmor': [
        r'__*armor*',
        r'armor\s*=\s*\{',
        r'LuaArmor',
    ],
    'vmprotect': [
        r'local\s+f\s*=\s*loadstring',
        r'local\s+\w+\s*=\s*\w+\(\w+\(\w+\(\w+\)',
    ],
    'psu': [
        r'ProtectedString',
        r'ByteCode\s*=',
    ],
    'xen': [
        r'Xen\s*=\s*',
        r'Bytecode',
    ],
    'sentinel': [
        r'Sentinel\s*=\s*',
        r'V3',
    ],
    'aurora': [
        r'__aurora\s*=\s*',
        r'Aurora\s*=\s*',
    ],
    'obfuscated': [
        r'local\s+\w+\s*=\s*loadstring',
        r'string\.char\s*\(',
        r'\\x[0-9a-fA-F]{2}',
    ],
    'sk8r': [
        r'sk8r\s*=\s*',
    ],
}

def detect_obfuscator(text):
    scores = {}
    for name, pats in OBFUSCATOR_PATTERNS.items():
        total = sum(1 for p in pats if re.search(p, text, re.IGNORECASE))
        if total > 0:
            scores[name] = total
    if not scores:
        return 'generic'
    best = max(scores, key=lambda k: scores[k])
    return best if scores[best] >= 1 else 'generic'

class BytecodeParser:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.strings = []
        self.numbers = []

    def u8(self):
        v = self.data[self.pos]; self.pos += 1; return v

    def u32(self):
        v = struct.unpack_from('<I', self.data, self.pos)[0]; self.pos += 4; return v

    def double(self):
        v = struct.unpack_from('<d', self.data, self.pos)[0]; self.pos += 8; return v

    def string(self):
        size = self.u32()
        if size == 0:
            return ''
        s = self.data[self.pos:self.pos + size - 1].decode('utf-8', errors='replace')
        self.pos += size
        return s

    def parse_function(self):
        self.string()
        self.u32()
        self.u32()
        self.u8()
        self.u8()
        self.u8()
        self.u8()
        code_n = self.u32()
        self.pos += code_n * 4
        const_n = self.u32()
        for _ in range(const_n):
            t = self.u8()
            if t == 0:
                pass
            elif t == 1:
                self.u8()
            elif t == 3:
                v = self.double()
                self.numbers.append(v)
            elif t == 4:
                s = self.string()
                if s:
                    self.strings.append(s)
        proto_n = self.u32()
        for _ in range(proto_n):
            self.parse_function()
        line_n = self.u32()
        self.pos += line_n * 4
        local_n = self.u32()
        for _ in range(local_n):
            self.string(); self.u32(); self.u32()
        upv_n = self.u32()
        for _ in range(upv_n):
            self.string()

    def parse(self):
        if self.data[:4] != b'\x1bLua':
            return False
        self.pos = 12
        try:
            self.parse_function()
            return True
        except:
            return False

def extract_bytecode_constants(source: str):
    candidates = []
    try:
        raw = source.encode('latin-1')
        candidates.append(raw)
    except:
        pass
    for m in re.finditer(r'[A-Za-z0-9+/=]{60,}', source):
        try:
            candidates.append(base64.b64decode(m.group(0) + '=='))
        except:
            pass
    for m in re.finditer(r'["\']([A-Za-z0-9+/=]{60,})["\']', source):
        try:
            candidates.append(base64.b64decode(m.group(1) + '=='))
        except:
            pass
    for data in candidates:
        if data[:4] == b'\x1bLua':
            p = BytecodeParser(data)
            if p.parse():
                return {'strings': p.strings, 'numbers': p.numbers}
        for key in range(256):
            decrypted = bytes(b ^ key for b in data[:16])
            if decrypted[:4] == b'\x1bLua':
                full = bytes(b ^ key for b in data)
                p = BytecodeParser(full)
                if p.parse():
                    return {'strings': p.strings, 'numbers': p.numbers, 'xor_key': key}
    return None

def decode_escape_sequences(code: str) -> str:
    code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), code)
    code = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)
    code = re.sub(r'\\u\{([0-9a-fA-F]+)\}', lambda m: chr(int(m.group(1), 16)), code)
    return code

def decode_string_char(code: str) -> str:
    def repl(m):
        nums = re.findall(r'\d+', m.group(1))
        try:
            chars = ''.join(chr(int(n)) for n in nums if int(n) < 256)
            return '"' + chars + '"'
        except:
            return m.group(0)
    return re.sub(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', repl, code)

def decode_base64_strings(code: str) -> str:
    def repl(m):
        try:
            decoded = base64.b64decode(m.group(1)).decode('utf-8', errors='replace')
            if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in decoded):
                return '"' + decoded.replace('"', '\\"') + '"'
        except:
            pass
        return m.group(0)
    return re.sub(r'(?:base64\.decode|Base64\.decode)\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']\s*\)', repl, code)

def _fold_match(m):
    try:
        a, op, b = float(m.group(1)), m.group(2), float(m.group(3))
        ops = {'+': a+b, '-': a-b, '*': a*b,
               '/': a/b if b else None, '%': a%b if b else None}
        r = ops.get(op)
        if r is None:
            return m.group(0)
        return str(int(r)) if r == int(r) else str(r)
    except:
        return m.group(0)

def fold_constants(code: str) -> str:
    result = []
    parts = re.split(r'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')', code)
    for i, part in enumerate(parts):
        if i % 2 == 1:
            result.append(part)
        else:
            result.append(re.sub(
                r'\b(\d+(?:\.\d+)?)\s*([+\-*/%])\s*(\d+(?:\.\d+)?)\b',
                _fold_match, part
            ))
    return ''.join(result)

def remove_dead_code(code: str) -> str:
    code = re.sub(r'if\s+false\s+then.*?end', '', code, flags=re.DOTALL)
    code = re.sub(r'do\s+local\s+\w+\s*=\s*\d+\s+\w+\s*=\s*nil\s+end', '', code)
    code = re.sub(r'while\s+false\s+do.*?end', '', code, flags=re.DOTALL)
    return code

def unwrap_loadstring(code: str) -> str:
    for _ in range(15):
        m = re.search(r'loadstring\s*\(\s*["\'](.*?)["\']\s*\)\s*(?:\(\s*\))?', code, re.DOTALL)
        if m:
            inner = m.group(1).replace('\\"', '"').replace("\\'", "'").replace('\\\\', '\\')
            code = code[:m.start()] + inner + code[m.end():]
            continue
        m = re.search(r'loadstring\s*\(\s*(\w+)\s*\)\s*(?:\(\s*\))?', code)
        if m:
            var = m.group(1)
            vm = re.search(rf'\blocal\s+{re.escape(var)}\s*=\s*["\'](.*?)["\']', code)
            if vm:
                inner = vm.group(1).replace('\\"', '"').replace("\\'", "'")
                code = code[:m.start()] + inner + code[m.end():]
                continue
        break
    return code

def beautify_lua(code: str) -> str:
    lines = code.split('\n')
    out = []
    indent = 0
    for line in lines:
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
        if s.endswith('then') or s.endswith('do'):
            pass
    return '\n'.join(out)

def full_static_clean(code: str) -> str:
    code = decode_escape_sequences(code)
    code = decode_string_char(code)
    code = decode_base64_strings(code)
    code = fold_constants(code)
    code = remove_dead_code(code)
    code = unwrap_loadstring(code)
    return code

def _sandbox_worker(source: str, q: Queue, trace: bool = False):
    try:
        from lupa import LuaRuntime
        captured = []

        def safe_loadstring(code, *args):
            if callable(code):
                chunks = []
                while True:
                    chunk = code()
                    if not chunk:
                        break
                    chunks.append(str(chunk))
                code = ''.join(chunks)
            if code and len(str(code).strip()) > 5:
                captured.append(str(code))
            return lua.eval("function(...) end")

        lua = LuaRuntime(unpack_returned_tuples=True)

        for name in ['io','os','require','dofile','loadfile','debug','package',
                     'collectgarbage','newproxy','module']:
            try:
                lua.execute(f"{name} = nil")
            except:
                pass

        lua.globals()['loadstring'] = safe_loadstring
        lua.globals()['load'] = safe_loadstring

        lua.execute("""
            game          = setmetatable({}, {__index = function() return function() end end})
            workspace     = game
            script        = {}
            Players       = {LocalPlayer = {Name="Player", UserId=1}}
            RunService    = {Heartbeat={Connect=function() end}}
            UserInputService = {}
            tick          = function() return 0 end
            time          = function() return 0 end
            wait          = function(n) return n or 0 end
            spawn         = function(f) end
            delay         = function(t, f) end
            print         = function() end
            warn          = function() end
            error         = function(e) end
            assert        = function(v, m) if not v then error(m or 'assertion failed') end return v end

            HttpService   = {JSONDecode=function(s) return {} end, JSONEncode=function(t) return "{}" end}
            TweenService  = {}
            CFrame        = {new=function() return {} end}
            Vector3       = {new=function() return {} end}
            Color3        = {new=function() return {} end, fromRGB=function() return {} end}
            UDim2         = {new=function() return {} end}
            Instance      = {new=function(n) return setmetatable({},{__index=function() return function() end end}) end}

            bit = {}
            bit.bxor = function(a,b)
                local result, place = 0, 1
                while a > 0 or b > 0 do
                    if a % 2 ~= b % 2 then result = result + place end
                    a = math.floor(a/2); b = math.floor(b/2); place = place*2
                end
                return result
            end
            bit.band = function(a,b)
                local result, place = 0, 1
                while a > 0 and b > 0 do
                    if a % 2 == 1 and b % 2 == 1 then result = result + place end
                    a = math.floor(a/2); b = math.floor(b/2); place = place*2
                end
                return result
            end
            bit.bor = function(a,b)
                local result, place = 0, 1
                while a > 0 or b > 0 do
                    if a % 2 == 1 or b % 2 == 1 then result = result + place end
                    a = math.floor(a/2); b = math.floor(b/2); place = place*2
                end
                return result
            end
            bit.bnot = function(a) return -a - 1 end
            bit.rshift = function(a,b) return math.floor(a / (2^b)) end
            bit.lshift = function(a,b) return a * (2^b) end
            bit32 = bit

            string.byte   = string.byte
            string.char   = string.char
            string.sub    = string.sub
            string.rep    = string.rep
            string.len    = string.len
            string.find   = string.find
            string.gsub   = string.gsub
            string.match  = string.match
            string.gmatch = string.gmatch
            string.format = string.format
            string.lower  = string.lower
            string.upper  = string.upper
            string.reverse = string.reverse
            string.dump   = function() return "" end

            math.abs   = math.abs
            math.floor = math.floor
            math.ceil  = math.ceil
            math.max   = math.max
            math.min   = math.min
            math.sqrt  = math.sqrt
            math.random = math.random
            math.huge  = math.huge
            math.pi    = math.pi
            math.sin   = math.sin
            math.cos   = math.cos
            math.tan   = math.tan
            math.log   = math.log
            math.exp   = math.exp
            math.fmod  = math.fmod
            math.modf  = math.modf

            table.insert  = table.insert
            table.remove  = table.remove
            table.sort    = table.sort
            table.concat  = table.concat
            table.unpack  = table.unpack or unpack
            table.pack    = table.pack or function(...) return {n=select('#',...), ...} end
            table.move    = table.move or function(a,f,e,t,b) b=b or a for i=f,e do b[t+(i-f)]=a[i] end return b end

            coroutine = {
                create  = function(f) return f end,
                resume  = function(f,...) return pcall(f,...) end,
                yield   = function(...) return ... end,
                wrap    = function(f) return f end,
                status  = function() return "dead" end,
                running = function() return nil end
            }

            Drawing       = setmetatable({}, {__index=function() return function() end end})
            debug         = {traceback=function() return "" end, getinfo=function() return {} end}
            syn           = {protect_gui=function() end, queue_on_teleport=function() end}
            writefile     = function() end
            readfile      = function() return "" end
            isfile        = function() return false end
            isfolder      = function() return false end
            makefolder    = function() end
            listfiles     = function() return {} end
            request       = function() return {Body="",StatusCode=200,Success=true} end
            http          = {request=function() return {Body="",StatusCode=200} end}
            rconsole      = {print=function() end, clear=function() end}
            identifyexecutor = function() return "synapse", "2.0" end
            getexecutorname  = function() return "synapse" end
            checkcaller      = function() return true end
            isrbxactive      = function() return true end

            local _realenv = {
                string=string, math=math, table=table, bit=bit,
                pairs=pairs, ipairs=ipairs, select=select, next=next,
                tostring=tostring, tonumber=tonumber, type=type,
                rawget=rawget, rawset=rawset, rawlen=rawlen,
                setmetatable=setmetatable, getmetatable=getmetatable,
                unpack=table.unpack or unpack,
                loadstring=loadstring, load=load,
                pcall=pcall, xpcall=xpcall, error=error, assert=assert,
                print=print, warn=warn,
                game=game, workspace=workspace, script=script,
                coroutine=coroutine, shared=shared
            }
            getfenv = function(n) return _realenv end
            setfenv = function(n, t)
                for k,v in pairs(t) do _realenv[k]=v end
                return t
            end

            _G = _realenv
            _ENV = _realenv
        """)

        try:
            lua.execute(source)
        except Exception as e:
            pass

        q.put({
            'captured': captured,
            'error': None
        })

    except Exception as e:
        q.put({'captured': [], 'error': str(e)})

def run_sandboxed(source: str, timeout: int = 6) -> tuple:
    q = Queue()
    p = Process(target=_sandbox_worker, args=(source, q))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.kill()
        p.join()
        return [], 'Timeout'
    if not q.empty():
        result = q.get()
        return result.get('captured', []), result.get('error')
    return [], 'No response from sandbox'

def run_multilayer(source: str, max_passes: int = 8, timeout: int = 6) -> tuple:
    current = source
    layers = 0
    previews = []

    for _ in range(max_passes):
        captured, err = run_sandboxed(current, timeout)
        if not captured:
            break
        payload = captured[-1]
        if len(payload.strip()) < 10 or payload == current:
            break
        previews.append(payload[:80].replace('\n', ' '))
        current = payload
        layers += 1

    return current, layers, previews

async def ai_explain(code: str) -> str:
    if not ANTHROPIC_KEY:
        return code
    snippet = code[:3000]
    prompt = (
        "You are a Lua reverse engineer. The following is deobfuscated Lua code. "
        "Rename meaningless variable names (like _0x1a, l_0_0, _A, R1 etc) to descriptive names "
        "based on what the code actually does. Add short comments explaining each section. "
        "Preserve all logic exactly. Return only the improved Lua code, no markdown fences.\n\n"
        + snippet
    )
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                'https://api.anthropic.com/v1/messages',
                headers={
                    'x-api-key': ANTHROPIC_KEY,
                    'anthropic-version': '2023-06-01',
                    'content-type': 'application/json',
                },
                json={
                    'model': 'claude-sonnet-4-20250514',
                    'max_tokens': 2000,
                    'messages': [{'role': 'user', 'content': prompt}]
                }
            )
            data = resp.json()
            text = data['content'][0]['text']
            if len(code) > 3000:
                text += '\n\n-- [remaining ' + str(len(code) - 3000) + ' chars not AI-processed]\n'
                text += code[3000:]
            return text
    except Exception as e:
        return code

@bot.command(name='deobf')
async def deobf(ctx, flags: str = ''):
    use_ai   = '--ai' in flags or '-ai' in flags
    scan_only= '--scan' in flags or '-scan' in flags

    if not ctx.message.attachments:
        return await ctx.send(
            '**Usage:**\n'
            '`!deobf` — deobfuscate attached `.lua` file\n'
            '`!deobf --ai` — deobf + AI rename variables and add comments\n'
            '`!deobf --scan` — detect obfuscator + dump constants without executing'
        )

    attachment = ctx.message.attachments[0]
    if not attachment.filename.lower().endswith(('.lua', '.txt', '.luac')):
        return await ctx.send('Attach a `.lua`, `.luac`, or `.txt` file.')

    raw = await attachment.read()
    try:
        text = raw.decode('utf-8')
    except:
        try:
            text = raw.decode('latin-1')
        except:
            return await ctx.send('File encoding not supported.')

    obf_type = detect_obfuscator(text)

    embed = discord.Embed(
        title=f'Detected: {obf_type}',
        color=0x3498db
    )
    embed.add_field(name='File', value=attachment.filename, inline=True)
    embed.add_field(name='Size', value=f'{len(text):,} chars', inline=True)
    msg = await ctx.send(embed=embed)

    constants = extract_bytecode_constants(text)
    if constants:
        str_preview = ', '.join(repr(s) for s in constants['strings'][:12])
        embed.add_field(
            name='Bytecode constants found',
            value=f"Strings: {str_preview or 'none'}\n"
                  f"XOR key: {constants.get('xor_key', 'none')}",
            inline=False
        )
        await msg.edit(embed=embed)

    if scan_only:
        embed.title = f'Scan complete: {obf_type}'
        embed.color = 0x2ecc71
        await msg.edit(embed=embed)
        return

    embed.description = 'Running static transforms...'
    await msg.edit(embed=embed)

    embed.description = 'Sandboxing and intercepting loadstring...'
    await msg.edit(embed=embed)

    final_code, layers, previews = await asyncio.to_thread(
        run_multilayer, text, 8, 6
    )

    if layers > 0:
        final_code = full_static_clean(final_code)
        final_code = beautify_lua(final_code)

        embed.description = (
            f'{layers} layer(s) peeled via loadstring intercept.\n'
        )
        if previews:
            preview_text = '\n'.join(f'Layer {i+1}: {p}...' for i, p in enumerate(previews))
            embed.add_field(name='Layer previews', value=preview_text[:900], inline=False)
        embed.color = 0x2ecc71

    else:
        embed.description = 'Sandbox captured nothing (VM-protected or crashed). Running static transforms only...'
        embed.color = 0xe67e22
        await msg.edit(embed=embed)

        final_code = full_static_clean(text)
        final_code = beautify_lua(final_code)

        embed.add_field(
            name='What this means',
            value=(
                'This script likely uses a custom VM. '
                'VM-protected scripts compile Lua into a private instruction set. '
                'The static-cleaned version is attached with string decoding and constant folding applied.'
            ),
            inline=False
        )

    if use_ai and ANTHROPIC_KEY:
        embed.description += '\nRunning AI rename pass...'
        await msg.edit(embed=embed)
        final_code = await ai_explain(final_code)
        embed.add_field(name='AI', value='Variables renamed + comments added', inline=True)
    elif use_ai and not ANTHROPIC_KEY:
        embed.add_field(name='AI', value='No ANTHROPIC_API_KEY set', inline=True)

    await msg.edit(embed=embed)

    out_name = f'deobf_{attachment.filename}'
    file = discord.File(fp=io.StringIO(final_code), filename=out_name)
    await ctx.send(
        f'Result: {layers} sandbox layer(s) | {len(final_code):,} chars',
        file=file
    )

@bot.command(name='constants')
async def constants_cmd(ctx):
    if not ctx.message.attachments:
        return await ctx.send('Attach a file.')
    raw   = await ctx.message.attachments[0].read()
    text  = raw.decode('latin-1', errors='replace')
    consts = extract_bytecode_constants(text)
    if not consts:
        return await ctx.send('No Lua 5.1 bytecode found.')
    out = '-- Extracted constants\n'
    out += '-- Strings:\n'
    for s in consts['strings']:
        out += f'--   {repr(s)}\n'
    out += '-- Numbers:\n'
    for n in consts['numbers']:
        out += f'--   {n}\n'
    if 'xor_key' in consts:
        out += f'-- XOR key: {consts["xor_key"]}\n'
    await ctx.send(file=discord.File(fp=io.StringIO(out), filename='constants.lua'))

@bot.command(name='info')
async def info_cmd(ctx):
    embed = discord.Embed(title='Lua Deobfuscator', color=0x3498db)
    embed.add_field(
        name='Commands',
        value=(
            '`!deobf` — Deobfuscate attached `.lua` file\n'
            '`!deobf --ai` — AI renames variables and adds comments\n'
            '`!deobf --scan` — Detect obfuscator + dump constants\n'
            '`!constants` — Dump string/number constants from bytecode'
        ),
        inline=False
    )
    embed.add_field(
        name='What it can reverse',
        value=(
            'WeareDevs, basic Luraph, IronBrew 1: sandbox intercept\n'
            'String encoding (\\x41, string.char, base64)\n'
            'Nested loadstring layers (up to 8 deep)\n'
            'Bytecode constants (survives most obfuscation)\n'
            'IronBrew 2/3, modern Luraph: partial (static only)\n'
            'Full custom VM: not reversible automatically'
        ),
        inline=False
    )
    await ctx.send(embed=embed)

@bot.event
async def on_ready():
    print(f'Bot online as {bot.user}')

if __name__ == '__main__':
    bot.run(TOKEN)
