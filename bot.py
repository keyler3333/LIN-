import discord
import re
import io
import os
import asyncio
import threading
from discord.ext import commands
from lupa import LuaRuntime

TOKEN = os.environ['DISCORD_BOT_TOKEN']
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

BLOCKED_GLOBALS = ['io', 'os', 'require', 'dofile', 'loadfile', 'debug', 'package', 'rawget', 'rawset', 'rawequal', 'rawlen', 'collectgarbage', 'module', 'newproxy']

OBFUSCATOR_PATTERNS = {
    'luraph': [r'loadstring\s*\(\s*\(function', r'bytecode\s*=\s*["\'][A-Za-z0-9+/=]{50,}'],
    'moonsec': [r'local\s+\w+\s*=\s*\{[\d\s,]+\}', r'_moon\s*=\s*function'],
    'ironbrew': [r'local\s+\w+\s*=\s*\{\s*"\\x', r'getfenv\s*\(\)'],
    'wearedevs': [r'show_\w+\s*=\s*function', r'getfenv\s*\(\)'],
    'custom_vm': [r'mkexec', r'constTags', r'protoFormats'],
    'synapse': [r'syn\.', r'Bytecode'],
    'aurora': [r'__aurora', r'Aurora\s*='],
    'sentinel': [r'Sentinel\s*=', r'V3'],
    'psu': [r'ProtectedString', r'ByteCode'],
    'xen': [r'Xen\s*=', r'Bytecode'],
    'luaarmor': [r'armor\s*=', r'___armor_'],
    'vmprotect': [r'local\s+f\s*=\s*loadstring'],
}

def detect_obfuscator(text):
    scores = {}
    for name, pats in OBFUSCATOR_PATTERNS.items():
        total = sum(1 for p in pats if re.search(p, text, re.IGNORECASE))
        if total > 0:
            scores[name] = total
    if scores:
        best = max(scores, key=lambda k: scores[k])
        if scores[best] >= 2:
            return best
        if 'luraph' in scores and scores['luraph'] >= 1:
            return 'luraph'
    return 'generic'

def run_sandboxed(lua_source, timeout=5):
    captured = []
    error_container = [None]

    def safe_loadstring(code):
        captured.append(str(code))
        return lambda: None

    def execute():
        try:
            lua = LuaRuntime(unpack_returned_tuples=True)
            for name in BLOCKED_GLOBALS:
                try:
                    lua.execute(f"{name} = nil")
                except:
                    pass
            lua.globals()['loadstring'] = safe_loadstring
            lua.globals()['load'] = safe_loadstring
            lua.execute("""
                game = {}
                workspace = {}
                script = {}
                getfenv = function() return {} end
                setfenv = function() end
                tick = function() return 0 end
                wait = function() end
                spawn = function() end
                delay = function() end
                print = function() end
                warn = function() end
                error = function() end
                pcall = function(f, ...) return {true, f(...)} end
                xpcall = function(f, h, ...) return true, f(...) end
                _G = {}
                _ENV = {}
                shared = {}
                plugin = {}
                stats = {}
                time = function() return 0 end
                elapsed_time = function() return 0 end
                UserSettings = function() return {} end
                settings = function() return {} end
                typeof = function() return "table" end
                type = type or function() return "table" end
                if _VERSION then else _VERSION = "Lua 5.1" end
                coroutine = {create = function() end, resume = function() end, yield = function() end}
                string = {byte = string.byte, char = string.char, sub = string.sub, rep = string.rep, len = string.len, find = string.find, gsub = string.gsub, match = string.match, gmatch = string.gmatch, format = string.format, lower = string.lower, upper = string.upper, reverse = string.reverse}
                math = {abs = math.abs, floor = math.floor, ceil = math.ceil, max = math.max, min = math.min, sqrt = math.sqrt, pow = math.pow, random = math.random, huge = math.huge, pi = math.pi, sin = math.sin, cos = math.cos, tan = math.tan}
                table = {insert = table.insert, remove = table.remove, sort = table.sort, concat = table.concat, pack = table.pack or function(...) return {n=select('#',...), ...} end, unpack = table.unpack or unpack}
                bit32 = {bxor = bit32.bxor or function(a,b) return a ~ b end, band = bit32.band or function(a,b) return a & b end, bor = bit32.bor or function(a,b) return a | b end}
                utf8 = {}
            """)
            lua.execute(lua_source)
        except Exception as e:
            error_container[0] = str(e)

    t = threading.Thread(target=execute)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        return None
    if captured:
        return captured[-1]
    return None

def beautify_lua(code):
    lines = code.split('\n')
    out = []
    indent = 0
    for line in lines:
        stripped = line.strip()
        if not stripped:
            out.append('')
            continue
        if stripped.startswith('end') or stripped.startswith('else') or stripped.startswith('elseif') or stripped.startswith('until'):
            indent = max(0, indent - 1)
        out.append('    ' * indent + stripped)
        if stripped.startswith('if ') or stripped.startswith('for ') or stripped.startswith('while ') or stripped.startswith('repeat'):
            indent += 1
        if stripped.startswith('function ') or stripped.startswith('local function '):
            indent += 1
        if stripped == 'do':
            indent += 1
        if stripped.endswith('then') and not stripped.startswith('if '):
            pass
    return '\n'.join(out)

def deobfuscate_static(text):
    code = text
    code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), code)
    code = re.sub(r'\\u\{([0-9a-fA-F]+)\}', lambda m: chr(int(m.group(1), 16)), code)
    code = re.sub(r'\\(\\d{1,3})', lambda m: chr(int(m.group(1))), code)
    def char_decode(m):
        nums = re.findall(r'\\d+', m.group(1))
        chars = ''.join([chr(int(n)) for n in nums if int(n) < 256])
        return '"' + chars + '"'
    code = re.sub(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', char_decode, code)
    for _ in range(10):
        match = re.search(r'loadstring\s*\(\s*["\'](.*?)["\']\s*\)\s*\(?\s*\)?', code, re.DOTALL)
        if not match:
            inner_match = re.search(r'loadstring\s*\(\s*(\w+(?:\.\w+)*(?:\(\))?)\s*\)\s*\(?\s*\)?', code)
            if inner_match:
                var_name = inner_match.group(1)
                var_match = re.search(rf'local\s+{re.escape(var_name)}\s*=\s*["\'](.*?)["\']', code)
                if var_match:
                    inner = var_match.group(1)
                    code = code[:inner_match.start()] + inner + code[inner_match.end():]
                    continue
            break
        inner = match.group(1)
        inner = inner.replace('\\"', '"').replace("\\'", "'").replace('\\\\', '\\')
        code = code[:match.start()] + inner + code[match.end():]
    return code

@bot.command(name='deobf')
async def deobf(ctx):
    if not ctx.message.attachments:
        return await ctx.send('Attach a `.lua` file.')
    raw = await ctx.message.attachments[0].read()
    try:
        text = raw.decode('utf-8')
    except:
        try:
            text = raw.decode('latin-1')
        except:
            return await ctx.send('File encoding not supported.')

    obf_type = detect_obfuscator(text)
    embed = discord.Embed(title="🔍 Static pass: decoding strings...", color=0x3498db)
    msg = await ctx.send(embed=embed)
    await asyncio.sleep(0.5)

    text = deobfuscate_static(text)
    embed.title = "⏳ Sandbox: intercepting loadstring..."
    embed.color = 0xf39c12
    await msg.edit(embed=embed)
    await asyncio.sleep(0.5)

    result = await asyncio.to_thread(run_sandboxed, text, 6)
    if result:
        embed.title = "⏳ Deeper sandbox pass..."
        await msg.edit(embed=embed)
        await asyncio.sleep(0.5)
        deeper = await asyncio.to_thread(run_sandboxed, result, 4)
        if deeper:
            result = deeper
    else:
        result = None

    if result and len(result.strip()) > 10:
        result = beautify_lua(result)
        embed.title = "✅ Deobfuscated successfully"
        embed.description = f"Detected: {obf_type}\nPayload captured from loadstring intercept."
        embed.color = 0x2ecc71
        await msg.edit(embed=embed)
        file = discord.File(fp=io.StringIO(result), filename=f'deobfuscated_{ctx.message.attachments[0].filename}')
        await ctx.send(file=file)
    else:
        embed.title = "❌ Could not deobfuscate"
        embed.description = f"Detected: {obf_type}\nThe script uses a custom VM that cannot be reversed this way."
        embed.color = 0xe74c3c
        await msg.edit(embed=embed)

@bot.event
async def on_ready():
    print(f'Bot online as {bot.user}')

if __name__ == '__main__':
    bot.run(TOKEN)
