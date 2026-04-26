import discord
from discord import app_commands
from discord.ext import commands
from itertools import cycle
import re
import io
import os
import struct
import base64
import httpx
import asyncio

TOKEN         = os.environ['DISCORD_BOT_TOKEN']
ANTHROPIC_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
API_URL       = os.environ.get('DEOBF_API_URL', 'http://localhost:5000')

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)
tree = bot.tree

OBFUSCATOR_PATTERNS = {
    'luraph':     [r'loadstring\s*\(\s*\(function', r'bytecode\s*=\s*["\'][A-Za-z0-9+/=]{50,}'],
    'moonsec':    [r'local\s+\w+\s*=\s*\{[\d\s,]{20,}\}', r'_moon\s*=\s*function'],
    'ironbrew':   [r'local\s+\w+\s*=\s*\{\s*"\\x[0-9a-fA-F]{2}', r'\bIronBrew\b', r'bit\.bxor'],
    'ironbrew2':  [r'while\s+true\s+do\s+local\s+\w+\s*=\s*\w+\[\w+\]'],
    'wearedevs':  [r'show_\w+\s*=\s*function', r'getfenv\s*\(\s*\)', r'string\.reverse\s*\('],
    'prometheus': [r'Prometheus', r'number_to_bytes'],
    'custom_vm':  [r'mkexec', r'constTags', r'protoFormats'],
    'synapse':    [r'syn\.\w+\s*=\s*', r'syn\.protect'],
    'luaarmor':   [r'___armor_', r'LuaArmor'],
    'psu':        [r'ProtectedString', r'ByteCode\s*='],
    'aurora':     [r'__aurora\s*=\s*', r'Aurora\s*=\s*'],
    'obfuscated': [r'string\.char\s*\(', r'\\x[0-9a-fA-F]{2}'],
}

def detect_obfuscator(text):
    scores = {}
    for name, pats in OBFUSCATOR_PATTERNS.items():
        s = sum(1 for p in pats if re.search(p, text, re.IGNORECASE))
        if s: scores[name] = s
    return max(scores, key=lambda k: scores[k]) if scores else 'generic'

class BytecodeParser:
    def __init__(self, data):
        self.data = data; self.pos = 0
        self.strings = []; self.numbers = []
    def u8(self):
        v = self.data[self.pos]; self.pos += 1; return v
    def u32(self):
        v = struct.unpack_from('<I', self.data, self.pos)[0]; self.pos += 4; return v
    def f64(self):
        v = struct.unpack_from('<d', self.data, self.pos)[0]; self.pos += 8; return v
    def lstring(self):
        n = self.u32()
        if n == 0: return ''
        s = self.data[self.pos:self.pos+n-1].decode('utf-8', errors='replace')
        self.pos += n; return s
    def proto(self):
        self.lstring(); self.u32(); self.u32()
        self.u8(); self.u8(); self.u8(); self.u8()
        self.pos += self.u32() * 4
        for _ in range(self.u32()):
            t = self.u8()
            if t == 1: self.u8()
            elif t == 3: self.numbers.append(self.f64())
            elif t == 4:
                s = self.lstring()
                if s: self.strings.append(s)
        for _ in range(self.u32()): self.proto()
        self.pos += self.u32() * 4
        for _ in range(self.u32()): self.lstring(); self.u32(); self.u32()
        for _ in range(self.u32()): self.lstring()
    def parse(self):
        if self.data[:4] != b'\x1bLua': return False
        self.pos = 12
        try: self.proto(); return True
        except: return False

def extract_constants(source):
    candidates = []
    try: candidates.append(source.encode('latin-1'))
    except: pass
    for m in re.finditer(r'["\']([A-Za-z0-9+/=]{60,})["\']', source):
        try: candidates.append(base64.b64decode(m.group(1) + '=='))
        except: pass
    for data in candidates:
        if len(data) < 16: continue
        if data[:4] == b'\x1bLua':
            p = BytecodeParser(data)
            if p.parse(): return {'strings': p.strings, 'numbers': p.numbers}
        for key in range(256):
            if bytes(b ^ key for b in data[:4]) == b'\x1bLua':
                full = bytes(b ^ key for b in data)
                p = BytecodeParser(full)
                if p.parse(): return {'strings': p.strings, 'numbers': p.numbers, 'xor_key': key}
    return None

async def call_api(source):
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(f'{API_URL}/deobf', json={'source': source})
        return r.json()

async def ai_clean(code):
    if not ANTHROPIC_KEY:
        return code
    prompt = (
        "You are a Lua reverse engineer. Below is deobfuscated Lua. "
        "Rename cryptic variables to meaningful names. "
        "Add brief comments explaining each section. "
        "Preserve all logic exactly. Return ONLY Lua code, no markdown.\n\n"
        + code[:3500]
    )
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(
                'https://api.anthropic.com/v1/messages',
                headers={'x-api-key': ANTHROPIC_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
                json={'model': 'claude-sonnet-4-20250514', 'max_tokens': 2048, 'messages': [{'role': 'user', 'content': prompt}]}
            )
            result = r.json()['content'][0]['text']
            if len(code) > 3500: result += '\n\n' + code[3500:]
            return result
    except:
        return code

async def run_deobf_process(text, filename, use_ai=False, scan_only=False):
    obf = detect_obfuscator(text)
    if scan_only:
        embed = discord.Embed(title=f'Scan: {obf}', color=0x2ecc71)
        embed.add_field(name='File', value=filename, inline=True)
        embed.add_field(name='Size', value=f'{len(text):,} chars', inline=True)
        return {'embed': embed, 'file': None}
    try:
        data = await call_api(text)
    except Exception as e:
        embed = discord.Embed(title='API Error', description=str(e), color=0xe74c3c)
        return {'embed': embed, 'file': None}
    if 'error' in data:
        embed = discord.Embed(title='Deobfuscation failed', description=data['error'], color=0xe74c3c)
        return {'embed': embed, 'file': None}
    result   = data['result']
    layers   = data.get('layers', 0)
    previews = data.get('previews', [])
    method   = data.get('method', 'static')
    detected = data.get('detected', obf)
    if use_ai and ANTHROPIC_KEY:
        result = await ai_clean(result)
    embed = discord.Embed(title='Deobfuscation complete', color=0x2ecc71 if layers > 0 else 0xe67e22)
    embed.add_field(name='Obfuscator',   value=detected, inline=True)
    embed.add_field(name='Method',       value=method,   inline=True)
    embed.add_field(name='Layers peeled',value=str(layers), inline=True)
    if previews:
        embed.add_field(
            name='Layer previews',
            value='\n'.join(f'Layer {i+1}: {p[:80]}...' for i, p in enumerate(previews[:3])),
            inline=False
        )
    if use_ai and ANTHROPIC_KEY:
        embed.add_field(name='AI', value='Variables renamed + comments added', inline=False)
    file = discord.File(fp=io.StringIO(result), filename=f'deobf_{filename}')
    return {'embed': embed, 'file': file}

@bot.command(name='deobf')
async def prefix_deobf(ctx, flags: str = ''):
    use_ai    = '--ai'   in flags
    scan_only = '--scan' in flags
    if not ctx.message.attachments:
        return await ctx.send('**Usage:**\n`!deobf` - deobfuscate `.lua` file\n`!deobf --ai` - deobf + AI rename\n`!deobf --scan` - scan only')
    att = ctx.message.attachments[0]
    if not att.filename.lower().endswith(('.lua', '.txt', '.luac')):
        return await ctx.send('Attach a `.lua`, `.luac`, or `.txt` file.')
    raw = await att.read()
    try: text = raw.decode('utf-8')
    except:
        try: text = raw.decode('latin-1')
        except: return await ctx.send('Cannot decode file.')
    start_embed = discord.Embed(
        title='Analyzing...',
        description=f"Detected: **{detect_obfuscator(text)}**\nSize: {len(text):,} chars",
        color=0x3498db
    )
    msg = await ctx.send(embed=start_embed)
    spinner = cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'])
    async def animate():
        for frame in spinner:
            await asyncio.sleep(0.4)
            try:
                start_embed.title = f'{frame} Deobfuscating...'
                await msg.edit(embed=start_embed)
            except:
                break
    anim_task = asyncio.create_task(animate())
    try:
        result = await run_deobf_process(text, att.filename, use_ai=use_ai, scan_only=scan_only)
    finally:
        anim_task.cancel()
    await msg.delete()
    if result['file']:
        await ctx.send(file=result['file'], embed=result['embed'])
    else:
        await ctx.send(embed=result['embed'])

@bot.command(name='constants')
async def prefix_constants(ctx):
    if not ctx.message.attachments:
        return await ctx.send('Attach a file.')
    raw = await ctx.message.attachments[0].read()
    text = raw.decode('latin-1', errors='replace')
    consts = extract_constants(text)
    if not consts:
        return await ctx.send('No Lua bytecode constants found.')
    out  = '-- Strings:\n' + ''.join(f'--   {repr(s)}\n' for s in consts['strings'])
    out += '-- Numbers:\n' + ''.join(f'--   {n}\n' for n in consts['numbers'])
    if 'xor_key' in consts: out += f'-- XOR key: {consts["xor_key"]}\n'
    await ctx.send(file=discord.File(fp=io.StringIO(out), filename='constants.lua'))

@bot.command(name='apistatus')
async def prefix_apistatus(ctx):
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f'{API_URL}/health')
            d = r.json()
        lua_ok = d.get('lua', False)
        em = discord.Embed(title='API Status', color=0x2ecc71 if lua_ok else 0xe74c3c)
        em.add_field(name='API',         value='Online', inline=True)
        em.add_field(name='Lua 5.1',     value='OK' if lua_ok else 'NOT FOUND', inline=True)
        em.add_field(name='Lua binary',  value=d.get('lua_bin', '?'), inline=True)
        em.add_field(name='Lua version', value=d.get('lua_version', '?'), inline=False)
    except Exception as e:
        em = discord.Embed(title='API Status', color=0xe74c3c)
        em.add_field(name='API', value=f'Offline - {e}', inline=False)
    await ctx.send(embed=em)

@bot.command(name='info')
async def prefix_info(ctx):
    em = discord.Embed(title='Lua Deobfuscator', color=0x3498db)
    em.add_field(name='Commands', value=(
        '`!deobf` - deobfuscate `.lua` file\n'
        '`!deobf --ai` - deobf + AI rename\n'
        '`!deobf --scan` - scan only\n'
        '`!constants` - dump bytecode constants\n'
        '`!apistatus` - check API server'
    ), inline=False)
    em.add_field(name='Slash commands', value='`/deobf` `/constants` `/apistatus` `/info`', inline=False)
    await ctx.send(embed=em)

@tree.command(name='deobf', description='Deobfuscate a Lua file')
@app_commands.describe(file='The Lua file to deobfuscate', ai='AI rename variables', scan='Scan only')
async def slash_deobf(interaction: discord.Interaction, file: discord.Attachment, ai: bool = False, scan: bool = False):
    if not file.filename.lower().endswith(('.lua', '.txt', '.luac')):
        return await interaction.response.send_message('Only `.lua`, `.luac`, or `.txt` files.', ephemeral=True)
    await interaction.response.defer(thinking=True)
    raw = await file.read()
    try: text = raw.decode('utf-8')
    except:
        try: text = raw.decode('latin-1')
        except: return await interaction.followup.send('Cannot decode file.', ephemeral=True)
    result = await run_deobf_process(text, file.filename, use_ai=ai, scan_only=scan)
    if result['file']:
        await interaction.followup.send(file=result['file'], embed=result['embed'])
    else:
        await interaction.followup.send(embed=result['embed'])

@tree.command(name='constants', description='Extract bytecode constants from a Lua file')
@app_commands.describe(file='The Lua file to analyze')
async def slash_constants(interaction: discord.Interaction, file: discord.Attachment):
    await interaction.response.defer(thinking=True)
    raw = await file.read()
    text = raw.decode('latin-1', errors='replace')
    consts = extract_constants(text)
    if not consts:
        return await interaction.followup.send('No Lua bytecode constants found.', ephemeral=True)
    out  = '-- Strings:\n' + ''.join(f'--   {repr(s)}\n' for s in consts['strings'])
    out += '-- Numbers:\n' + ''.join(f'--   {n}\n' for n in consts['numbers'])
    if 'xor_key' in consts: out += f'-- XOR key: {consts["xor_key"]}\n'
    await interaction.followup.send(file=discord.File(fp=io.StringIO(out), filename='constants.lua'))

@tree.command(name='apistatus', description='Check the deobfuscation API status')
async def slash_apistatus(interaction: discord.Interaction):
    await interaction.response.defer(thinking=True)
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f'{API_URL}/health')
            d = r.json()
        lua_ok = d.get('lua', False)
        em = discord.Embed(title='API Status', color=0x2ecc71 if lua_ok else 0xe74c3c)
        em.add_field(name='API',         value='Online', inline=True)
        em.add_field(name='Lua 5.1',     value='OK' if lua_ok else 'NOT FOUND', inline=True)
        em.add_field(name='Lua binary',  value=d.get('lua_bin', '?'), inline=True)
        em.add_field(name='Lua version', value=d.get('lua_version', '?'), inline=False)
    except Exception as e:
        em = discord.Embed(title='API Status', color=0xe74c3c)
        em.add_field(name='API', value=f'Offline - {e}', inline=False)
    await interaction.followup.send(embed=em)

@tree.command(name='info', description='Show bot info')
async def slash_info(interaction: discord.Interaction):
    em = discord.Embed(title='Lua Deobfuscator', color=0x3498db)
    em.add_field(name='Commands', value=(
        '`/deobf` - Deobfuscate a Lua file\n'
        '`/constants` - Extract bytecode constants\n'
        '`/apistatus` - Check API server\n'
        '`/info` - Show this help'
    ), inline=False)
    await interaction.response.send_message(embed=em)

@bot.event
async def on_ready():
    await tree.sync()
    print(f'Ready: {bot.user} | API: {API_URL}')

if __name__ == '__main__':
    bot.run(TOKEN)
