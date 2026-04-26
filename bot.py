import discord
import re
import io
import os
import struct
import base64
import httpx
from discord.ext import commands

TOKEN         = os.environ['DISCORD_BOT_TOKEN']
ANTHROPIC_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
API_URL       = os.environ.get('DEOBF_API_URL', 'http://localhost:5000')

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

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
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.post(f'{API_URL}/deobf', json={'source': source})
        return r.json()


async def ai_clean(code):
    if not ANTHROPIC_KEY: return code
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


@bot.command(name='deobf')
async def deobf(ctx, flags: str = ''):
    use_ai    = '--ai'   in flags
    scan_only = '--scan' in flags

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
    try: text = raw.decode('utf-8')
    except:
        try: text = raw.decode('latin-1')
        except: return await ctx.send('Cannot decode file.')

    obf = detect_obfuscator(text)
    em  = discord.Embed(title=f'Detected: `{obf}`', color=0x3498db)
    em.add_field(name='File', value=att.filename, inline=True)
    em.add_field(name='Size', value=f'{len(text):,} chars', inline=True)
    msg = await ctx.send(embed=em)

    consts = extract_constants(text)
    if consts:
        preview = ', '.join(repr(s) for s in consts['strings'][:10])
        em.add_field(name='Bytecode constants',
                     value=f"Strings: {preview or 'none'}\nXOR key: {consts.get('xor_key','none')}",
                     inline=False)
        await msg.edit(embed=em)

    if scan_only:
        em.title = f'Scan done: `{obf}`'; em.color = 0x2ecc71
        await msg.edit(embed=em); return

    em.description = 'Sending to deobfuscation server...'
    await msg.edit(embed=em)

    try:
        data = await call_api(text)
    except Exception as e:
        em.description = f'API error: {e}'; em.color = 0xe74c3c
        await msg.edit(embed=em); return

    if 'error' in data:
        em.description = f'Server error: {data["error"]}'; em.color = 0xe74c3c
        await msg.edit(embed=em); return

    result   = data['result']
    layers   = data['layers']
    previews = data['previews']
    method   = data['method']

    if layers > 0:
        em.description = f'Peeled {layers} layer(s) via sandbox.'
        em.color = 0x2ecc71
        if previews:
            em.add_field(name='Layers', value='\n'.join(f'`{i+1}:` {p}...' for i,p in enumerate(previews))[:900], inline=False)
    else:
        em.description = 'Sandbox got nothing — static decode applied.'
        em.color = 0xe67e22
        em.add_field(name='Note', value='Script likely uses a custom VM. String decoding and formatting were applied.', inline=False)

    em.add_field(name='Method', value=method, inline=True)

    if use_ai and ANTHROPIC_KEY:
        em.description += '\nAI pass running...'
        await msg.edit(embed=em)
        result = await ai_clean(result)
        em.add_field(name='AI', value='Done', inline=True)
    elif use_ai:
        em.add_field(name='AI', value='No ANTHROPIC_API_KEY set', inline=True)

    await msg.edit(embed=em)
    await ctx.send(
        f'**Done** — {layers} layer(s) | {len(result):,} chars',
        file=discord.File(fp=io.StringIO(result), filename=f'deobf_{att.filename}')
    )


@bot.command(name='constants')
async def constants_cmd(ctx):
    if not ctx.message.attachments: return await ctx.send('Attach a file.')
    raw = await ctx.message.attachments[0].read()
    text = raw.decode('latin-1', errors='replace')
    consts = extract_constants(text)
    if not consts: return await ctx.send('No Lua 5.1 bytecode found.')
    out  = '-- Strings:\n' + ''.join(f'--   {repr(s)}\n' for s in consts['strings'])
    out += '-- Numbers:\n' + ''.join(f'--   {n}\n' for n in consts['numbers'])
    if 'xor_key' in consts: out += f'-- XOR key: {consts["xor_key"]}\n'
    await ctx.send(file=discord.File(fp=io.StringIO(out), filename='constants.lua'))


@bot.command(name='apistatus')
async def apistatus(ctx):
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f'{API_URL}/health')
            d = r.json()
        em = discord.Embed(title='API Status', color=0x2ecc71 if d.get('lua') else 0xe74c3c)
        em.add_field(name='API',     value='Online', inline=True)
        em.add_field(name='Lua 5.1', value='OK' if d.get('lua') else 'NOT FOUND', inline=True)
    except Exception as e:
        em = discord.Embed(title='API Status', color=0xe74c3c)
        em.add_field(name='API', value=f'Offline — {e}', inline=False)
    await ctx.send(embed=em)


@bot.command(name='info')
async def info_cmd(ctx):
    em = discord.Embed(title='Lua Deobfuscator', color=0x3498db)
    em.add_field(name='Commands', value=(
        '`!deobf` — deobfuscate `.lua` file\n'
        '`!deobf --ai` — deobf + AI rename\n'
        '`!deobf --scan` — scan only\n'
        '`!constants` — dump bytecode constants\n'
        '`!apistatus` — check API server'
    ), inline=False)
    em.add_field(name='Coverage', value=(
        '✅ WeareDevs, IronBrew 1, basic Luraph\n'
        '✅ String encoding, nested loadstring layers\n'
        '✅ Bytecode constant extraction\n'
        '⚠️ IronBrew 2/3, modern Luraph — static only\n'
        '❌ Full custom VM — not reversible automatically'
    ), inline=False)
    await ctx.send(embed=em)


@bot.event
async def on_ready():
    print(f'Ready: {bot.user} | API: {API_URL}')


if __name__ == '__main__':
    bot.run(TOKEN)
