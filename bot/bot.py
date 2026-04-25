import discord, re, io, os, httpx
from discord.ext import commands

TOKEN = os.environ['DISCORD_BOT_TOKEN']
BACKEND_URL = os.environ.get('BACKEND_URL', 'http://backend:8080')

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

@bot.command(name='deobf')
async def deobf(ctx, flags: str = ''):
    if not ctx.message.attachments:
        return await ctx.send('Attach a `.lua` file with `!deobf`')
    att = ctx.message.attachments[0]
    if not att.filename.lower().endswith(('.lua', '.txt', '.luac')):
        return await ctx.send('Only `.lua`, `.luac`, `.txt` files are supported.')
    raw = await att.read()
    try:
        text = raw.decode('utf-8')
    except:
        try:
            text = raw.decode('latin-1')
        except:
            return await ctx.send('Cannot decode file.')
    scan_only = '--scan' in flags
    if scan_only:
        obf = detect_obfuscator(text)
        em = discord.Embed(title=f'Scan: {obf}', color=0x2ecc71)
        em.add_field(name='File', value=att.filename)
        em.add_field(name='Size', value=f'{len(text):,} chars')
        await ctx.send(embed=em)
        return
    msg = await ctx.send('⏳ Sending to backend...')
    async with httpx.AsyncClient(timeout=90) as client:
        try:
            resp = await client.post(
                f'{BACKEND_URL}/deobfuscate',
                files={'file': (att.filename, raw)}
            )
        except Exception as e:
            return await msg.edit(embed=discord.Embed(title='Error', description=f'Backend unreachable: {e}', color=0xe74c3c))
    if resp.status_code != 200:
        data = resp.json()
        err = data.get('error', 'Unknown error')
        em = discord.Embed(title='Deobfuscation failed', description=err[:500], color=0xe74c3c)
        await msg.edit(embed=em)
        return
    data = resp.json()
    code = data['code']
    layers = data.get('layers', 0)
    obf_type = data.get('obfuscator', 'generic')
    constants = data.get('constants')
    ai_used = data.get('ai', False)
    em = discord.Embed(title='Deobfuscation complete', color=0x2ecc71)
    em.add_field(name='Obfuscator', value=obf_type, inline=True)
    em.add_field(name='Layers peeled', value=str(layers), inline=True)
    if constants:
        preview = ', '.join(repr(s) for s in constants['strings'][:8])
        em.add_field(name='Bytecode constants', value=preview or 'none', inline=False)
    if ai_used:
        em.add_field(name='AI processing', value='Variables renamed + comments added', inline=True)
    file = discord.File(fp=io.StringIO(code), filename=f'deobf_{att.filename}')
    await ctx.send(embed=em, file=file)

@bot.command(name='info')
async def info_cmd(ctx):
    em = discord.Embed(title='Lua Deobfuscator', color=0x3498db)
    em.add_field(name='Commands', value='`!deobf`\n`!deobf --scan`\n`!info`', inline=False)
    em.add_field(name='Coverage', value='Luraph, Moonsec, Ironbrew, WeAreDevs, Prometheus, custom VMs, and more.', inline=False)
    await ctx.send(embed=em)

@bot.event
async def on_ready():
    print(f'Bot ready as {bot.user}')

if __name__ == '__main__':
    bot.run(TOKEN)
