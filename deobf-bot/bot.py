import discord
import io
import os
import httpx
import base64
from discord.ext import commands

TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
API_KEY = os.environ.get('API_KEY')
API_URL = os.environ.get('DEOBF_API_URL', 'http://localhost:5000')

if not TOKEN:
    raise SystemExit("DISCORD_BOT_TOKEN not set.")

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)
tree = bot.tree

async def call_api(source_b64):
    headers = {}
    if API_KEY:
        headers['X-API-Key'] = API_KEY
    async with httpx.AsyncClient(timeout=120) as c:
        r = await c.post(f'{API_URL}/deobf', json={'source_b64': source_b64}, headers=headers)
        return r.json()

async def run_deobf(raw_bytes, filename):
    if len(raw_bytes) > 5 * 1024 * 1024:
        return {'embed': discord.Embed(title='Error', description='File exceeds 5MB limit', color=0xe74c3c), 'file': None}
    try:
        source_b64 = base64.b64encode(raw_bytes).decode('ascii')
        data = await call_api(source_b64)
    except Exception as e:
        return {'embed': discord.Embed(title='API Error', description=str(e), color=0xe74c3c), 'file': None}
    if 'error' in data:
        return {'embed': discord.Embed(title='Deobfuscation failed', description=data['error'], color=0xe74c3c), 'file': None}

    result = data.get('result', '')
    detected = data.get('detected', 'unknown')
    diagnostic = data.get('diagnostic', '')
    raw_bytecode_b64 = data.get('raw_bytecode_b64')

    em = discord.Embed(title='Deobfuscation complete', color=0x2ecc71 if detected == 'success' else 0xe67e22)
    em.add_field(name='Status', value=detected, inline=True)
    if diagnostic:
        em.add_field(name='Pipeline', value=diagnostic[:1000], inline=False)

    files = []
    if result:
        files.append(discord.File(fp=io.StringIO(result), filename=f'deobf_{filename}'))
    if raw_bytecode_b64:
        raw_bytes_out = base64.b64decode(raw_bytecode_b64)
        files.append(discord.File(fp=io.BytesIO(raw_bytes_out), filename=f'captured_{filename}.luac'))

    return {'embed': em, 'files': files}

@bot.command(name='deobf')
@commands.cooldown(1, 30, commands.BucketType.user)
async def prefix_deobf(ctx):
    if not ctx.message.attachments:
        return await ctx.send('Attach a `.lua` file with `!deobf`')
    att = ctx.message.attachments[0]
    if not att.filename.lower().endswith('.lua'):
        return await ctx.send('Please attach a `.lua` file.')
    if att.size > 5 * 1024 * 1024:
        return await ctx.send('File exceeds 5MB limit.')
    raw = await att.read()
    msg = await ctx.send(embed=discord.Embed(title='Deobfuscating...', color=0x3498db))
    res = await run_deobf(raw, att.filename)
    try:
        await msg.delete()
    except discord.NotFound:
        pass
    await ctx.send(embed=res['embed'], files=res.get('files', []))

@tree.command(name='deobf', description='Deobfuscate a Lua file')
async def slash_deobf(interaction: discord.Interaction, file: discord.Attachment):
    if not file.filename.lower().endswith('.lua'):
        return await interaction.response.send_message('Please attach a `.lua` file.', ephemeral=True)
    if file.size > 5 * 1024 * 1024:
        return await interaction.response.send_message('File exceeds 5MB limit.', ephemeral=True)
    await interaction.response.defer(thinking=True)
    raw = await file.read()
    res = await run_deobf(raw, file.filename)
    await interaction.followup.send(embed=res['embed'], files=res.get('files', []))

@bot.event
async def on_ready():
    await tree.sync()
    print(f'Ready: {bot.user} | API: {API_URL}')

if __name__ == '__main__':
    bot.run(TOKEN)
