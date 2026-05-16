import discord
import io
import os
import httpx
import base64
from discord.ext import commands

TOKEN    = os.environ['DISCORD_BOT_TOKEN']
GROQ_KEY = os.environ.get('GROQ_API_KEY', '')
API_URL  = os.environ.get('DEOBF_API_URL', 'http://localhost:5000')

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)
tree = bot.tree

async def call_api(source_b64):
    async with httpx.AsyncClient(timeout=120) as c:
        r = await c.post(f'{API_URL}/deobf', json={'source_b64': source_b64})
        return r.json()

async def run_deobf(raw_bytes, filename):
    try:
        source_b64 = base64.b64encode(raw_bytes).decode('ascii')
        data = await call_api(source_b64)
    except Exception as e:
        em = discord.Embed(title='API Error', description=str(e), color=0xe74c3c)
        return {'embed': em, 'file': None}
    if 'error' in data:
        em = discord.Embed(title='Deobfuscation failed', description=data['error'], color=0xe74c3c)
        return {'embed': em, 'file': None}
    result = data.get('result', '')
    detected = data.get('detected', 'unknown')
    diagnostic = data.get('diagnostic', '')
    em = discord.Embed(title='Deobfuscation complete', color=0x2ecc71)
    em.add_field(name='Obfuscator', value=detected, inline=True)
    if diagnostic:
        em.add_field(name='Diagnostic', value=diagnostic[:1000], inline=False)
    f = discord.File(fp=io.StringIO(result), filename=f'deobf_{filename}')
    return {'embed': em, 'file': f}

@bot.command(name='deobf')
async def prefix_deobf(ctx):
    if not ctx.message.attachments:
        return await ctx.send('Attach a `.lua` file with `!deobf`')
    att = ctx.message.attachments[0]
    raw = await att.read()
    msg = await ctx.send(embed=discord.Embed(title='Deobfuscating...', color=0x3498db))
    res = await run_deobf(raw, att.filename)
    await msg.delete()
    if res['file']:
        await ctx.send(file=res['file'], embed=res['embed'])
    else:
        await ctx.send(embed=res['embed'])

@tree.command(name='deobf', description='Deobfuscate a Lua file')
async def slash_deobf(interaction: discord.Interaction, file: discord.Attachment):
    await interaction.response.defer(thinking=True)
    raw = await file.read()
    res = await run_deobf(raw, file.filename)
    if res['file']:
        await interaction.followup.send(file=res['file'], embed=res['embed'])
    else:
        await interaction.followup.send(embed=res['embed'])

@bot.event
async def on_ready():
    await tree.sync()
    print(f'Ready: {bot.user} | API: {API_URL}')

if __name__ == '__main__':
    bot.run(TOKEN)
