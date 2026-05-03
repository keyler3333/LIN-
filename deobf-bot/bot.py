import discord
import io
import os
import httpx
from discord.ext import commands
from discord import app_commands

TOKEN   = os.environ['DISCORD_BOT_TOKEN']
API_URL = os.environ.get('DEOBF_API_URL', 'http://localhost:5000')

intents = discord.Intents.default()
intents.message_content = True
bot  = commands.Bot(command_prefix='!', intents=intents, help_command=None)
tree = bot.tree


async def call_api(source):
    async with httpx.AsyncClient(timeout=120) as c:
        r = await c.post(f'{API_URL}/deobf', json={'source': source})
        return r.json()


async def run_deobf(text, filename):
    try:
        data = await call_api(text)
    except Exception as e:
        em = discord.Embed(title='API Error', description=str(e), color=0xe74c3c)
        return {'embed': em, 'file': None}

    if 'error' in data:
        em = discord.Embed(title='Deobfuscation failed', description=data['error'], color=0xe74c3c)
        return {'embed': em, 'file': None}

    result     = data.get('result', '')
    detected   = data.get('detected', 'unknown')
    diagnostic = data.get('diagnostic', '')

    if len(result.encode()) > 7_500_000:
        result = result[:1_000_000] + "\n-- Output truncated (too large for Discord)"

    em = discord.Embed(title='Deobfuscation complete', color=0x2ecc71)
    em.add_field(name='Obfuscator', value=detected, inline=True)
    if diagnostic:
        em.add_field(name='Diagnostic', value=diagnostic[:1000], inline=False)

    f = discord.File(fp=io.StringIO(result), filename=f'deobf_{filename}')
    return {'embed': em, 'file': f}


@bot.command(name='deobf')
async def prefix_deobf(ctx, flags: str = ''):
    if not ctx.message.attachments:
        return await ctx.send('Attach a `.lua` file with `!deobf`')
    att = ctx.message.attachments[0]
    raw = await att.read()
    try:    text = raw.decode('utf-8')
    except: text = raw.decode('latin-1')
    msg = await ctx.send(embed=discord.Embed(title='Deobfuscating...', color=0x3498db))
    res = await run_deobf(text, att.filename)
    await msg.delete()
    if res['file']:
        await ctx.send(file=res['file'], embed=res['embed'])
    else:
        await ctx.send(embed=res['embed'])


@tree.command(name='deobf', description='Deobfuscate a Lua file')
@app_commands.describe(file='The .lua file to deobfuscate')
async def slash_deobf(interaction: discord.Interaction, file: discord.Attachment):
    await interaction.response.defer(thinking=True)
    raw = await file.read()
    try:    text = raw.decode('utf-8')
    except: text = raw.decode('latin-1')
    res = await run_deobf(text, file.filename)
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
