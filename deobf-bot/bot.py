import discord, io, os, httpx, asyncio
from discord.ext import commands
from discord import app_commands

TOKEN = os.environ['DISCORD_BOT_TOKEN']
API_URL = os.environ.get('DEOBF_API_URL', 'http://localhost:5000')

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)
tree = bot.tree

async def call_api(source):
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.post(f'{API_URL}/deobf', json={'source': source})
        return r.json()

@bot.command(name='deobf')
async def deobf(ctx):
    if not ctx.message.attachments:
        return await ctx.send('Attach a .lua file')
    att = ctx.message.attachments[0]
    raw = await att.read()
    try: text = raw.decode('utf-8')
    except: text = raw.decode('latin-1')
    msg = await ctx.send('Deobfuscating...')
    try:
        data = await call_api(text)
    except Exception as e:
        return await msg.edit(content=f'Error: {e}')
    if 'error' in data:
        return await msg.edit(content=f'Failed: {data["error"]}')
    result = data['result']
    file = discord.File(fp=io.StringIO(result), filename='deobf_' + att.filename)
    await ctx.send(file=file)

@tree.command(name='deobf', description='Deobfuscate a Lua file')
@app_commands.describe(file='The .lua file')
async def slash_deobf(interaction: discord.Interaction, file: discord.Attachment):
    await interaction.response.defer(thinking=True)
    raw = await file.read()
    try: text = raw.decode('utf-8')
    except: text = raw.decode('latin-1')
    try:
        data = await call_api(text)
    except Exception as e:
        return await interaction.followup.send(f'Error: {e}')
    if 'error' in data:
        return await interaction.followup.send(f'Failed: {data["error"]}')
    result = data['result']
    out = discord.File(fp=io.StringIO(result), filename='deobf_' + file.filename)
    await interaction.followup.send(file=out)

@bot.event
async def on_ready():
    await tree.sync()
    print(f'Bot ready: {bot.user}')
bot.run(TOKEN)
