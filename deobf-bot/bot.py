import discord, io, os, httpx, asyncio, re
from discord.ext import commands
from discord import app_commands
from itertools import cycle

TOKEN      = os.environ['DISCORD_BOT_TOKEN']
GROQ_KEY   = os.environ.get('GROQ_API_KEY', '')
API_URL    = os.environ.get('DEOBF_API_URL', 'http://localhost:5000')

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)
tree = bot.tree

async def call_api(source):
    async with httpx.AsyncClient(timeout=90) as c:
        r = await c.post(f'{API_URL}/deobf', json={'source': source})
        return r.json()

async def ai_diagnose(error_text, profile, sample):
    if not GROQ_KEY or not error_text:
        return None
    prompt = (
        "You are a Lua reverse engineer. The deobfuscation sandbox returned this diagnostic.\n"
        "Explain what went wrong and what specific fix the user should apply.\n\n"
        f"PROFILE: {profile}\nERROR/DIAGNOSTIC:\n{error_text[:1500]}\n\n"
        f"SCRIPT SAMPLE:\n{sample[:1500]}\n\nDiagnosis:"
    )
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(
                'https://api.groq.com/openai/v1/chat/completions',
                headers={'Authorization': f'Bearer {GROQ_KEY}', 'Content-Type': 'application/json'},
                json={'model': 'llama-3.3-70b-versatile', 'max_tokens': 1024, 'messages': [{'role': 'user', 'content': prompt}]}
            )
            return r.json()['choices'][0]['message']['content']
    except:
        return None

async def run_deobf(text, filename):
    try:
        data = await call_api(text)
    except Exception as e:
        em = discord.Embed(title='API Error', description=str(e), color=0xe74c3c)
        return {'embed': em, 'file': None}
    if 'error' in data:
        diag = await ai_diagnose(data.get('diagnostic', ''), str(data.get('detected', '?')), text)
        em = discord.Embed(title='Deobfuscation failed', description=data['error'], color=0xe74c3c)
        if diag:
            em.add_field(name='AI Diagnosis', value=diag[:1000], inline=False)
        return {'embed': em, 'file': None}
    result = data.get('result', '')
    layers = data.get('layers', 0)
    method = data.get('method', 'static')
    detected = data.get('detected', 'unknown')
    diagnostic = data.get('diagnostic', '')
    em = discord.Embed(title='Deobfuscation complete', color=0x2ecc71 if layers > 0 else 0xe67e22)
    em.add_field(name='Obfuscator', value=detected, inline=True)
    em.add_field(name='Method', value=method, inline=True)
    em.add_field(name='Layers', value=str(layers), inline=True)
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
    try:
        text = raw.decode('utf-8')
    except:
        text = raw.decode('latin-1')
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
    try:
        text = raw.decode('utf-8')
    except:
        text = raw.decode('latin-1')
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
