import discord
import io
import os
import re
import httpx
import base64
from discord.ext import commands

TOKEN   = os.environ.get('DISCORD_BOT_TOKEN')
API_URL = os.environ.get('DEOBF_API_URL', 'http://localhost:5000')

if not TOKEN:
    raise SystemExit("DISCORD_BOT_TOKEN not set.")

intents = discord.Intents.default()
intents.message_content = True
bot  = commands.Bot(command_prefix='!', intents=intents, help_command=None)
tree = bot.tree

ALLOWED_EXTENSIONS = ('.lua', '.txt', '.luau')
MAX_BYTES = 5 * 1024 * 1024


async def call_api(source_b64):
    async with httpx.AsyncClient(timeout=120) as c:
        r = await c.post(f'{API_URL}/deobf', json={'source_b64': source_b64})
        r.raise_for_status()
        return r.json()


def _extract_inline_code(content):
    m = re.search(r'```(?:lua|luau|txt)?\s*\n?(.*?)```', content, re.DOTALL)
    if m:
        return m.group(1).strip()
    stripped = content.strip()
    return stripped or None


async def run_deobf(raw_bytes, filename):
    if len(raw_bytes) > MAX_BYTES:
        return {
            'embed': discord.Embed(title='Error', description='Input exceeds 5 MB limit', color=0xe74c3c),
            'files': [],
        }
    try:
        source_b64 = base64.b64encode(raw_bytes).decode('ascii')
        data = await call_api(source_b64)
    except Exception as e:
        return {
            'embed': discord.Embed(title='API Error', description=str(e)[:1800], color=0xe74c3c),
            'files': [],
        }
    if 'error' in data:
        return {
            'embed': discord.Embed(title='Deobfuscation Failed', description=data['error'][:1800], color=0xe74c3c),
            'files': [],
        }

    result     = data.get('result', '')
    detected   = data.get('detected', 'unknown')
    diagnostic = data.get('diagnostic', '')

    SUCCESS_METHODS = ('static_lift', 'static_decode', 'unluac', 'lune_capture',
                       'lune_unluac', 'sandbox_capture', 'sandbox_unluac')
    color = 0x2ecc71 if detected in SUCCESS_METHODS else (0xe67e22 if detected not in ('unable',) else 0xe74c3c)

    em = discord.Embed(title='Deobfuscation Complete', color=color)
    em.add_field(name='Method',   value=f'`{detected}`', inline=True)
    em.add_field(name='Input',    value=filename,        inline=True)
    if diagnostic:
        em.add_field(name='Diagnostic', value=diagnostic[:1000], inline=False)

    files = []
    if result and detected != 'bytecode':
        files.append(discord.File(fp=io.StringIO(result), filename=f'deobf_{filename}'))
    elif detected == 'bytecode' and result:
        raw_out = base64.b64decode(result)
        files.append(discord.File(fp=io.BytesIO(raw_out), filename=f'extracted_{filename}.luac'))

    return {'embed': em, 'files': files}


@bot.command(name='deobf')
@commands.cooldown(1, 30, commands.BucketType.user)
async def prefix_deobf(ctx):
    raw = None
    filename = 'input.lua'

    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        if not att.filename.lower().endswith(ALLOWED_EXTENSIONS):
            return await ctx.send('Please attach a `.lua`, `.luau`, or `.txt` file.')
        if att.size > MAX_BYTES:
            return await ctx.send('File exceeds 5 MB limit.')
        raw      = await att.read()
        filename = att.filename
    else:
        body = ctx.message.content
        cmd_end = body.lower().find('deobf')
        if cmd_end != -1:
            body = body[cmd_end + len('deobf'):].strip()
        code = _extract_inline_code(body)
        if not code:
            return await ctx.send(
                'Attach a `.lua` file **or** paste code (with or without \\`\\`\\`lua fences) after `!deobf`.'
            )
        raw = code.encode('utf-8')

    msg = await ctx.send(embed=discord.Embed(
        title='⚙️ Deobfuscating…',
        description='Running all engines. This may take up to 90 s.',
        color=0x3498db,
    ))
    res = await run_deobf(raw, filename)
    try:
        await msg.delete()
    except discord.NotFound:
        pass
    await ctx.send(embed=res['embed'], files=res.get('files', []))


@prefix_deobf.error
async def deobf_error(ctx, error):
    if isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f'Cooldown — try again in {error.retry_after:.0f} s.')


@tree.command(name='deobf', description='Deobfuscate a Lua file')
async def slash_deobf(interaction: discord.Interaction, file: discord.Attachment):
    if not file.filename.lower().endswith(ALLOWED_EXTENSIONS):
        return await interaction.response.send_message(
            'Please attach a `.lua`, `.luau`, or `.txt` file.', ephemeral=True)
    if file.size > MAX_BYTES:
        return await interaction.response.send_message(
            'File exceeds 5 MB limit.', ephemeral=True)
    await interaction.response.defer(thinking=True)
    raw = await file.read()
    res = await run_deobf(raw, file.filename)
    await interaction.followup.send(embed=res['embed'], files=res.get('files', []))


@bot.command(name='help')
async def help_cmd(ctx):
    em = discord.Embed(title='Deobfuscator Help', color=0x3498db)
    em.add_field(
        name='!deobf [file or pasted code]',
        value=(
            'Deobfuscate Lua source.\n'
            '• Attach a `.lua` / `.luau` / `.txt` file, **or**\n'
            '• Paste code directly (with or without \\`\\`\\`lua fences)\n'
            '• 30 s cooldown per user'
        ),
        inline=False,
    )
    em.add_field(
        name='/deobf',
        value='Slash command — attach a file via the attachment picker.',
        inline=False,
    )
    await ctx.send(embed=em)


@bot.event
async def on_ready():
    await tree.sync()
    print(f'Ready: {bot.user}  |  API: {API_URL}')


if __name__ == '__main__':
    bot.run(TOKEN)
