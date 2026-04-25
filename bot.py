import discord
import re
import io
import os
import base64
import struct
import asyncio
from discord.ext import commands

TOKEN = os.environ['DISCORD_BOT_TOKEN']
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

OBFUSCATOR_PATTERNS = {
    'luraph': [
        r'loadstring\s*\(\s*\(function\s*\(',
        r'bytecode\s*=\s*["\'][A-Za-z0-9+/=]{50,}["\']',
        r';\s*local\s+\w+\s*=\s*\{',
        r'\\x[0-9a-fA-F]{2}',
    ],
    'moonsec': [
        r'local\s+\w+\s*=\s*\{[\d\s,]+\}',
        r'_moon\s*=\s*function',
        r'moon_\w+\s*=\s*\{',
    ],
    'ironbrew': [
        r'local\s+\w+\s*=\s*\{\s*"\\x[0-9a-fA-F]{2}',
        r'getfenv\s*\(\)',
        r'%[0-9a-fA-F]{2}',
    ],
    'ironbrew2': [
        r'local\s+\w+\s*=\s*\{\s*"\\x[0-9a-fA-F]{2}',
        r'\%*\%*\%*',
    ],
    'wearedevs': [
        r'show_\w+\s*=\s*function',
        r'getfenv\s*\(\)',
    ],
    'custom_vm': [
        r'mkexec',
        r'constTags',
        r'protoFormats',
    ],
    'synapse': [
        r'syn\.\w+\s*=\s*',
        r'Bytecode',
    ],
    'aurora': [
        r'__aurora\s*=\s*',
        r'Aurora\s*=\s*',
    ],
    'sentinel': [
        r'Sentinel\s*=\s*',
        r'V3',
    ],
    'psu': [
        r'ProtectedString',
        r'ByteCode',
    ],
    'xen': [
        r'Xen\s*=\s*',
        r'Bytecode',
    ],
    'obfuscatorx': [
        r'OBF\s*=\s*',
    ],
    'luaarmor': [
        r'armor\s*=\s*',
        r'___armor_',
    ],
    'sk8r': [
        r'sk8r\s*=\s*',
    ],
    'vmprotect': [
        r'local\s+f\s*=\s*loadstring',
    ],
}

def detect_obfuscator(text):
    scores = {}
    for name, pats in OBFUSCATOR_PATTERNS.items():
        total = 0
        for pat in pats:
            if re.search(pat, text, re.IGNORECASE):
                total += 1
        if total > 0:
            scores[name] = total
    if scores:
        best = max(scores, key=lambda k: scores[k])
        if scores[best] >= 2:
            return best
        if 'luraph' in scores and scores['luraph'] >= 1:
            return 'luraph'
    return 'generic'

def decode_hex_string(code):
    def hex_replace(m):
        hex_str = m.group(1)
        try:
            char = chr(int(hex_str, 16))
            return char
        except:
            return m.group(0)
    return re.sub(r'\\x([0-9a-fA-F]{2})', hex_replace, code)

def decode_string_char(code):
    def char_replace(m):
        nums = m.group(1)
        chars = []
        for n in re.findall(r'\d+', nums):
            try:
                chars.append(chr(int(n)))
            except:
                pass
        return '"' + ''.join(chars) + '"'
    code = re.sub(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', char_replace, code)
    return code

def unwrap_loadstring(code):
    max_passes = 10
    for _ in range(max_passes):
        match = re.search(r'loadstring\s*\(\s*["\'](.*?)["\']\s*\)\s*\(?\s*\)?', code, re.DOTALL)
        if not match:
            break
        inner = match.group(1)
        inner = inner.replace('\\"', '"').replace('\\\'', '\'')
        code = code[:match.start()] + inner + code[match.end():]
    return code

def try_extract_lua_bytecode(code):
    for b64_pat in [r'["\']([A-Za-z0-9+/=]{100,})["\']', r'\[==\[(.*?)\]==\]']:
        m = re.search(b64_pat, code, re.DOTALL)
        if m:
            b64 = m.group(1).replace('\n','').replace(' ','')
            try:
                data = base64.b64decode(b64)
                for key in range(256):
                    decrypted = bytes([b ^ key for b in data])
                    if decrypted[:4] == b'\x1bLua':
                        dec = _decompile_lua51(decrypted)
                        if dec:
                            return dec
            except:
                continue
    return None

class Lua51Decompiler:
    def __init__(self, bc):
        self.bc = bc
        self.pos = 12

    def read_byte(self):
        v = self.bc[self.pos]
        self.pos += 1
        return v

    def read_int(self):
        v = int.from_bytes(self.bc[self.pos:self.pos+4], 'little')
        self.pos += 4
        return v

    def read_size_t(self):
        return self.read_int()

    def read_string(self):
        size = self.read_size_t()
        if size == 0:
            return ""
        s = self.bc[self.pos:self.pos+size-1].decode('utf-8', errors='replace')
        self.pos += size
        return s

    def read_number(self):
        size = self.read_size_t()
        if size == 0:
            return 0
        raw = self.bc[self.pos:self.pos+size-1]
        self.pos += size
        try:
            s = raw.decode('utf-8')
            if '.' in s or 'e' in s.lower():
                return float(s)
            return int(s)
        except:
            return 0

    def read_function(self):
        self.read_string()
        self.read_int()
        self.read_int()
        self.read_byte()
        num_params = self.read_byte()
        self.read_byte()
        self.read_byte()
        code_len = self.read_int()
        instructions = [self.read_int() for _ in range(code_len)]
        const_len = self.read_int()
        constants = []
        for _ in range(const_len):
            t = self.read_byte()
            if t == 0:
                constants.append(None)
            elif t == 1:
                constants.append(self.read_byte() != 0)
            elif t == 3:
                constants.append(self.read_number())
            elif t == 4:
                constants.append(self.read_string())
            else:
                constants.append(None)
        proto_len = self.read_int()
        for _ in range(proto_len):
            self.read_function()
        local_len = self.read_int()
        locals_info = []
        for _ in range(local_len):
            name = self.read_string()
            start_pc = self.read_int()
            end_pc = self.read_int()
            locals_info.append((name, start_pc, end_pc))
        self.read_int()
        for _ in range(self.read_int()):
            self.read_string()
        return instructions, constants, num_params, locals_info

    def decompile(self):
        instrs, consts, params, locals_info = self.read_function()
        regs = [None]*256
        lines = []
        for i in range(params):
            regs[i] = f"arg{i+1}"
        def rk(v):
            if v >= 256:
                idx = v-256
                if idx < len(consts):
                    c = consts[idx]
                    if isinstance(c, str):
                        return repr(c)
                    if c is None: return "nil"
                    return str(c).lower() if isinstance(c,bool) else str(c)
                return f"k[{idx}]"
            if v < len(regs) and regs[v] is not None:
                return regs[v]
            return f"R{v}"
        labels = set()
        for idx, instr in enumerate(instrs):
            op = instr & 0x3F
            if op == 22:
                sx_b = (instr >> 14) & 0x1FFFF
                if sx_b & 0x10000:
                    sx_b = -((~sx_b & 0xFFFF)+1)
                target = idx+1+sx_b
                if target != idx+1:
                    labels.add(target)
        pc = 0
        while pc < len(instrs):
            if pc in labels:
                lines.append(f"::L{pc}::")
            for name, s, e in locals_info:
                if s == pc:
                    lines.append(f"local {name}")
            instr = instrs[pc]
            op = instr & 0x3F
            a = (instr >> 6) & 0xFF
            c = (instr >> 14) & 0x1FF
            b = (instr >> 23) & 0x1FF
            pc += 1
            if op == 0:
                regs[a] = rk(b)
            elif op == 1:
                regs[a] = rk(b+256)
            elif op == 2:
                regs[a] = "true" if b else "false"
                if c: pc += 1
            elif op == 3:
                for i in range(a, b+1):
                    regs[i] = "nil"
            elif op == 5:
                if b < len(consts):
                    regs[a] = consts[b]
                else:
                    regs[a] = f'_G["{b}"]'
            elif op == 6:
                regs[a] = f"{rk(b)}[{rk(c)}]"
            elif op == 7:
                if b < len(consts):
                    lines.append(f"{consts[b]} = {rk(a)}")
                else:
                    lines.append(f'_G["{b}"] = {rk(a)}')
            elif op == 9:
                lines.append(f"{rk(a)}[{rk(b)}] = {rk(c)}")
            elif op == 10:
                regs[a] = "{}"
            elif op == 12:
                regs[a] = f"({rk(b)} + {rk(c)})"
            elif op == 13:
                regs[a] = f"({rk(b)} - {rk(c)})"
            elif op == 14:
                regs[a] = f"({rk(b)} * {rk(c)})"
            elif op == 15:
                regs[a] = f"({rk(b)} / {rk(c)})"
            elif op == 16:
                regs[a] = f"({rk(b)} % {rk(c)})"
            elif op == 17:
                regs[a] = f"({rk(b)} ^ {rk(c)})"
            elif op == 18:
                regs[a] = f"-{rk(b)}"
            elif op == 19:
                regs[a] = f"not {rk(b)}"
            elif op == 20:
                regs[a] = f"#{rk(b)}"
            elif op == 21:
                parts = [str(rk(i)) for i in range(b, c+1)]
                regs[a] = " .. ".join(parts)
            elif op == 22:
                sx_b = (instr >> 14) & 0x1FFFF
                if sx_b & 0x10000:
                    sx_b = -((~sx_b & 0xFFFF)+1)
                target = pc + sx_b
                lines.append(f"goto L{target}")
                continue
            elif op == 23:
                neg = a == 1
                lines.append(f"if {rk(b)} {'~=' if neg else '=='} {rk(c)} then goto L{pc+1} end")
            elif op == 24:
                neg = a == 1
                lines.append(f"if {rk(b)} {'>=' if neg else '<'} {rk(c)} then goto L{pc+1} end")
            elif op == 25:
                neg = a == 1
                lines.append(f"if {rk(b)} {'>' if neg else '<='} {rk(c)} then goto L{pc+1} end")
            elif op == 26:
                if c == 0:
                    lines.append(f"if not {rk(a)} then goto L{pc+1} end")
                else:
                    lines.append(f"if {rk(a)} then goto L{pc+1} end")
            elif op == 27:
                if c == 0:
                    lines.append(f"if not {rk(b)} then goto L{pc+1} end")
                else:
                    lines.append(f"if {rk(b)} then goto L{pc+1} end")
                regs[a] = rk(b)
            elif op == 28:
                nargs = max(b-1,0)
                args = [str(rk(a+1+i)) for i in range(nargs)]
                nret = c-1
                if nret == -1:
                    lines.append(f"{rk(a)}({', '.join(args)})")
                elif nret == 0:
                    lines.append(f"local _ = {rk(a)}({', '.join(args)})")
                elif nret == 1:
                    lines.append(f"local R{a} = {rk(a)}({', '.join(args)})")
                else:
                    rets = [f"R{a+i}" for i in range(nret)]
                    lines.append(f"local {', '.join(rets)} = {rk(a)}({', '.join(args)})")
            elif op == 29:
                nargs = max(b-1,0)
                args = [str(rk(a+1+i)) for i in range(nargs)]
                lines.append(f"return {rk(a)}({', '.join(args)})")
                break
            elif op == 30:
                nret = b-1
                if nret == -1:
                    lines.append("return")
                elif nret == 0:
                    lines.append("do return end")
                else:
                    rets = [str(rk(a+i)) for i in range(nret)]
                    lines.append(f"return {', '.join(rets)}")
                break
            elif op == 33:
                vars_list = [str(rk(a+3+i)) for i in range(c)]
                lines.append(f"for {', '.join(vars_list)} in {rk(a)}, {rk(a+1)}, {rk(a+2)} do")
                pc += b+1
                lines.append("end")
        result = []
        if params > 0:
            args = ", ".join([f"arg{i+1}" for i in range(params)])
            result.append(f"local function main({args})")
        else:
            result.append("local function main()")
        for line in lines:
            result.append(f"  {line}")
        result.append("end")
        result.append("return main()")
        return "\n".join(result)

def _decompile_lua51(bytecode):
    try:
        dec = Lua51Decompiler(bytecode)
        return dec.decompile()
    except:
        return None

def beautify_lua(code):
    indent = 0
    lines = code.split('\n')
    out = []
    for line in lines:
        stripped = line.strip()
        if stripped.endswith('end') or stripped.endswith(')') or stripped.endswith('}'):
            indent = max(0, indent-1)
        out.append('    '*indent + stripped)
        if stripped.startswith('if ') or stripped.startswith('for ') or stripped.startswith('while ') or stripped.startswith('function ') or stripped.startswith('do') or stripped.startswith('repeat'):
            indent += 1
        elif stripped.endswith('then') or stripped.endswith('do') or stripped.endswith('{') or stripped.endswith('('):
            pass
    return '\n'.join(out)

def deobfuscate(text, obf_type):
    code = text
    code = decode_hex_string(code)
    code = decode_string_char(code)
    code = unwrap_loadstring(code)
    bytecode_decompiled = try_extract_lua_bytecode(code)
    if bytecode_decompiled:
        return beautify_lua(bytecode_decompiled)
    code = beautify_lua(code)
    return code

@bot.command(name='deobf')
async def deobf(ctx):
    if not ctx.message.attachments:
        return await ctx.send('Please attach a `.lua` file.')
    attachment = ctx.message.attachments[0]
    if not attachment.filename.lower().endswith(('.lua', '.txt', '.luac')):
        return await ctx.send('Only `.lua` files are supported.')
    raw = await attachment.read()
    try:
        text = raw.decode('utf-8')
    except:
        try:
            text = raw.decode('latin-1')
        except:
            return await ctx.send('File encoding not supported.')

    embed = discord.Embed(title="🔍 Analyzing obfuscation...", color=0x3498db)
    msg = await ctx.send(embed=embed)
    await asyncio.sleep(1)

    obf_type = detect_obfuscator(text)
    embed.title = f"🔓 Detected: {obf_type}"
    embed.description = "Decoding hex strings..."
    embed.color = 0xf39c12
    await msg.edit(embed=embed)
    await asyncio.sleep(0.5)

    embed.description += "\nReplacing string.char calls..."
    await msg.edit(embed=embed)
    await asyncio.sleep(0.5)

    embed.description += "\nUnwrapping loadstring layers..."
    await msg.edit(embed=embed)
    await asyncio.sleep(0.5)

    embed.description += "\nSearching for embedded bytecode..."
    await msg.edit(embed=embed)
    await asyncio.sleep(0.5)

    result = deobfuscate(text, obf_type)
    embed.description += "\nBeautifying output..."
    embed.color = 0x2ecc71
    await msg.edit(embed=embed)
    await asyncio.sleep(0.5)

    file = discord.File(fp=io.StringIO(result), filename=f'deobfuscated_{attachment.filename}')
    embed2 = discord.Embed(title="✅ Deobfuscation complete", description="Clean Lua attached.", color=0x2ecc71)
    await ctx.send(embed=embed2, file=file)

@bot.event
async def on_ready():
    print(f'Bot online as {bot.user}')

if __name__ == '__main__':
    bot.run(TOKEN)
