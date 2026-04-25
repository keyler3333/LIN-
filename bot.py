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

SIGNATURES = {
    'luraph': {
        r'loadstring\s*\(\s*\(function\s*\(': 10,
        r'bytecode\s*=\s*["\']': 8,
        r'return\s+\(function\s*\(': 5,
        r'\\x[0-9a-fA-F]{2}': 3,
        r'[A-Za-z0-9+/]{200,}={0,2}': 6,
    },
    'moonsec': {
        r'local\s+\w+\s*=\s*\{\s*\d+\s*,\s*\d+': 10,
        r'_moon\s*=\s*function': 8,
        r'local\s+\w+\s*=\s*\{.*?\}': 5,
        r'\\x[0-9a-fA-F]{2}': 4,
    },
    'ironbrew': {
        r'local\s+\w+\s*=\s*{"\\x': 10,
        r'getfenv\b': 8,
        r'setfenv\b': 6,
        r'%[0-9a-fA-F]{2}': 4,
    },
    'wearedevs': {
        r'show_\w+\s*=\s*function': 10,
        r'getfenv\b': 7,
        r'string\.char\(': 5,
        r'\w{25,}': 3,
    },
    'custom_vm': {
        r'mkexec': 10,
        r'constTags': 8,
        r'protoFormats': 8,
        r'local\s+\w+\s*=\s*\{.*code\s*=\s*\{': 10,
        r'xb\s*=\s*': 5,
    },
    'synapse': {
        r'syn\.': 10,
        r'compress': 7,
        r'Bytecode': 5,
    },
    'aurora': {
        r'__aurora': 10,
        r'Aurora\s*=': 8,
    },
    'sentinel': {
        r'Sentinel\s*=': 10,
        r'V3': 7,
    },
}

def detect_obfuscator(raw_bytes):
    scores = {}
    for name, patterns in SIGNATURES.items():
        total = 0
        for pat, weight in patterns.items():
            if re.search(pat, raw_bytes, re.IGNORECASE):
                total += weight
        if total > 0:
            scores[name] = total
    if scores:
        return max(scores, key=scores.get)
    return 'generic'

class LuaDecompiler:
    def __init__(self, bc: bytes):
        self.bc = bc
        self.pos = 12
        self.constants = []
        self.locals = []

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
        source_name = self.read_string()
        line_defined = self.read_int()
        last_line = self.read_int()
        upvalues = self.read_byte()
        num_params = self.read_byte()
        is_vararg = self.read_byte()
        max_stack = self.read_byte()
        code_len = self.read_int()
        instructions = []
        for _ in range(code_len):
            instructions.append(self.read_int())
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
        for i in range(proto_len):
            self.read_function()
        self.locals = []
        local_len = self.read_int()
        for _ in range(local_len):
            name = self.read_string()
            start_pc = self.read_int()
            end_pc = self.read_int()
            self.locals.append((name, start_pc, end_pc))
        debug_line_count = self.read_int()
        for _ in range(debug_line_count):
            self.read_int()
        debug_upvalue_count = self.read_int()
        for _ in range(debug_upvalue_count):
            self.read_string()
        return (instructions, constants, num_params, is_vararg, max_stack)

    def decompile(self):
        code, consts, params, vararg, stack = self.read_function()
        lines = []
        regs = [None] * 256
        
        for i in range(params):
            regs[i] = f"arg{i+1}"
        
        if vararg:
            lines.append("local vararg = {...}")

        def rk(v):
            if v >= 256:
                idx = v - 256
                if idx < len(consts):
                    c = consts[idx]
                    if isinstance(c, str):
                        return repr(c)
                    if c is None:
                        return "nil"
                    if isinstance(c, bool):
                        return "true" if c else "false"
                    return str(c)
                return f"k[{idx}]"
            if v < len(regs) and regs[v] is not None:
                return regs[v]
            return f"R{v}"

        labels = set()
        for idx, instr in enumerate(code):
            op = instr & 0x3F
            if op == 22:
                sx_b = (instr >> 14) & 0x1FFFF
                if sx_b & 0x10000:
                    sx_b = -((~sx_b & 0xFFFF) + 1)
                target = idx + 1 + sx_b
                if target != idx + 1:
                    labels.add(target)

        pc = 0
        while pc < len(code):
            if pc in labels:
                lines.append(f"::L{pc}::")

            for name, start, end in self.locals:
                if start == pc:
                    lines.append(f"local {name}")

            instr = code[pc]
            op = instr & 0x3F
            a = (instr >> 6) & 0xFF
            c = (instr >> 14) & 0x1FF
            b = (instr >> 23) & 0x1FF

            pc += 1

            if op == 0:
                regs[a] = rk(b)
            elif op == 1:
                regs[a] = rk(b + 256)
            elif op == 2:
                regs[a] = "true" if b else "false"
                if c:
                    pc += 1
            elif op == 3:
                for i in range(a, b + 1):
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
            elif op == 11:
                regs[a + 1] = rk(b)
                regs[a] = f"{rk(b)}[{rk(c)}]"
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
                parts = [str(rk(i)) for i in range(b, c + 1)]
                regs[a] = " .. ".join(parts)
            elif op == 22:
                sx_b = (instr >> 14) & 0x1FFFF
                if sx_b & 0x10000:
                    sx_b = -((~sx_b & 0xFFFF) + 1)
                target = pc + sx_b
                lines.append(f"goto L{target}")
                continue
            elif op == 23:
                neg = a == 1
                lines.append(f"if {rk(b)} {'~=' if neg else '=='} {rk(c)} then goto L{pc + 1} end")
            elif op == 24:
                neg = a == 1
                lines.append(f"if {rk(b)} {'>=' if neg else '<'} {rk(c)} then goto L{pc + 1} end")
            elif op == 25:
                neg = a == 1
                lines.append(f"if {rk(b)} {'>' if neg else '<='} {rk(c)} then goto L{pc + 1} end")
            elif op == 26:
                if c == 0:
                    lines.append(f"if not {rk(a)} then goto L{pc + 1} end")
                else:
                    lines.append(f"if {rk(a)} then goto L{pc + 1} end")
            elif op == 27:
                if c == 0:
                    lines.append(f"if not {rk(b)} then goto L{pc+1} end")
                else:
                    lines.append(f"if {rk(b)} then goto L{pc+1} end")
                regs[a] = rk(b)
            elif op == 28:
                nargs = max(b - 1, 0)
                args = [str(rk(a + 1 + i)) for i in range(nargs)]
                nret = c - 1
                if nret == -1:
                    lines.append(f"{rk(a)}({', '.join(args)})")
                elif nret == 0:
                    lines.append(f"local _ = {rk(a)}({', '.join(args)})")
                elif nret == 1:
                    lines.append(f"local R{a} = {rk(a)}({', '.join(args)})")
                else:
                    rets = [f"R{a + i}" for i in range(nret)]
                    lines.append(f"local {', '.join(rets)} = {rk(a)}({', '.join(args)})")
            elif op == 29:
                nargs = max(b - 1, 0)
                args = [str(rk(a + 1 + i)) for i in range(nargs)]
                lines.append(f"return {rk(a)}({', '.join(args)})")
                break
            elif op == 30:
                nret = b - 1
                if nret == -1:
                    lines.append("return")
                elif nret == 0:
                    lines.append("do return end")
                else:
                    rets = [str(rk(a + i)) for i in range(nret)]
                    lines.append(f"return {', '.join(rets)}")
                break
            elif op == 31:
                lines.append("do")
                lines.append(f"  {rk(a+3)} = {rk(a)}")
                lines.append(f"  if {rk(a)} + {rk(a+2)} <= {rk(a+1)} then")
                lines.append(f"    {rk(a)} = {rk(a)} + {rk(a+2)}")
                lines.append(f"    goto L{pc + c}")
                lines.append("  end")
                lines.append("end")
            elif op == 33:
                vars_list = [str(rk(a + 3 + i)) for i in range(c)]
                lines.append(f"for {', '.join(vars_list)} in {rk(a)}, {rk(a+1)}, {rk(a+2)} do")
                pc += b + 1
                lines.append("end")
            elif op == 36:
                regs[a] = f"function_{b}"
            elif op == 37:
                if b == 1:
                    regs[a] = "vararg"

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

def deobfuscate_bytecode(source):
    b64_patterns = [
        r'bytecode\s*=\s*"(.*?)"',
        r'bytecode\s*=\s*\'(.*?)\'',
        r'\[==\[(.*?)\]==\]',
        r'["\']([A-Za-z0-9+/=]{100,})["\']',
    ]
    b64 = None
    for pat in b64_patterns:
        m = re.search(pat, source, re.DOTALL)
        if m:
            b64 = m.group(1).replace('\n', '').replace(' ', '').replace('\r', '')
            break
    if not b64:
        return None
    try:
        encrypted = base64.b64decode(b64)
    except:
        return None
    for k in range(256):
        test = bytes(b ^ k for b in encrypted[:4])
        if test == b'\x1bLua':
            bytecode = bytes(b ^ k for b in encrypted)
            dec = LuaDecompiler(bytecode)
            return dec.decompile()
    return None

def deobfuscate_moonsec(source):
    chunks = re.findall(r'local\s+\w+\s*=\s*\{([^}]+)\}', source)
    if not chunks:
        return None
    bytecode_parts = []
    for chunk in chunks:
        nums = [int(x.strip()) for x in chunk.split(',') if x.strip().lstrip('-').isdigit()]
        bytecode_parts.append(bytes(nums))
    full = b''.join(bytecode_parts)
    if len(full) > 12 and full[:4] == b'\x1bLua':
        dec = LuaDecompiler(full)
        return dec.decompile()
    return None

def deobfuscate_ironbrew(source):
    match = re.search(r'local\s+\w+\s*=\s*\{([^}]+)\}', source)
    if not match:
        return None
    vals = re.findall(r'\d+', match.group(1))
    out = []
    for v in vals:
        try:
            out.append(struct.pack('<I', int(v)))
        except:
            pass
    bytecode = b''.join(out)
    if len(bytecode) > 12 and bytecode[:4] == b'\x1bLua':
        dec = LuaDecompiler(bytecode)
        return dec.decompile()
    return None

def deobfuscate_generic(source):
    result = deobfuscate_bytecode(source)
    if result:
        return result
    loadstring_matches = re.findall(r'loadstring\s*\(\s*["\'](.*?)["\']\s*\)', source, re.DOTALL)
    if loadstring_matches:
        return deobfuscate_generic(loadstring_matches[-1])
    return 'Could not deobfuscate. Unsupported or corrupt obfuscation.'

def deobfuscate(source, obf_type):
    if obf_type == 'luraph':
        return deobfuscate_bytecode(source) or deobfuscate_generic(source)
    elif obf_type == 'moonsec':
        return deobfuscate_moonsec(source) or deobfuscate_generic(source)
    elif obf_type == 'ironbrew':
        return deobfuscate_ironbrew(source) or deobfuscate_generic(source)
    elif obf_type == 'custom_vm':
        return deobfuscate_generic(source)
    else:
        return deobfuscate_generic(source)

@bot.command(name='deobf')
async def deobf(ctx):
    async with ctx.typing():
        await asyncio.sleep(1)
        
        if not ctx.message.attachments:
            return await ctx.send('Please attach a `.lua` file with the command: `!deobf`')
        
        attachment = ctx.message.attachments[0]
        
        if not attachment.filename.lower().endswith(('.lua', '.txt', '.luac')):
            return await ctx.send('Please attach a `.lua` file.')
        
        raw = await attachment.read()
        
        try:
            text = raw.decode('utf-8')
        except:
            try:
                text = raw.decode('latin-1')
            except:
                return await ctx.send('File encoding not supported.')
        
        await ctx.send('\U0001f50d **Analyzing obfuscation...**')
        await asyncio.sleep(0.5)
        obf_type = detect_obfuscator(raw)
        
        await ctx.send(f'\U0001f513 **Detected:** `{obf_type}` — reversing protection layers...')
        await asyncio.sleep(0.5)
        result = deobfuscate(text, obf_type)
        
        await asyncio.sleep(0.5)
        
        file = discord.File(fp=io.StringIO(result), filename=f'deobfuscated_{attachment.filename}')
        await ctx.send(f'\u2705 **Deobfuscated!** `{obf_type}` → clean Lua below:', file=file)

@bot.event
async def on_ready():
    print(f'Bot online as {bot.user}')

if __name__ == '__main__':
    bot.run(TOKEN)
