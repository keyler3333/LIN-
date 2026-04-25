import discord
import re
import io
import os
import base64
import struct
from discord.ext import commands

TOKEN = os.environ['DISCORD_BOT_TOKEN']
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

SIGNATURES = {
    'custom_vm': [
        rb'mkexec',
        rb'constTags',
        rb'protoFormats',
    ],
    'luraph': [
        rb'loadstring',
        rb'bytecode\s*=\s*["\']',
        rb'return\s+\(function\s*\(',
    ],
    'moonsec': [
        rb'local\s+\w+\s*=\s*\{.*\d+\s*,\s*\d+',
        rb'_moon\s*=\s*function',
    ],
    'ironbrew': [
        rb'local\s+\w+\s*=\s*{"\\x',
        rb'getfenv',
    ],
    'wearedevs': [
        rb'show_\w+\s*=\s*function',
        rb'getfenv',
    ],
    'psu': [
        rb'ProtectedString',
        rb'ByteCode',
    ],
    'xen': [
        rb'Xen\s*=\s*',
        rb'Bytecode',
    ],
    'aurora': [
        rb'Aurora\s*=\s*',
        rb'__aurora',
    ],
    'synapse': [
        rb'syn\.',
        rb'compress',
    ],
    'sentinel': [
        rb'Sentinel\s*=\s*',
        rb'V3',
    ],
}

def detect_obfuscator(raw_bytes):
    scores = {}
    for name, patterns in SIGNATURES.items():
        hits = sum(1 for p in patterns if re.search(p, raw_bytes, re.IGNORECASE))
        if hits > 0:
            scores[name] = hits
    if scores:
        return max(scores, key=scores.get)
    return 'unknown'

class LuaDecompiler:
    def __init__(self, bc: bytes):
        self.bc = bc
        self.pos = 12
        self.strings = []
        self.constants = []
        self.protos = {}
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
            if s.find('.') != -1 or s.find('e') != -1:
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
            self.protos[f"func_{len(self.protos)}"] = self.read_function()
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
            elif op == 4:
                regs[a] = f"upval_{b}"
            elif op == 5:
                if b < len(consts):
                    regs[a] = consts[b]
                else:
                    regs[a] = f"_G[\"{b}\"]"
            elif op == 6:
                regs[a] = f"{rk(b)}[{rk(c)}]"
            elif op == 7:
                if b < len(consts):
                    lines.append(f"{consts[b]} = {rk(a)}")
                else:
                    lines.append(f"_G[\"{b}\"] = {rk(a)}")
            elif op == 8:
                lines.append(f"upval_{b} = {rk(a)}")
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
                nargs = b - 1
                if nargs < 0:
                    nargs = 0
                args = []
                for i in range(nargs):
                    args.append(str(rk(a + 1 + i)))
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
                nargs = b - 1
                if nargs < 0:
                    nargs = 0
                args = []
                for i in range(nargs):
                    args.append(str(rk(a + 1 + i)))
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
                lines.append(f"do")
                lines.append(f"  {rk(a+3)} = {rk(a)}")
                lines.append(f"  if {rk(a)} + {rk(a+2)} <= {rk(a+1)} then")
                lines.append(f"    {rk(a)} = {rk(a)} + {rk(a+2)}")
                lines.append(f"    goto L{pc + c}")
                lines.append(f"  end")
                lines.append(f"end")
            elif op == 32:
                pass
            elif op == 33:
                vars_list = [str(rk(a + 3 + i)) for i in range(c)]
                lines.append(f"for {', '.join(vars_list)} in {rk(a)}, {rk(a+1)}, {rk(a+2)} do")
                pc += b + 1
                lines.append("end")
            elif op == 34:
                pass
            elif op == 36:
                regs[a] = f"function_{b}"
            elif op == 37:
                if b == 1:
                    regs[a] = "vararg"
                else:
                    lines.append(f"do local vararg = {{...}} end")

        result = []
        if params > 0:
            args = ", ".join([f"arg{i+1}" for i in range(params)])
            result.append(f"local function main({args})")
        else:
            result.append("local function main()")
        
        for line in lines:
            if line.startswith("local function main"):
                continue
            result.append(f"  {line}")
        
        result.append("end")
        result.append("return main()")
        return "\n".join(result)

class CustomVMDeobfuscator:
    def __init__(self, source):
        self.src = source
        self.pf = {}
        self.const_tags = {}
        self.enc = {}
        self._parse()

    def _parse(self):
        m = re.search(r'local\s+(\w+)\s*=\s*\{', self.src)
        self.blob_var = m.group(1)
        self.proto = self._extract_table(self.src, m.start())
        dec = re.search(r'local function (\w+)\((\w+),(\w+)\)(.*?)end', self.src, re.DOTALL)
        self.dec_name, self.dec_pr, self.dec_pk = dec.group(1), dec.group(2), dec.group(3)
        body = dec.group(4)
        self.enc['k1'] = int(re.search(r'_rk\s*=\s*\(\s*(\d+)\s*\^', body).group(1))
        self.enc['rot'] = int(re.search(r'>>\s*\(\s*(\d+)', body).group(1))
        self.enc['k2'] = int(re.search(r'_b\s*~\s*(\d+)', body).group(1))
        self.enc['k3'] = int(re.search(r'_b\s*-\s*(\d+)', body).group(1))
        tags = re.findall(r'ct\s*==\s*(\d+)', body)
        self.const_tags = {
            'STRING': int(tags[0]),
            'NUMBER': int(tags[1]),
            'BOOL_T': int(tags[2]),
            'BOOL_F': int(tags[3]),
            'NIL': int(tags[4])
        }
        pf_def = re.search(r'pf\s*=\s*\{(.*?)\}', self.src, re.DOTALL)
        if pf_def:
            for k, v in re.findall(r'(\w+)\s*=\s*[{"\']?(\w+)[}"\']?', pf_def.group(1)):
                self.pf[k] = v
        for k, v in [('code', 'code'), ('consts', 'consts'), ('checksum', 'checksum'), ('fmt', 'fmt')]:
            if k not in self.pf:
                self.pf[k] = v

    def _extract_table(self, text, idx):
        i = text.index('{', idx)
        depth = 0
        for j in range(i, len(text)):
            if text[j] == '{':
                depth += 1
            elif text[j] == '}':
                depth -= 1
                if depth == 0:
                    return self._lua_to_py(text[i:j+1])
        return {}

    def _lua_to_py(self, s):
        s = s.strip()[1:-1]
        items = ['']
        brace = 0
        in_string = False
        string_char = None
        for ch in s:
            if in_string:
                items[-1] += ch
                if ch == string_char:
                    in_string = False
                continue
            if ch in ('"', "'"):
                in_string = True
                string_char = ch
                items[-1] += ch
                continue
            if ch == '{':
                brace += 1
            elif ch == '}':
                brace -= 1
            if brace == 0 and ch == ',':
                items.append('')
            else:
                items[-1] += ch
        result = {}
        for it in items:
            it = it.strip()
            if not it:
                continue
            if '=' not in it:
                continue
            k, v = it.split('=', 1)
            k = k.strip()
            v = v.strip()
            if v.startswith('{'):
                result[k] = self._lua_to_py(v)
            elif v.startswith('"') or v.startswith("'"):
                result[k] = v[1:-1]
            else:
                try:
                    result[k] = int(v)
                except:
                    result[k] = v
        return result

    def decode_constants(self):
        raw = self.proto[self.pf['consts']]
        checksum = self.proto[self.pf['checksum']]
        rk = (self.enc['k1'] ^ (checksum & 0xFF)) & 0xFF
        out = []
        for entry in raw:
            tag = entry[0]
            val = entry[1]
            if tag == self.const_tags['STRING']:
                s = []
                for i, b in enumerate(val):
                    b = (b - self.enc['k3']) & 0xFF
                    b ^= self.enc['k2']
                    b = ((b << (8 - self.enc['rot'])) | (b >> self.enc['rot'])) & 0xFF
                    b ^= (rk + i * 5 + 11) & 0xFF
                    s.append(chr(b))
                out.append(''.join(s))
            elif tag == self.const_tags['NUMBER']:
                out.append(val)
            elif tag == self.const_tags['BOOL_T']:
                out.append(True)
            elif tag == self.const_tags['BOOL_F']:
                out.append(False)
            elif tag == self.const_tags['NIL']:
                out.append(None)
        return out

    def decompile(self):
        code_field = self.pf['code']
        code = self.proto[code_field]
        consts = self.decode_constants()
        rbias = 0x5000
        regs = [None] * 256
        pc = 0
        lines = []
        
        while pc < len(code):
            ins = code[pc]
            if isinstance(ins, list):
                op = ins[0]
                a = ins[1] if len(ins) > 1 else 0
                b = ins[2] if len(ins) > 2 else 0
                c = ins[3] if len(ins) > 3 else 0
            else:
                op = ins & 0xFFF
                a = (ins >> 12) & 0xFF
                b = (ins >> 20) & 0x3F
                c = (ins >> 26) & 0x3F
            pc += 1

            def rk(v):
                if v >= rbias:
                    idx = v - rbias + 1
                    if idx < len(consts):
                        return consts[idx]
                    return f"K[{idx}]"
                return regs[v]

            if op == 0:
                regs[a] = rk(b)
            elif op == 1:
                regs[a] = consts[b]
            elif op == 2:
                regs[a] = (b != 0)
                if c != 0:
                    pc += 1
            elif op == 3:
                for i in range(a, b + 1):
                    regs[i] = "nil"
            elif op == 4:
                regs[a] = f'_G["{consts[b]}"]'
            elif op == 5:
                lines.append(f'_G["{consts[b]}"] = {rk(a)}')
            elif op == 8:
                regs[a] = f"{rk(b)}[{rk(c)}]"
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
                parts = [str(rk(i)) for i in range(b, c + 1)]
                regs[a] = " .. ".join(parts)
            elif op == 22:
                pc += c
            elif op == 23:
                lines.append(f"if ({rk(b)} == {rk(c)}) ~= ({a != 0}) then break end")
            elif op == 24:
                lines.append(f"if ({rk(b)} < {rk(c)}) ~= ({a != 0}) then break end")
            elif op == 25:
                lines.append(f"if ({rk(b)} <= {rk(c)}) ~= ({a != 0}) then break end")
            elif op == 26:
                lines.append(f"if (not not {rk(a)}) ~= ({c != 0}) then break end")
            elif op == 27:
                lines.append(f"if (not not {rk(b)}) == ({c != 0}) then {regs[a]} = {rk(b)} else break end")
            elif op == 28:
                args = ', '.join([str(rk(a + 1 + i)) for i in range(b - 1)])
                lines.append(f"{rk(a)}({args})")
            elif op == 29:
                args = ', '.join([str(rk(a + 1 + i)) for i in range(b - 1)])
                lines.append(f"return {rk(a)}({args})")
                break
            elif op == 30:
                if b == 1:
                    lines.append("return")
                else:
                    rets = ', '.join([str(rk(a + i)) for i in range(b - 1)])
                    lines.append(f"return {rets}")
                break

        return '\n'.join(lines)

def deobfuscate_luraph_full(source):
    match = re.search(r'return\s+\(function\s*\(\)\s*(.*?)\s*end\)\(\)', source, re.DOTALL)
    if match:
        inner = match.group(1)
        source = inner + "\n" + source[match.end():]
    
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
        return "Unable to locate bytecode in the obfuscated file."
    
    try:
        encrypted = base64.b64decode(b64)
    except:
        return "Failed to decode base64 bytecode."
    
    possible_keys = []
    for i in range(256):
        test = bytes(b ^ i for b in encrypted[:4])
        if test == b'\x1bLua':
            possible_keys.append(i)
    
    if not possible_keys:
        for i in range(256):
            test = bytes(b ^ i for b in encrypted[-4:])
            if test == b'\x00\x00\x00\x00':
                possible_keys.append(i)
    
    if not possible_keys:
        return "Could not determine XOR decryption key."
    
    bytecode = encrypted
    for k in reversed(possible_keys):
        for _ in range(2):
            bytecode = bytes(b ^ k for b in bytecode)
    
    if bytecode[:4] != b'\x1bLua':
        return "Decryption produced invalid Lua bytecode."
    
    dec = LuaDecompiler(bytecode)
    return dec.decompile()

def deobfuscate_moonsec_full(source):
    chunks = re.findall(r'local\s+\w+\s*=\s*\{([^}]+)\}', source)
    if not chunks:
        return "No bytecode chunks found."
    
    bytecode_parts = []
    for chunk in chunks:
        nums = [int(x.strip()) for x in chunk.split(',') if x.strip().lstrip('-').isdigit()]
        bytecode_parts.append(bytes(nums))
    
    full_bytecode = b''.join(bytecode_parts)
    
    if full_bytecode[:4] == b'\x1bLua':
        dec = LuaDecompiler(full_bytecode)
        return dec.decompile()
    
    for k in range(256):
        decrypted = bytes(b ^ k for b in full_bytecode)
        if decrypted[:4] == b'\x1bLua':
            dec = LuaDecompiler(decrypted)
            return dec.decompile()
    
    return "Not valid Lua bytecode."

def deobfuscate_ironbrew_full(source):
    match = re.search(r'local\s+\w+\s*=\s*\{([^}]+)\}', source)
    if not match:
        return "No instruction table found."
    
    raw = match.group(1)
    vals = re.findall(r'\d+', raw)
    
    out = []
    for v in vals:
        try:
            v = int(v)
            out.append(struct.pack('>I', v))
        except:
            pass
    
    bytecode = b''.join(out)
    
    if len(bytecode) > 12 and bytecode[:4] == b'\x1bLua':
        dec = LuaDecompiler(bytecode)
        return dec.decompile()
    
    bytecode_le = b''
    for v in vals:
        try:
            v = int(v)
            bytecode_le += struct.pack('<I', v)
        except:
            pass
    
    if len(bytecode_le) > 12 and bytecode_le[:4] == b'\x1bLua':
        dec = LuaDecompiler(bytecode_le)
        return dec.decompile()
    
    return "Invalid Ironbrew bytecode structure."

def deobfuscate_wearedevs_full(source):
    match = re.search(r'["\']([^"\']{50,})["\']', source)
    if match:
        encoded = match.group(1)
        try:
            decoded = base64.b64decode(encoded)
            if decoded[:4] == b'\x1bLua':
                dec = LuaDecompiler(decoded)
                return dec.decompile()
        except:
            pass
    
    encrypted_match = re.search(r'loadstring\s*\(\s*["\'](.*?)["\']\s*\)', source, re.DOTALL)
    if encrypted_match:
        return "Found loadstring wrapper. Unable to fully decompile this variant."
    
    return "WeAreDevs deobfuscation incomplete. Manual review required."

def deobfuscate_generic(source):
    loadstring_matches = re.findall(r'loadstring\s*\(\s*["\'](.*?)["\']\s*\)', source, re.DOTALL)
    if loadstring_matches:
        deepest = loadstring_matches[-1]
        try:
            return deobfuscate_generic(deepest)
        except:
            return deepest
    
    b64_matches = re.findall(r'["\']([A-Za-z0-9+/=]{100,})["\']', source)
    for b64 in b64_matches:
        try:
            decoded = base64.b64decode(b64)
            if decoded[:4] == b'\x1bLua':
                dec = LuaDecompiler(decoded)
                return dec.decompile()
        except:
            continue
    
    return "Could not automatically deobfuscate. The file may require manual analysis."

def deobfuscate(source, obf_type):
    if obf_type == 'custom_vm':
        return CustomVMDeobfuscator(source).decompile()
    elif obf_type == 'luraph':
        return deobfuscate_luraph_full(source)
    elif obf_type == 'moonsec':
        return deobfuscate_moonsec_full(source)
    elif obf_type == 'ironbrew':
        return deobfuscate_ironbrew_full(source)
    elif obf_type == 'wearedevs':
        return deobfuscate_wearedevs_full(source)
    elif obf_type in ['psu', 'xen', 'aurora', 'synapse', 'sentinel']:
        return deobfuscate_generic(source)
    else:
        return deobfuscate_generic(source)

@bot.command(name='deobf')
async def deobf(ctx):
    if not ctx.message.attachments:
        return await ctx.send('Please attach a .lua file with the command: `!deobf`')
    
    attachment = ctx.message.attachments[0]
    
    if not attachment.filename.lower().endswith(('.lua', '.txt', '.luac')):
        return await ctx.send('Please attach a .lua file.')
    
    await ctx.send('Processing file...')
    
    try:
        raw = await attachment.read()
    except:
        return await ctx.send('Failed to read the attached file.')
    
    try:
        text = raw.decode('utf-8')
    except:
        try:
            text = raw.decode('latin-1')
        except:
            return await ctx.send('File encoding not supported.')
    
    obf_type = detect_obfuscator(raw)
    result = deobfuscate(text, obf_type)
    
    if len(result) > 1900:
        file = discord.File(fp=io.StringIO(result), filename=f'deobfuscated_{attachment.filename}')
        await ctx.send(f'Detected obfuscator: **{obf_type}**', file=file)
    else:
        file = discord.File(fp=io.StringIO(result), filename=f'deobfuscated_{attachment.filename}')
        await ctx.send(f'Detected obfuscator: **{obf_type}**', file=file)

@bot.event
async def on_ready():
    print(f'Bot online as {bot.user}')

if __name__ == '__main__':
    bot.run(TOKEN)
