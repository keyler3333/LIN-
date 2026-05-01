import re
import base64
import struct

class Transformer:
    def transform(self, code):
        raise NotImplementedError

class WeAreDevsLifter(Transformer):
    def transform(self, code):
        lifted = self._try_lift(code)
        if lifted is not None:
            return lifted
        return code

    def _try_lift(self, source):
        table_match = re.search(r'local\s+N\s*=\s*\{(.*?)\}', source, re.DOTALL)
        if not table_match:
            return None
        raw_table = table_match.group(1)
        encoded_strings = re.findall(r'"((?:\\.|[^"\\])*)"', raw_table)
        if not encoded_strings:
            return None

        decoder_match = re.search(r'local\s+b\s*=\s*\{([^}]+)\}', source, re.DOTALL)
        if not decoder_match:
            return None
        decoder_body = decoder_match.group(1)
        char_map = {}
        for pair in re.finditer(r'\[?"?([^"\]]+)"?\]?\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', decoder_body):
            key = pair.group(1).strip()
            expr = pair.group(2).replace(' ', '')
            try:
                val = eval(expr)
                char_map[key] = val & 0x3F
            except:
                pass

        shuffle_pairs = []
        for a_expr, b_expr in re.findall(r'\{(-?\d+(?:\s*[+\-]\s*-?\d+)*)\s*,\s*(-?\d+(?:\s*[+\-]\s*-?\d+)*)\}', source):
            try:
                a = eval(a_expr.replace(' ', ''))
                b = eval(b_expr.replace(' ', ''))
                shuffle_pairs.append([a, b])
            except:
                pass

        strings = list(encoded_strings)
        for a, b in reversed(shuffle_pairs):
            a_idx, b_idx = a - 1, b - 1
            if a_idx < 0 or b_idx >= len(strings):
                continue
            while a_idx < b_idx:
                strings[a_idx], strings[b_idx] = strings[b_idx], strings[a_idx]
                a_idx += 1
                b_idx -= 1

        decoded_chunks = []
        for s in strings:
            byte_buffer = bytearray()
            acc, bits, count = 0, 0, 0
            for ch in s:
                if ch == '=':
                    if count == 3:
                        byte_buffer.append((acc >> 16) & 0xFF)
                        byte_buffer.append((acc >> 8) & 0xFF)
                    elif count == 2:
                        byte_buffer.append((acc >> 16) & 0xFF)
                    break
                val = char_map.get(ch)
                if val is None:
                    continue
                acc = (acc << 6) | val
                bits += 6
                count += 1
                if count == 4:
                    byte_buffer.extend([
                        (acc >> 16) & 0xFF,
                        (acc >> 8) & 0xFF,
                        acc & 0xFF,
                    ])
                    acc, bits, count = 0, 0, 0
            if byte_buffer:
                decoded_chunks.append(bytes(byte_buffer))

        full_data = bytearray()
        for chunk in decoded_chunks:
            full_data.extend(chunk)

        if len(full_data) >= 12 and full_data[:4] == b'\x1bLua':
            return self._lift_bytecode(full_data)
        return None

    def _lift_bytecode(self, bc):
        pos = 12
        instructions = []
        constants = []

        def read_int():
            nonlocal pos
            v = struct.unpack_from('<I', bc, pos)[0]
            pos += 4
            return v

        def read_byte():
            nonlocal pos
            v = bc[pos]
            pos += 1
            return v

        def read_string():
            size = read_int()
            if size == 0:
                return ""
            s = bc[pos:pos+size-1].decode('latin-1', errors='replace')
            pos += size
            return s

        def read_function():
            read_string()
            read_int()
            read_int()
            read_byte()
            read_byte()
            read_byte()
            read_byte()
            code_len = read_int()
            for _ in range(code_len):
                instructions.append(read_int())
            const_len = read_int()
            for _ in range(const_len):
                t = read_byte()
                if t == 0:
                    constants.append(None)
                elif t == 1:
                    constants.append(read_byte() != 0)
                elif t == 3:
                    size = read_int()
                    num_str = bc[pos:pos+size-1].decode('latin-1')
                    pos += size
                    if '.' in num_str or 'e' in num_str.lower():
                        constants.append(float(num_str))
                    else:
                        constants.append(int(num_str))
                elif t == 4:
                    s = read_string()
                    constants.append(s)
                else:
                    constants.append(None)
            proto_count = read_int()
            for _ in range(proto_count):
                read_function()

        read_function()
        return self._generate_code(instructions, constants)

    def _generate_code(self, instructions, constants):
        lines = []
        regs = [None] * 256
        upvals = [f"Up{i}" for i in range(256)]
        var_count = 1

        def rk(v):
            if v >= 256:
                idx = v - 256
                if 0 <= idx < len(constants):
                    c = constants[idx]
                    if isinstance(c, str):
                        return repr(c)
                    if c is None:
                        return "nil"
                    if isinstance(c, bool):
                        return "true" if c else "false"
                    return str(c)
                return f"K[{idx}]"
            r = regs[v]
            return r if r is not None else f"R{v}"

        for pc, instr in enumerate(instructions):
            op = instr & 0x3F
            a = (instr >> 6) & 0xFF
            b = (instr >> 23) & 0x1FF
            c = (instr >> 14) & 0x1FF

            if op == 0:
                regs[a] = rk(b)
            elif op == 1:
                regs[a] = rk(b + 256)
            elif op == 5:
                regs[a] = f"_G[{repr(constants[b])}]"
            elif op == 6:
                regs[a] = upvals[b] if b < len(upvals) else f"Up[{b}]"
            elif op == 7:
                lines.append(f"_G[{repr(constants[b])}] = {rk(a)}")
            elif op == 8:
                upvals[b] = rk(a)
            elif op == 10:
                regs[a] = f"function_{b}"
            elif op == 12:
                lines.append(f"R{a} = {rk(b)} + {rk(c)}")
            elif op == 13:
                lines.append(f"R{a} = {rk(b)} - {rk(c)}")
            elif op == 14:
                lines.append(f"R{a} = {rk(b)} * {rk(c)}")
            elif op == 25:
                lines.append(f"if ({rk(b)} < {rk(c)}) ~= {a} then goto next")
            elif op == 26:
                lines.append(f"if ({rk(b)} == {rk(c)}) ~= {a} then goto next")
            elif op == 28:
                args = ""
                if b > 1:
                    args = ", ".join(rk(a+1+i) for i in range(b-1))
                if c == 1:
                    lines.append(f"{rk(a)}({args})")
                elif c == 0:
                    vname = f"var_{var_count}"
                    var_count += 1
                    lines.append(f"local {vname} = {rk(a)}({args})")
                    regs[a] = vname
                else:
                    rets = []
                    for i in range(c-1):
                        rets.append(f"var_{var_count}")
                        var_count += 1
                    lines.append(f"local {', '.join(rets)} = {rk(a)}({args})")
                    regs[a] = rets[0]
            elif op == 30:
                nret = b - 1
                if nret >= 0:
                    lines.append("return " + ", ".join(rk(a+i) for i in range(nret)))
                else:
                    lines.append("return")
                break

        return "\n".join(lines)

class MathTransformer(Transformer):
    def transform(self, code):
        def safe_calc(match):
            try:
                a_str, op, b_str = match.groups()
                a, b = int(a_str), int(b_str)
                if op == '+': return str(a + b)
                if op == '-': return str(a - b)
                if op == '*': return str(a * b)
                if op == '/' and b != 0: return str(a // b)
                if op == '^': return str(a ** b)
                if op == '%' and b != 0: return str(a % b)
            except:
                pass
            return match.group(0)
        code = re.sub(r'\((-?\d+)\s*([\+\-\*\/\^\%])\s*(-?\d+)\)', safe_calc, code)
        return code

class CipherMapTransformer(Transformer):
    def transform(self, code):
        cipher_map = self._extract_mapping(code)
        if not cipher_map:
            return code

        table_match = re.search(r'local\s+[a-zA-Z_]\w*\s*=\s*\{(.*?)\}', code, re.DOTALL)
        if not table_match:
            return code

        encoded_strings = re.findall(r'"((?:\\.|[^"\\])*)"', table_match.group(1))
        shuffle_pairs = self._extract_shuffles(code)
        if shuffle_pairs:
            encoded_strings = self._unshuffle(encoded_strings, shuffle_pairs)

        for s in encoded_strings:
            decoded = self._decode(s, cipher_map)
            if decoded and any(c.isprintable() for c in decoded):
                code = code.replace(f'"{s}"', f'"{decoded}"')
        return code

    def _extract_mapping(self, code):
        for match in re.finditer(r'local\s+\w+\s*=\s*\{(.*?)\}', code, re.DOTALL):
            content = match.group(1)
            if '=' not in content or content.count('=') < 10:
                continue
            mapping = {}
            pairs = re.findall(r'\[?"?([^"\]]+)"?\]?\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', content)
            for k, expr in pairs:
                try:
                    val = eval(expr.replace(' ', ''), {"__builtins__": None}, {})
                    mapping[k.strip()] = val & 0x3F
                except:
                    continue
            if len(mapping) > 30:
                return mapping
        return None

    def _extract_shuffles(self, code):
        pairs = []
        for a_expr, b_expr in re.findall(r'\{(-?\d+(?:\s*[+\-]\s*-?\d+)*)\s*,\s*(-?\d+(?:\s*[+\-]\s*-?\d+)*)\}', code):
            try:
                a = eval(a_expr.replace(' ', ''), {"__builtins__": None}, {})
                b = eval(b_expr.replace(' ', ''), {"__builtins__": None}, {})
                pairs.append([a, b])
            except:
                continue
        return pairs

    def _unshuffle(self, strings, pairs):
        res = list(strings)
        for a, b in reversed(pairs):
            a_idx, b_idx = a - 1, b - 1
            if a_idx < 0 or b_idx >= len(res):
                continue
            while a_idx < b_idx:
                res[a_idx], res[b_idx] = res[b_idx], res[a_idx]
                a_idx += 1
                b_idx -= 1
        return res

    def _decode(self, s, cmap):
        buf = bytearray()
        acc = count = 0
        for ch in s:
            if ch == '=':
                if count == 3:
                    buf.extend([(acc >> 16) & 0xFF, (acc >> 8) & 0xFF])
                elif count == 2:
                    buf.append((acc >> 16) & 0xFF)
                break
            val = cmap.get(ch)
            if val is None:
                continue
            acc = (acc << 6) | val
            count += 1
            if count == 4:
                buf.extend([(acc >> 16) & 0xFF, (acc >> 8) & 0xFF, acc & 0xFF])
                acc = count = 0
        try:
            return buf.decode('utf-8', errors='ignore')
        except:
            return buf.decode('latin-1', errors='ignore')

class EscapeSequenceTransformer(Transformer):
    def transform(self, code):
        code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), code)
        code = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)
        return code

class HexNameRenamer(Transformer):
    def transform(self, code):
        self.mapping = {}
        self.counter = 0
        def replace_hex(match):
            hex_name = match.group(0)
            if hex_name not in self.mapping:
                self.counter += 1
                self.mapping[hex_name] = f"var{self.counter}"
            return self.mapping[hex_name]
        return re.sub(r'(?<![^\s\[\(\)\.\=\+\-\*\/\^\%\#\<\>\~\&\|\,])(_0x[0-9a-fA-F]+)(?=[^\w]|$)', replace_hex, code)

class DictRenamer(Transformer):
    def __init__(self, mapping):
        self.mapping = mapping

    def transform(self, code):
        for old, new in self.mapping.items():
            code = re.sub(
                r'(?<![^\w\.\:])' + re.escape(old) + r'(?![^\w])',
                new,
                code
            )
        return code

class StringCharDecoder(Transformer):
    def transform(self, code):
        def decode_string_char(match):
            inner = match.group(1)
            try:
                nums = [int(x.strip()) for x in inner.split(',') if x.strip().isdigit()]
                decoded = ''.join(chr(n) for n in nums if 0 <= n < 256)
                if len(decoded) >= 1 and any(c.isprintable() or c in '\n\r\t' for c in decoded):
                    escaped = decoded.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
                    return f'"{escaped}"'
            except:
                pass
            return match.group(0)
        code = re.sub(r'string\.char\s*\(\s*([\d\s,]+)\s*\)', decode_string_char, code)
        return code

class OpaquePredicateRemover(Transformer):
    def transform(self, code):
        always_true_patterns = [
            r'\(\s*1\s*\+\s*1\s*==\s*2\s*\)\s+and\s+',
            r'\(\s*2\s*\*\s*3\s*>\s*5\s*\)\s+and\s+',
            r'\(\s*10\s*\-\s*5\s*==\s*5\s*\)\s+and\s+',
            r'\(\s*1\s*\*\s*1\s*>=\s*0\s*\)\s+and\s+',
            r'\(\s*\d+\s*==\s*\d+\s*\)\s+and\s+',
            r'\(\s*\d+\s*[<>=!]+\s*\d+\s*\)\s+and\s+',
        ]
        for pat in always_true_patterns:
            code = re.sub(pat, '', code)
        return code

class ExecutorCallResolver(Transformer):
    def transform(self, code):
        preamble = """--[[ Executor Globals Stub ]]
local getgenv = getgenv or function() return getfenv() end
local getrenv = getrenv or getgenv
local getsenv = getsenv or getgenv
local cloneref = cloneref or function(i) return i end
local compareinstances = compareinstances or function(a,b) return a==b end
local isluau = isluau or function() return true end
local setclipboard = setclipboard or function() end
local queueteleport = queueteleport or function() end
local syn_queue_on_teleport = syn_queue_on_teleport or function() end
local setreadonly = setreadonly or function() end
local makereadonly = makereadonly or function() end
local makewriteable = makewriteable or function() end
local getrawmetatable = getrawmetatable or function() return nil end
local setrawmetatable = setrawmetatable or function() end
local getconstants = getconstants or function() return {} end
local setconstant = setconstant or function() end
local getupvalues = getupvalues or function() return {} end
local setupvalue = setupvalue or function() end
local getupvalue = getupvalue or function() return nil end
local getscriptclosure = getscriptclosure or function() return function() end end
local restorefunction = restorefunction or function(f) return f end
local detourfunction = detourfunction or function(f) return f end
local replaceclosure = replaceclosure or function() end
local unhookfunction = unhookfunction or function() end
local getcallingscript = getcallingscript or function() return nil end
local getscripthash = getscripthash or function() return "" end
local getscripts = getscripts or function() return {} end
local getmodules = getmodules or function() return {} end
local getproperties = getproperties or function() return {} end
local getnilinstances = getnilinstances or function() return {} end
local debug_getregistry = debug_getregistry or function() return {} end
local debug_traceback = debug_traceback or function() return "" end
local crypt = crypt or { base64encode = function() return "" end, base64decode = function() return "" end, encrypt = function() return "" end, decrypt = function() return "" end }
local gethui = gethui or function() return nil end
local hookfunction = hookfunction or function(a,b) return a end
local newcclosure = newcclosure or function(f) return f end
local clonefunction = clonefunction or function(f) return f end
local rconsole = rconsole or { print = function() end, clear = function() end }
"""
        return preamble + code
