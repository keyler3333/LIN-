import re
import base64
import os
import tempfile
import subprocess
import shutil
from deobfuscator_core import Deobfuscator
from pattern_scanner import PatternScanner
from execution_engine import ExecutionEngine


class LuaEscapeDecoder:
    def decode(self, s):
        s = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)
        s = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))), s)
        return s


class CustomBase64Decoder:
    def __init__(self):
        self.alphabet = None

    def extract_alphabet(self, code):
        decoder = LuaEscapeDecoder()
        for m in re.finditer(r'local\s+\w+\s*=\s*\{([^}]+)\}', code, re.DOTALL):
            body = m.group(1)
            pairs = re.findall(r'\[?"?([^"\]]+)"?\]?\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', body)
            if len(pairs) >= 40:
                mapping = {}
                for key, expr in pairs:
                    plain_key = decoder.decode(key.strip().strip('"').strip("'"))
                    val = self._safe_eval(expr) & 0x3F
                    mapping[plain_key] = val
                if len(mapping) >= 40:
                    self.alphabet = mapping
                    return True
            chars = re.findall(r'"([^"]*)"', body)
            if len(chars) >= 40:
                decoded_chars = [decoder.decode(c) for c in chars]
                self.alphabet = {c: i for i, c in enumerate(decoded_chars)}
                return True
        return False

    def _safe_eval(self, expr):
        expr = expr.replace(' ', '')
        if re.match(r'^-?\d+$', expr):
            return int(expr)
        return 0

    def decode(self, s):
        if not self.alphabet:
            return None
        buf = bytearray()
        acc = 0
        cnt = 0
        for ch in s:
            if ch == '=':
                if cnt == 3:
                    buf.append((acc >> 16) & 0xFF)
                    buf.append((acc >> 8) & 0xFF)
                elif cnt == 2:
                    buf.append((acc >> 16) & 0xFF)
                break
            val = self.alphabet.get(ch)
            if val is None:
                continue
            acc = (acc << 6) | val
            cnt += 1
            if cnt == 4:
                buf.extend([(acc >> 16) & 0xFF, (acc >> 8) & 0xFF, acc & 0xFF])
                acc = 0
                cnt = 0
        return bytes(buf)


class ShuffleExtractor:
    def extract_pairs(self, code):
        pairs = []
        for a_s, b_s in re.findall(r'\{(-?\d+(?:\s*[+\-]\s*-?\d+)*)\s*[,;]\s*(-?\d+(?:\s*[+\-]\s*-?\d+)*)\}',
                                   code):
            try:
                a = int(a_s.replace(' ', ''))
                b = int(b_s.replace(' ', ''))
                if a > 0 and b > 0:
                    pairs.append((a, b))
            except:
                pass
        return pairs

    def unshuffle(self, strings, pairs):
        res = list(strings)
        for a, b in reversed(pairs):
            lo, hi = a - 1, b - 1
            if 0 <= lo < len(res) and 0 <= hi < len(res) and lo < hi:
                res[lo:hi + 1] = res[lo:hi + 1][::-1]
        return res


class WeAreDevsExtractor:
    def __init__(self):
        self.custom_b64 = CustomBase64Decoder()
        self.shuffler = ShuffleExtractor()
        self.escape_decoder = LuaEscapeDecoder()
        self.seen = set()

    def transform(self, code):
        self.custom_b64.extract_alphabet(code)
        pairs = self.shuffler.extract_pairs(code)

        data_table = None
        for m in re.finditer(r'local\s+N\s*=\s*\{([^}]+)\}', code, re.DOTALL):
            data_table = m.group(1)
            break
        if not data_table:
            return code

        strings = re.findall(r'"((?:\\.|[^"\\])*)"', data_table)
        if not strings:
            return code

        decoded_strings = [self.escape_decoder.decode(s) for s in strings]

        if pairs:
            decoded_strings = self.shuffler.unshuffle(decoded_strings, pairs)

        payload = bytearray()
        for s in decoded_strings:
            chunk = self.custom_b64.decode(s)
            if chunk:
                payload.extend(chunk)

        data = bytes(payload)
        if len(data) >= 12 and data[:4] == b'\x1bLua':
            return self._decompile_bytecode(data)

        for s in decoded_strings:
            chunk = self.custom_b64.decode(s)
            if chunk:
                try:
                    text = chunk.decode('utf-8', errors='ignore')
                    if len(text) > 50 and ('function' in text or 'local' in text):
                        return text
                except:
                    pass

        joined = ''.join(decoded_strings)
        if len(joined) > 100 and ('function' in joined or 'local' in joined):
            return joined

        return code

    def _decompile_bytecode(self, bc):
        try:
            import struct
            pos = 12
            instructions = []
            constants = []
            def read_int():
                nonlocal pos; v = struct.unpack_from('<I', bc, pos)[0]; pos += 4; return v
            def read_byte():
                nonlocal pos; v = bc[pos]; pos += 1; return v
            def read_string():
                size = read_int()
                if size == 0: return ""
                s = bc[pos:pos+size-1].decode('latin-1', errors='replace')
                pos += size; return s
            def read_function():
                read_string(); read_int(); read_int()
                read_byte(); read_byte(); read_byte(); read_byte()
                code_len = read_int()
                for _ in range(code_len): instructions.append(read_int())
                const_len = read_int()
                for _ in range(const_len):
                    t = read_byte()
                    if t == 0: constants.append(None)
                    elif t == 1: constants.append(bool(read_byte()))
                    elif t == 3: constants.append(struct.unpack('<d', bc[pos:pos+8])[0]); pos += 8
                    elif t == 4: constants.append(read_string())
                    else: constants.append(None)
                proto_count = read_int()
                for _ in range(proto_count): read_function()
            read_function()
            lines = []
            regs = [None]*256
            upvals = [f'Up{i}' for i in range(256)]
            var_count = 1
            def rk(v):
                if v >= 256:
                    idx = v - 256
                    if 0 <= idx < len(constants):
                        c = constants[idx]
                        if isinstance(c, str): return repr(c)
                        if c is None: return 'nil'
                        if isinstance(c, bool): return 'true' if c else 'false'
                        return str(c)
                    return f'K[{idx}]'
                r = regs[v]; return r if r is not None else f'R{v}'
            for instr in instructions:
                op = instr & 0x3F
                a = (instr >> 6) & 0xFF
                b = (instr >> 23) & 0x1FF
                c = (instr >> 14) & 0x1FF
                if op == 0: regs[a] = rk(b)
                elif op == 1: regs[a] = rk(b + 256)
                elif op == 5: regs[a] = f'_G[{repr(constants[b])}]'
                elif op == 6: regs[a] = upvals[b] if b < len(upvals) else f'Up[{b}]'
                elif op == 7: lines.append(f'_G[{repr(constants[b])}] = {rk(a)}')
                elif op == 8: upvals[b] = rk(a)
                elif op == 10: regs[a] = f'function_{b}'
                elif op == 12: lines.append(f'R{a} = {rk(b)} + {rk(c)}')
                elif op == 13: lines.append(f'R{a} = {rk(b)} - {rk(c)}')
                elif op == 14: lines.append(f'R{a} = {rk(b)} * {rk(c)}')
                elif op == 25: lines.append(f'if ({rk(b)} < {rk(c)}) ~= {a} then goto next')
                elif op == 26: lines.append(f'if ({rk(b)} == {rk(c)}) ~= {a} then goto next')
                elif op == 28:
                    args = ', '.join(rk(a+1+i) for i in range(b-1)) if b > 1 else ''
                    if c == 1: lines.append(f'{rk(a)}({args})')
                    elif c == 0:
                        vname = f'var_{var_count}'; var_count += 1
                        lines.append(f'local {vname} = {rk(a)}({args})'); regs[a] = vname
                    else:
                        rets = [f'var_{var_count+i}' for i in range(c-1)]
                        var_count += c-1
                        lines.append(f'local {", ".join(rets)} = {rk(a)}({args})')
                        regs[a] = rets[0]
                elif op == 30:
                    nret = b - 1
                    if nret >= 0: lines.append('return ' + ', '.join(rk(a+i) for i in range(nret)))
                    else: lines.append('return')
                    break
            return '\n'.join(lines)
        except:
            return None


class WRDPipeline:
    def __init__(self):
        self.deobfuscator = Deobfuscator()
        self.scanner = PatternScanner()
        self.executor = ExecutionEngine(max_time=15)
        self.lua_bin = shutil.which('lua5.1') or shutil.which('lua51') or shutil.which('lua') or 'lua'
        self.runtime_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sandbox_runtime.lua')
        self.extractor = WeAreDevsExtractor()

    def run(self, code):
        result = self.extractor.transform(code)
        if result and result != code and len(result) > 50:
            return result

        result = self._static_extract(code)
        if result:
            return result

        result = self._sandbox_extract(code)
        if result:
            return result

        return code

    def _static_extract(self, source):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as tmp:
            tmp.write(source)
            tmp_path = tmp.name
        try:
            analysis = self.deobfuscator.analyze_script(tmp_path)
            strings = analysis.get('decrypted_strings', [])
            for s in strings:
                if len(s) > 50 and ('function' in s or 'local' in s):
                    return s
            joined = ''.join(strings)
            if len(joined) > 100 and ('function' in joined or 'local' in joined):
                return joined
        except Exception:
            pass
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        return None

    def _sandbox_extract(self, source):
        if not os.path.isfile(self.runtime_path):
            return None
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, 'input.lua')
            drv = os.path.join(d, 'driver.lua')
            with open(inp, 'w', encoding='utf-8') as f:
                f.write(source)
            with open(self.runtime_path, 'r', encoding='utf-8') as f:
                runtime = f.read()
            driver = runtime.replace('"OUTDIR_PLACEHOLDER"', f'"{d.replace(chr(92), "/")}"')\
                            .replace('"INPATH_PLACEHOLDER"', f'"{inp.replace(chr(92), "/")}"')
            with open(drv, 'w', encoding='utf-8') as f:
                f.write(driver)
            try:
                subprocess.run([self.lua_bin, drv], capture_output=True, text=True,
                               timeout=20, cwd=d, env=os.environ.copy())
            except Exception:
                pass
            captures = self._read_captures(d)
            for tag in ('LOADSTRING_PAYLOAD', 'BASE64', 'CONCAT_RESULT'):
                if tag in captures:
                    payload = captures[tag].strip()
                    if len(payload) > 20 and ('function' in payload or 'local' in payload):
                        return payload
        return None

    def _read_captures(self, d):
        cap_path = os.path.join(d, 'cap.txt')
        if not os.path.exists(cap_path):
            return {}
        captures = {}
        with open(cap_path, encoding='utf-8', errors='replace') as f:
            current_tag = None
            current_data = []
            for line in f:
                line = line.rstrip('\n')
                if line.startswith('--- ') and line.endswith(' ---'):
                    if current_tag and current_data:
                        captures[current_tag] = '\n'.join(current_data)
                    current_tag = line[4:-4].strip()
                    current_data = []
                elif line == '---SEP---':
                    if current_tag and current_data:
                        captures[current_tag] = '\n'.join(current_data)
                    current_tag = None
                    current_data = []
                else:
                    current_data.append(line)
            if current_tag and current_data:
                captures[current_tag] = '\n'.join(current_data)
        return captures
