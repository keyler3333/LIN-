import re
import struct

class Transformer:
    def transform(self, code):
        raise NotImplementedError

class WeAreDevsLifter(Transformer):
    def transform(self, code):
        lifted = self._try_lift(code)
        if lifted:
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

        char_map = self._build_char_map(source)
        if not char_map or len(char_map) < 40:
            return None

        shuffle_pairs = self._extract_shuffle_pairs(source)
        strings = list(encoded_strings)
        if shuffle_pairs:
            strings = self._apply_unshuffle(strings, shuffle_pairs)

        decoded_bytes = bytearray()
        for s in strings:
            chunk = self._decode_string(s, char_map)
            if chunk:
                decoded_bytes.extend(chunk)

        data = bytes(decoded_bytes)
        if len(data) >= 12 and data[:4] == b'\x1bLua':
            return self._lift_bytecode(data)
        return None

    def _build_char_map(self, source):
        decoder_match = re.search(r'local\s+b\s*=\s*\{([^}]+)\}', source, re.DOTALL)
        if not decoder_match:
            return None
        body = decoder_match.group(1)
        char_map = {}
        for pair in re.finditer(r'\[?"?([^"\]]+)"?\]?\s*=\s*(-?\d+(?:\s*[+\-]\s*-?\d+)*)', body):
            key = pair.group(1).strip()
            expr = pair.group(2).replace(' ', '')
            try:
                val = eval(expr) & 0x3F
                char_map[key] = val
            except:
                pass
        return char_map

    def _extract_shuffle_pairs(self, source):
        pairs = []
        for a_expr, b_expr in re.findall(
            r'\{(-?\d+(?:\s*[+\-]\s*-?\d+)*)\s*,\s*(-?\d+(?:\s*[+\-]\s*-?\d+)*)\}',
            source
        ):
            try:
                a = eval(a_expr.replace(' ', ''))
                b = eval(b_expr.replace(' ', ''))
                pairs.append([a, b])
            except:
                continue
        return pairs

    def _apply_unshuffle(self, strings, pairs):
        res = list(strings)
        for a, b in reversed(pairs):
            lo, hi = a - 1, b - 1
            if lo < 0 or hi >= len(res):
                continue
            while lo < hi:
                res[lo], res[hi] = res[hi], res[lo]
                lo += 1
                hi -= 1
        return res

    def _decode_string(self, s, char_map):
        buf = bytearray()
        acc = count = 0
        for ch in s:
            if ch == '=':
                if count == 3:
                    buf.append((acc >> 16) & 0xFF)
                    buf.append((acc >> 8) & 0xFF)
                elif count == 2:
                    buf.append((acc >> 16) & 0xFF)
                break
            val = char_map.get(ch)
            if val is None:
                continue
            acc = (acc << 6) | val
            count += 1
            if count == 4:
                buf.extend([
                    (acc >> 16) & 0xFF,
                    (acc >> 8) & 0xFF,
                    acc & 0xFF
                ])
                acc = count = 0
        return bytes(buf) if buf else None

    # -------- bytecode parser & lifter ----------
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
            read_string()          # source name
            read_int()             # line defined
            read_int()             # last line defined
            read_byte()            # num upvalues
            read_byte()            # num params
            read_byte()            # is_vararg
            read_byte()            # max stack size
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
                    constants.append(read_string())
                else:
                    constants.append(None)
            proto_count = read_int()
            for _ in range(proto_count):
                read_function()

        read_function()
        return self._emit_lua(instructions, constants)

    def _emit_lua(self, instructions, constants):
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

        for instr in instructions:
            op = instr & 0x3F
            a = (instr >> 6) & 0xFF
            b = (instr >> 23) & 0x1FF
            c = (instr >> 14) & 0x1FF

            if op == 0:      # MOVE
                regs[a] = rk(b)
            elif op == 1:    # LOADK
                regs[a] = rk(b + 256)
            elif op == 5:    # GETGLOBAL
                regs[a] = f"_G[{repr(constants[b])}]"
            elif op == 6:    # GETUPVAL
                regs[a] = upvals[b] if b < len(upvals) else f"Up[{b}]"
            elif op == 7:    # SETGLOBAL
                lines.append(f"_G[{repr(constants[b])}] = {rk(a)}")
            elif op == 8:    # SETUPVAL
                upvals[b] = rk(a)
            elif op == 10:   # CLOSURE
                regs[a] = f"function_{b}"
            elif op == 12:   # ADD
                lines.append(f"R{a} = {rk(b)} + {rk(c)}")
            elif op == 13:   # SUB
                lines.append(f"R{a} = {rk(b)} - {rk(c)}")
            elif op == 14:   # MUL
                lines.append(f"R{a} = {rk(b)} * {rk(c)}")
            elif op == 25:   # LT
                lines.append(f"if ({rk(b)} < {rk(c)}) ~= {a} then goto next")
            elif op == 26:   # EQ
                lines.append(f"if ({rk(b)} == {rk(c)}) ~= {a} then goto next")
            elif op == 28:   # CALL
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
                    rets = [f"var_{var_count+i}" for i in range(c-1)]
                    var_count += c - 1
                    lines.append(f"local {', '.join(rets)} = {rk(a)}({args})")
                    regs[a] = rets[0]
            elif op == 30:   # RETURN
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
            except:
                pass
            return match.group(0)
        return re.sub(r'\((-?\d+)\s*([\+\-\*\/\^])\s*(-?\d+)\)', safe_calc, code)


class EscapeSequenceTransformer(Transformer):
    def transform(self, code):
        code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), code)
        code = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)
        return code


class HexNameRenamer(Transformer):
    def transform(self, code):
        mapping = {}
        counter = 0
        def replace_hex(match):
            nonlocal counter
            h = match.group(0)
            if h not in mapping:
                counter += 1
                mapping[h] = f"var{counter}"
            return mapping[h]
        return re.sub(r'(?<![^\s\[\(\)\.\=\+\-\*\/\^\%\#\<\>\~\&\|\,])(_0x[0-9a-fA-F]+)(?=[^\w]|$)', replace_hex, code)
