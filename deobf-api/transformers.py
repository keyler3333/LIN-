import re
import base64
import struct

class WeAreDevsLifter:
    def lift(self, source):
        table_match = re.search(r'local\s+N\s*=\s*\{(.*?)\}', source, re.DOTALL)
        if not table_match:
            return None
        raw_table = table_match.group(1)
        encoded_strings = re.findall(r'"((?:\\.|[^"\\])*)"', raw_table)

        # Extract decoder map 'b'
        decoder_match = re.search(r'local\s+b\s*=\s*\{([^}]+)\}', source, re.DOTALL)
        if not decoder_match:
            return None
        char_map = {}
        for pair in re.finditer(r'\[?"?([^"\]]+)"?\]?\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', decoder_match.group(1)):
            key = pair.group(1).strip()
            expr = pair.group(2).replace(' ', '')
            try:
                val = eval(expr) & 0x3F
                char_map[key] = val
            except:
                pass
        if len(char_map) < 40:   # must be a full Base64 table
            return None

        # Unshuffle N table
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

        # Decode all strings
        decoded_bytes = bytearray()
        for s in strings:
            accum, bits, count = 0, 0, 0
            for ch in s:
                if ch == '=':
                    if count == 3:
                        decoded_bytes.append((accum >> 16) & 0xFF)
                        decoded_bytes.append((accum >> 8) & 0xFF)
                    elif count == 2:
                        decoded_bytes.append((accum >> 16) & 0xFF)
                    break
                val = char_map.get(ch)
                if val is None:
                    continue
                accum = (accum << 6) | val
                bits += 6
                count += 1
                if count == 4:
                    decoded_bytes.extend([
                        (accum >> 16) & 0xFF,
                        (accum >> 8) & 0xFF,
                        accum & 0xFF,
                    ])
                    accum, bits, count = 0, 0, 0
        data = bytes(decoded_bytes)

        if len(data) >= 12 and data[:4] == b'\x1bLua':
            return self._lift_bytecode(data)
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


class StaticCleanup:
    def transform(self, code):
        code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), code)
        code = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)
        def safe_calc(match):
            try:
                a_str, op, b_str = match.groups()
                a, b = int(a_str), int(b_str)
                if op == '+': return str(a + b)
                if op == '-': return str(a - b)
                if op == '*': return str(a * b)
                if op == '/': return str(a // b) if b != 0 else match.group(0)
            except:
                pass
            return match.group(0)
        code = re.sub(r'\((-?\d+)\s*([\+\-\*\/])\s*(-?\d+)\)', safe_calc, code)
        return code
