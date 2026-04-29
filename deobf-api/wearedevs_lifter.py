import re
import base64
import struct

def _decode_wearedevs_strings(source):
    table_match = re.search(r'local\s+N\s*=\s*\{(.*?)\}', source, re.DOTALL)
    if not table_match:
        return None
    raw_table = table_match.group(1)
    encoded_strings = re.findall(r'"((?:\\.|[^"\\])*)"', raw_table)

    decoder_match = re.search(r'local\s+b\s*=\s*\{([^}]+)\}', source, re.DOTALL)
    if decoder_match:
        decoder_body = decoder_match.group(1)
        char_map = {}
        for pair in re.finditer(r'\[?"?([^"\]]+)"?\]?\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', decoder_body):
            key = pair.group(1).strip()
            expr = pair.group(2).replace(' ', '')
            try:
                val = eval(expr)
                char_map[key] = val & 0x3F
            except:
                continue

        if char_map:
            decoded_bytes = bytearray()
            for s in encoded_strings:
                accum, bits, count = 0, 0, 0
                for ch in s:
                    if ch == '=':
                        if bits >= 6:
                            accum >>= bits - 6
                            decoded_bytes.append(accum & 0xFF)
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
            if decoded_bytes:
                return bytes(decoded_bytes)

    all_decoded = {}
    for s in encoded_strings:
        try:
            padded = s + "=" * ((4 - len(s) % 4) % 4)
            dec = base64.b64decode(padded).decode('latin-1', errors='replace')
            if len(dec) > 0:
                all_decoded[s] = dec
        except:
            continue

    if not all_decoded:
        return None
    full_bytecode = bytearray()
    for s in encoded_strings:
        if s in all_decoded:
            full_bytecode.extend(all_decoded[s].encode('latin-1'))
    if full_bytecode:
        return bytes(full_bytecode)
    return all_decoded

def _is_lua_bytecode(data):
    return len(data) >= 12 and data[:4] == b'\x1bLua'

def _read_lua_bytecode(bc):
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
    return instructions, constants

def _lift_lua_bytecode(instructions, constants):
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

def lift_wearedevs(source):
    data = _decode_wearedevs_strings(source)
    if data is None:
        return None
    if isinstance(data, bytes):
        if _is_lua_bytecode(data):
            instructions, constants = _read_lua_bytecode(data)
            lifted = _lift_lua_bytecode(instructions, constants)
            if lifted.strip():
                return lifted
        decoded_text = data.decode('latin-1', errors='replace')
        if decoded_text.strip():
            return decoded_text
    if isinstance(data, dict) and data:
        lines = ["-- Decoded strings from N table:"]
        for orig, dec in sorted(data.items(), key=lambda x: len(x[0])):
            lines.append(f"-- {orig} => {dec}")
        return "\n".join(lines)
    return None
