import re
import base64
import struct

def _extract_cipher_mapping(source):
    mapping_pattern = r'local\s+(\w+)\s*=\s*\{(.*?)\}'
    for match in re.finditer(mapping_pattern, source, re.DOTALL):
        mapping_content = match.group(2)
        if '=' not in mapping_content or mapping_content.count('=') <= 10:
            continue
        mapping_dict = {}
        pairs = re.findall(r'\["([^"]+)"\]\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', mapping_content)
        if not pairs:
            pairs = re.findall(r'"([^"]+)"\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', mapping_content)
        if not pairs:
            pairs = re.findall(r'\[?"?([^"\]]+)"?\]?\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', mapping_content)
        for key, expr in pairs:
            try:
                val = eval(expr.replace(' ', ''))
                mapping_dict[key.strip()] = val & 0x3F
            except:
                continue
        if len(mapping_dict) > 30:
            return mapping_dict
    return None

def _decode_wearedevs_strings(source):
    cipher_map = _extract_cipher_mapping(source)
    if cipher_map is None:
        return None

    table_match = re.search(r'local\s+\w+\s*=\s*\{(.*?)\}', source, re.DOTALL)
    if not table_match:
        return None
    raw_table = table_match.group(1)
    encoded_strings = re.findall(r'"((?:\\.|[^"\\])*)"', raw_table)
    if not encoded_strings:
        return None

    decoded_chunks = []
    for s in encoded_strings:
        byte_buffer = bytearray()
        accumulator = 0
        bits = 0
        count = 0
        for ch in s:
            if ch == '=':
                if count == 3:
                    byte_buffer.append((accumulator >> 16) & 0xFF)
                    byte_buffer.append((accumulator >> 8) & 0xFF)
                elif count == 2:
                    byte_buffer.append((accumulator >> 16) & 0xFF)
                break
            val = cipher_map.get(ch)
            if val is None:
                continue
            accumulator = (accumulator << 6) | val
            bits += 6
            count += 1
            if count == 4:
                byte_buffer.extend([
                    (accumulator >> 16) & 0xFF,
                    (accumulator >> 8) & 0xFF,
                    accumulator & 0xFF,
                ])
                accumulator = 0
                bits = 0
                count = 0
        if byte_buffer:
            decoded_chunks.append(bytes(byte_buffer))

    full_data = bytearray()
    for chunk in decoded_chunks:
        full_data.extend(chunk)
    return bytes(full_data)

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
    if isinstance(data, bytes) and _is_lua_bytecode(data):
        instructions, constants = _read_lua_bytecode(data)
        lifted = _lift_lua_bytecode(instructions, constants)
        if lifted.strip():
            return lifted
    return None
