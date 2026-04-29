import re, struct

def _decode_octal_string(s):
    result = ""
    for part in s.split("\\"):
        if part and part.isdigit():
            result += chr(int(part))
    return result

def _decode_base85_chunk(chunk):
    v = 0
    for i, c in enumerate(chunk):
        v += (ord(c) - 33) * (85 ** (4 - i))
    return struct.pack(">I", v)

def _decode_bytecode(raw_strings):
    encoded = ""
    for s in raw_strings:
        encoded += _decode_octal_string(s)
    encoded = encoded.replace("!!!!!", "z")
    encoded = re.sub(r'\.\.\.\.\.', '', encoded)
    decoded = b""
    for i in range(0, len(encoded), 5):
        chunk = encoded[i:i+5]
        if len(chunk) == 5:
            decoded += _decode_base85_chunk(chunk)
    return list(decoded)

def _lift_wearedevs_bytecode(bytecode):
    op_names = {
        0: "MOVE", 1: "LOADK", 2: "LOADBOOL", 3: "LOADNIL",
        4: "GETUPVAL", 5: "GETGLOBAL", 6: "GETTABLE", 7: "SETGLOBAL",
        8: "SETUPVAL", 9: "SETTABLE", 10: "NEWTABLE", 11: "SELF",
        12: "ADD", 13: "SUB", 14: "MUL", 15: "DIV", 16: "MOD", 17: "POW",
        18: "UNM", 19: "NOT", 20: "LEN", 21: "CONCAT", 22: "JMP",
        23: "EQ", 24: "LT", 25: "LE", 26: "TEST", 27: "TESTSET",
        28: "CALL", 29: "TAILCALL", 30: "RETURN", 31: "FORLOOP",
        32: "FORPREP", 33: "TFORLOOP", 34: "SETLIST", 35: "CLOSE",
        36: "CLOSURE", 37: "VARARG",
    }
    lines = []
    pc = 0
    reg_map = {}
    var_counter = 1

    def get_val(r):
        return reg_map.get(r, f"v{r}")

    while pc < len(bytecode):
        instr = bytecode[pc]
        op = instr & 0x3F
        a = (instr >> 6) & 0xFF
        c = (instr >> 14) & 0x1FF
        b = (instr >> 23) & 0x1FF
        pc += 1

        if op == 1:
            reg_map[a] = f"K[{b}]"
        elif op == 5:
            reg_map[a] = f"_G[K[{b}]]"
        elif op == 0:
            reg_map[a] = get_val(b)
        elif op == 12:
            reg_map[a] = f"({get_val(b)} + {get_val(c)})"
        elif op == 13:
            reg_map[a] = f"({get_val(b)} - {get_val(c)})"
        elif op == 14:
            reg_map[a] = f"({get_val(b)} * {get_val(c)})"
        elif op == 15:
            reg_map[a] = f"({get_val(b)} / {get_val(c)})"
        elif op == 16:
            reg_map[a] = f"({get_val(b)} % {get_val(c)})"
        elif op == 18:
            reg_map[a] = f"-{get_val(b)}"
        elif op == 19:
            reg_map[a] = f"not {get_val(b)}"
        elif op == 20:
            reg_map[a] = f"#{get_val(b)}"
        elif op == 21:
            parts = [get_val(b + i) for i in range(c - b + 1)]
            reg_map[a] = " .. ".join(parts)
        elif op == 22:
            lines.append(f"-- jump to {pc + c}")
        elif op == 23:
            cond = "==" if a == 0 else "~="
            lines.append(f"if {get_val(b)} {cond} {get_val(c)} then")
        elif op == 24:
            lines.append(f"if {get_val(b)} < {get_val(c)} then")
        elif op == 25:
            lines.append(f"if {get_val(b)} <= {get_val(c)} then")
        elif op == 26:
            lines.append(f"if {get_val(a)} then")
        elif op == 27:
            lines.append(f"if not {get_val(b)} then")
            reg_map[a] = get_val(b)
        elif op == 28:
            args = ", ".join(get_val(a + 1 + i) for i in range(b - 1)) if b > 1 else ""
            vname = f"var_{var_counter}"
            var_counter += 1
            if c == 1:
                lines.append(f"{get_val(a)}({args})")
            elif c == 0:
                lines.append(f"local {vname} = {get_val(a)}({args})")
                reg_map[a] = vname
            else:
                rets = [f"var_{var_counter + i}" for i in range(c - 1)]
                for rv in rets: var_counter += 1
                lines.append(f"local {', '.join(rets)} = {get_val(a)}({args})")
                reg_map[a] = rets[0]
        elif op == 30:
            lines.append("return")
            break
        elif op == 3:
            for i in range(a, b + 1): reg_map[i] = "nil"
        else:
            lines.append(f"-- op {op} ({op_names.get(op, '?')})")
    return "\n".join(lines)

def lift_wearedevs(source):
    string_table = re.search(r'local Q=\{([^}]+)\}', source)
    if not string_table: return None
    raw_strings = re.findall(r'"([^"]*)"', string_table.group(1))
    bytecode = _decode_bytecode(raw_strings)
    return _lift_wearedevs_bytecode(bytecode)
