import re, struct, math

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
    return struct.pack(">I4", v)

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
    regs = [None] * 256
    while pc < len(bytecode):
        instr = bytecode[pc]
        if isinstance(instr, int):
            op = instr & 0x3F
            a = (instr >> 6) & 0xFF
            c = (instr >> 14) & 0x1FF
            b = (instr >> 23) & 0x1FF
        else:
            op, a, b, c = 0, 0, 0, 0
        pc += 1
        if op == 1:
            lines.append(f"R{a} = K[{b}]")
        elif op == 5:
            lines.append(f"R{a} = _G[K[{b}]]")
        elif op == 7:
            lines.append(f"_G[K[{b}]] = R{a}")
        elif op == 12:
            lines.append(f"R{a} = R{b} + R{c}")
        elif op == 13:
            lines.append(f"R{a} = R{b} - R{c}")
        elif op == 14:
            lines.append(f"R{a} = R{b} * R{c}")
        elif op == 15:
            lines.append(f"R{a} = R{b} / R{c}")
        elif op == 0:
            lines.append(f"R{a} = R{b}")
        elif op == 30:
            lines.append("return")
            break
        elif op == 28:
            args = ", ".join(f"R{a+1+i}" for i in range(b-1)) if b > 1 else ""
            if c == 1:
                lines.append(f"R{a}({args})")
            elif c == 0:
                lines.append(f"local _ = R{a}({args})")
            else:
                rets = ", ".join(f"R{a+i}" for i in range(c-1))
                lines.append(f"{rets} = R{a}({args})")
        else:
            lines.append(f"-- op {op} ({op_names.get(op, '?')})")
    return "\n".join(lines)

def lift_wearedevs(source):
    string_table = re.search(r'local Q=\{([^}]+)\}', source)
    if not string_table:
        return None
    raw_strings = re.findall(r'"([^"]*)"', string_table.group(1))
    bytecode = _decode_bytecode(raw_strings)
    lifted = _lift_wearedevs_bytecode(bytecode)
    return lifted
