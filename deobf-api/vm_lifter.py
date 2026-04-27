import re

OP_NAMES = {
    0: 'MOVE', 1: 'LOADK', 2: 'LOADBOOL', 3: 'LOADNIL',
    4: 'GETUPVAL', 5: 'GETGLOBAL', 6: 'GETTABLE', 7: 'SETGLOBAL',
    8: 'SETUPVAL', 9: 'SETTABLE', 10: 'NEWTABLE', 11: 'SELF',
    12: 'ADD', 13: 'SUB', 14: 'MUL', 15: 'DIV', 16: 'MOD', 17: 'POW',
    18: 'UNM', 19: 'NOT', 20: 'LEN', 21: 'CONCAT', 22: 'JMP',
    23: 'EQ', 24: 'LT', 25: 'LE', 26: 'TEST', 27: 'TESTSET',
    28: 'CALL', 29: 'TAILCALL', 30: 'RETURN', 31: 'FORLOOP',
    32: 'FORPREP', 33: 'TFORLOOP', 34: 'SETLIST', 35: 'CLOSE',
    36: 'CLOSURE', 37: 'VARARG'
}

def _decode_instruction(instr):
    op = instr & 0x3F
    a = (instr >> 6) & 0xFF
    c = (instr >> 14) & 0x1FF
    b = (instr >> 23) & 0x1FF
    return op, a, b, c

class VMState:
    def __init__(self, code, constants, protos):
        self.code = code
        self.consts = constants
        self.protos = protos
        self.regs = [None] * 256
        self.pc = 0
        self.stack = []

    def rk(self, v):
        if v >= 256:
            idx = v - 256
            if idx < len(self.consts):
                return self.consts[idx]
            return 'nil'
        if self.regs[v] is not None:
            return self.regs[v]
        return f'R{v}'

def emulate_vm(code, constants, protos):
    vm = VMState(code, constants, protos)
    lines = []
    while vm.pc < len(vm.code):
        instr = vm.code[vm.pc]
        op, a, b, c = _decode_instruction(instr)
        vm.pc += 1
        if op == 0:
            vm.regs[a] = vm.rk(b)
            lines.append(f'R{a} = {vm.rk(b)}')
        elif op == 1:
            vm.regs[a] = f'{repr(constants[b])}'
            lines.append(f'R{a} = {repr(constants[b])}')
        elif op == 2:
            vm.regs[a] = 'true' if b else 'false'
            if c: vm.pc += 1
        elif op == 3:
            for i in range(a, b + 1): vm.regs[i] = 'nil'
        elif op == 5:
            vm.regs[a] = f'_G[{repr(constants[b])}]'
        elif op == 6:
            vm.regs[a] = f'{vm.rk(b)}[{vm.rk(c)}]'
        elif op == 7:
            lines.append(f'_G[{repr(constants[b])}] = {vm.rk(a)}')
        elif op == 9:
            lines.append(f'{vm.rk(a)}[{vm.rk(b)}] = {vm.rk(c)}')
        elif op == 10:
            vm.regs[a] = '{}'
        elif op == 12:
            res = f'({vm.rk(b)} + {vm.rk(c)})'
            vm.regs[a] = res
            lines.append(f'R{a} = {res}')
        elif op == 13:
            res = f'({vm.rk(b)} - {vm.rk(c)})'
            vm.regs[a] = res
        elif op == 14:
            res = f'({vm.rk(b)} * {vm.rk(c)})'
            vm.regs[a] = res
        elif op == 15:
            res = f'({vm.rk(b)} / {vm.rk(c)})'
            vm.regs[a] = res
        elif op == 18:
            vm.regs[a] = f'-{vm.rk(b)}'
        elif op == 19:
            vm.regs[a] = f'not {vm.rk(b)}'
        elif op == 20:
            vm.regs[a] = f'#{vm.rk(b)}'
        elif op == 21:
            parts = [str(vm.rk(i)) for i in range(b, c + 1)]
            vm.regs[a] = ' .. '.join(parts)
        elif op == 22:
            sx = c
            if sx >= 0x8000:
                sx -= 0x10000
            vm.pc += sx
            lines.append(f'-- jump {sx}')
        elif op == 23:
            cond = '==' if a == 0 else '~='
            lines.append(f'if {vm.rk(b)} {cond} {vm.rk(c)} then skip')
            vm.pc += 1
        elif op == 24:
            cond = '<' if a == 0 else '>='
            lines.append(f'if {vm.rk(b)} {cond} {vm.rk(c)} then skip')
            vm.pc += 1
        elif op == 25:
            cond = '<=' if a == 0 else '>'
            lines.append(f'if {vm.rk(b)} {cond} {vm.rk(c)} then skip')
            vm.pc += 1
        elif op == 26:
            if c == 0:
                lines.append(f'if not {vm.rk(a)} then skip')
                vm.pc += 1
        elif op == 27:
            if c == 0:
                lines.append(f'if not {vm.rk(b)} then skip')
            vm.regs[a] = vm.rk(b)
            vm.pc += 1
        elif op == 28:
            args = ', '.join(str(vm.rk(a + 1 + i)) for i in range(b - 1)) if b > 1 else ''
            if c == 1:
                lines.append(f'{vm.rk(a)}({args})')
            elif c == 0:
                lines.append(f'local _ = {vm.rk(a)}({args})')
            else:
                rets = ', '.join(f'R{a + i}' for i in range(c - 1))
                lines.append(f'{rets} = {vm.rk(a)}({args})')
        elif op == 30:
            rets = ', '.join(str(vm.rk(a + i)) for i in range(b - 1)) if b > 1 else ''
            lines.append(f'return {rets}')
            break
        elif op == 36:
            lines.append(f'R{a} = closure_{b}')
        elif op == 31:
            lines.append(f'-- forloop step')
        elif op == 32:
            lines.append(f'-- forprep')
        elif op == 33:
            lines.append(f'-- tforloop')
        else:
            lines.append(f'-- op {op} ({OP_NAMES.get(op, "?")})')
    return '\n'.join(lines)

def lift_vm_from_source(source):
    const_match = re.search(r'local\s+(\w+)\s*=\s*\{([\d\s,]+)\}', source)
    if not const_match:
        const_match = re.search(r'local\s+(\w+)\s*=\s*\{\s*"([^"]+)"\s*\}', source)
        if const_match:
            consts = [ord(c) for c in const_match.group(2)]
        else:
            return None
    else:
        consts = [int(c.strip()) for c in const_match.group(2).split(',') if c.strip().isdigit()]
    code_match = re.search(r'local\s+(\w+)\s*=\s*\{([^}]+)\}', source)
    if not code_match:
        return None
    code = [int(c.strip()) for c in code_match.group(2).split(',') if c.strip().isdigit()]
    return emulate_vm(code, consts, [])
