import re
import struct

class VMState:
    def __init__(self, bytecode, constants, proto):
        self.code = bytecode
        self.consts = constants
        self.protos = proto
        self.stack = []
        self.regs = [None] * 256
        self.pc = 0

    def push(self, v):
        self.stack.append(v)

    def pop(self):
        return self.stack.pop() if self.stack else None

def _decode_instruction(instr):
    op = instr & 0x3F
    a = (instr >> 6) & 0xFF
    c = (instr >> 14) & 0x1FF
    b = (instr >> 23) & 0x1FF
    return op, a, b, c

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

def _rk(vm, rk_val):
    if rk_val >= 256:
        return vm.consts[rk_val - 256]
    return vm.regs[rk_val]

def emulate_vm(code, constants, protos, num_params=0):
    vm = VMState(code, constants, protos)
    output_lines = []
    pc_list = []
    while vm.pc < len(vm.code):
        instr = vm.code[vm.pc]
        op, a, b, c = _decode_instruction(instr)
        vm.pc += 1
        if op == 1:
            vm.regs[a] = vm.consts[b]
            output_lines.append(f"R{a} = {repr(vm.consts[b])}")
        elif op == 5:
            vm.regs[a] = f"_G[{repr(vm.consts[b])}]"
        elif op == 12:
            res = f"({_rk(vm, b)} + {_rk(vm, c)})"
            vm.regs[a] = res
            output_lines.append(f"R{a} = {res}")
        elif op == 28:
            args = ", ".join(str(_rk(vm, a+1+i)) for i in range(b-1)) if b > 1 else ""
            output_lines.append(f"{_rk(vm, a)}({args})")
        elif op == 30:
            rets = ", ".join(str(_rk(vm, a+i)) for i in range(b-1)) if b > 1 else ""
            output_lines.append(f"return {rets}")
            break
        else:
            output_lines.append(f"-- op {op} ({OP_NAMES.get(op,'?')})")
    return '\n'.join(output_lines)

def lift_vm_from_source(source):
    const_match = re.search(r'local\s+(\w+)\s*=\s*\{([\d\s,]+)\}', source)
    if not const_match:
        return None
    consts = [int(c.strip()) for c in const_match.group(2).split(',') if c.strip().isdigit()]
    code_match = re.search(r'local\s+(\w+)\s*=\s*\{([^}]+)\}', source)  # simplistic
    return emulate_vm(consts, [], [], 0)
