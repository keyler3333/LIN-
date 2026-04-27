from ssa import SSAInstruction, SSAOperand
from symbolic_exec import SymConst, SymVar, SymBinOp, simplify

class SymStore:
    def __init__(self):
        self.data = {}

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value):
        self.data[key] = value

    def copy(self):
        s = SymStore()
        s.data = self.data.copy()
        return s

class SymState:
    def __init__(self, store=None):
        self.store = store or SymStore()
        self.path_condition = SymConst(True)

    def copy(self):
        s = SymState(self.store.copy())
        s.path_condition = self.path_condition
        return s

def execute_symbolic(instr, state):
    if instr.opcode == 'load_const':
        if instr.left:
            state.store.set(instr.dest.name, instr.left)
    elif instr.opcode in ('+', '-', '*', '/'):
        left_val = instr.left if not isinstance(instr.left, SSAOperand) else state.store.get(instr.left.var.name)
        right_val = instr.right if not isinstance(instr.right, SSAOperand) else state.store.get(instr.right.var.name)
        result = SymBinOp(left_val, instr.opcode, right_val)
        state.store.set(instr.dest.name, simplify(result))
    elif instr.opcode == 'if':
        cond = state.store.get(instr.dest.name) if instr.dest else None
        if isinstance(cond, SymConst):
            return cond.value
        return None
    return True
