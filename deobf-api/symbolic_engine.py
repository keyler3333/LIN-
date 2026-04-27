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
        s.data = dict(self.data)
        return s

class SymState:
    def __init__(self, store=None):
        self.store           = store or SymStore()
        self.path_condition  = SymConst(True)
    def copy(self):
        s = SymState(self.store.copy())
        s.path_condition = self.path_condition
        return s

def execute_symbolic(instr, state):
    if not isinstance(instr, SSAInstruction):
        return True
    if instr.opcode == 'load_const':
        if instr.dest and instr.left is not None:
            state.store.set(instr.dest.name, instr.left)
    elif instr.opcode in ('+', '-', '*', '/'):
        def resolve(operand):
            if isinstance(operand, SSAOperand):
                val = state.store.get(operand.var.name)
                return val if val is not None else SymVar(operand.var.name)
            return operand
        left_val  = resolve(instr.left)  if instr.left  else SymConst(0)
        right_val = resolve(instr.right) if instr.right else SymConst(0)
        result    = simplify(SymBinOp(left_val, instr.opcode, right_val))
        if instr.dest:
            state.store.set(instr.dest.name, result)
    elif instr.opcode == 'if':
        cond = state.store.get(instr.dest.name) if instr.dest else None
        if isinstance(cond, SymConst):
            return bool(cond.value)
        return None
    return True
