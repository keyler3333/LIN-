from symbolic_exec import SymConst, SymVar, SymBinOp, simplify
from symbolic_engine import SymState, SymStore, execute_symbolic
from z3_solver import expr_to_z3, solve_condition
import copy

class PathState:
    def __init__(self, ssa_instrs, pc=0, sym_state=None):
        self.instrs = ssa_instrs
        self.pc = pc
        self.sym_state = sym_state or SymState(SymStore())
        self.path_cond = SymConst(True)

    def fork(self):
        return copy.deepcopy(self)

def explore_paths(ssa_instrs, max_depth=1000):
    initial = PathState(ssa_instrs)
    worklist = [initial]
    resolved = []
    while worklist:
        state = worklist.pop()
        while state.pc < len(state.instrs):
            instr = state.instrs[state.pc]
            res = execute_symbolic(instr, state.sym_state)
            if instr.opcode == 'if':
                cond = state.sym_state.store.get(instr.dest.name) if instr.dest else None
                if isinstance(cond, SymConst):
                    state.pc += 1
                    continue
                z3_expr = expr_to_z3(cond) if cond else None
                if z3_expr is not None:
                    feasible = solve_condition(z3_expr)
                    if feasible is True:
                        true_state = state.fork()
                        true_state.path_cond = SymBinOp(state.path_cond, 'and', cond)
                        true_state.sym_state.path_condition = true_state.path_cond
                        true_state.pc += 1
                        worklist.append(true_state)
                    neg_cond = SymBinOp(cond, 'not') if cond else None
                    neg_feasible = solve_condition(expr_to_z3(neg_cond)) if neg_cond else None
                    if neg_feasible is True:
                        false_state = state.fork()
                        false_state.path_cond = SymBinOp(state.path_cond, 'and', neg_cond)
                        false_state.sym_state.path_condition = false_state.path_cond
                        false_state.pc += 2  # skip over the if block? depends on structure
                        worklist.append(false_state)
                    break
            elif instr.opcode == 'jmp':
                state.pc += instr.left  # assuming immediate?
                continue
            state.pc += 1
        resolved.append(state)
    return resolved
