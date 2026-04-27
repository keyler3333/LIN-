import copy
from symbolic_exec import SymConst, SymVar, SymBinOp, simplify
from symbolic_engine import SymState, SymStore, execute_symbolic
from z3_solver import expr_to_z3, solve_condition
from cfg import BasicBlock

class PathState:
    def __init__(self, block, sym_state=None, path_cond=None):
        self.block = block
        self.sym_state = sym_state or SymState(SymStore())
        self.path_cond = path_cond or SymConst(True)
        self.pc = 0

    def fork(self):
        return copy.deepcopy(self)

def _evaluate_condition(cond, state):
    if isinstance(cond, SymConst):
        return cond.value
    z3_expr = expr_to_z3(cond)
    if z3_expr is not None:
        return solve_condition(z3_expr)
    return None

def explore_paths(blocks):
    if not blocks:
        return []
    initial = PathState(blocks[0])
    worklist = [initial]
    resolved = []
    while worklist:
        state = worklist.pop()
        current_block = state.block
        for instr in current_block.instructions:
            execute_symbolic(instr, state.sym_state)
        if current_block.true_branch:
            cond = state.sym_state.store.get('__if_cond__')
            if cond:
                feasible = _evaluate_condition(cond, state.sym_state)
                if feasible is True or feasible is None:
                    true_state = state.fork()
                    true_state.block = current_block.true_branch
                    true_state.path_cond = SymBinOp(state.path_cond, 'and', cond)
                    true_state.sym_state.path_condition = true_state.path_cond
                    worklist.append(true_state)
                neg_cond = SymBinOp(cond, '==', SymConst(False))
                feasible_neg = _evaluate_condition(neg_cond, state.sym_state)
                if feasible_neg is True or feasible_neg is None:
                    false_state = state.fork()
                    false_state.block = current_block.false_branch if current_block.false_branch else None
                    false_state.path_cond = SymBinOp(state.path_cond, 'and', neg_cond)
                    false_state.sym_state.path_condition = false_state.path_cond
                    if false_state.block:
                        worklist.append(false_state)
            continue
        if current_block.successors:
            for succ in current_block.successors:
                next_state = state.fork()
                next_state.block = succ
                worklist.append(next_state)
        else:
            resolved.append(state)
    return resolved
