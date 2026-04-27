from copy import deepcopy
from symbolic_engine import SymState, SymStore, execute_symbolic
from z3_solver import expr_to_z3, solve_condition

class PathState:
    def __init__(self, block, state=None, path_cond=None):
        self.block = block
        self.state = state or SymState(SymStore())
        self.path_cond = path_cond

def _is_feasible(cond, path_cond):
    z3_cond = expr_to_z3(cond)
    z3_path = expr_to_z3(path_cond)

    if z3_cond is None:
        return True

    
    return solve_condition(z3_path) if z3_path else True

def explore(entry_block):
    initial = PathState(entry_block, SymState(SymStore()), True)
    worklist = [initial]
    final_states = []

    while worklist:
        ps = worklist.pop()
        block = ps.block


        for instr in block.instructions:
            execute_symbolic(instr, ps.state)


        if block.condition and block.true_branch:

            cond = block.condition
            true_state = deepcopy(ps)
            false_state = deepcopy(ps)

            true_state.path_cond = ("and", ps.path_cond, cond)
            false_state.path_cond = ("and", ps.path_cond, ("not", cond))

            if _is_feasible(cond, ps.path_cond):
                true_state.block = block.true_branch
                worklist.append(true_state)

            if _is_feasible(("not", cond), ps.path_cond):
                false_state.block = block.false_branch
                worklist.append(false_state)

            continue


        if block.successors:
            for nxt in block.successors:
                nxt_state = deepcopy(ps)
                nxt_state.block = nxt
                worklist.append(nxt_state)
        else:
            final_states.append(ps)

    return final_states
