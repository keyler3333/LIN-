from copy import deepcopy
from expr import Const, And, Not
from z3_solver import solve

class PathState:
    def __init__(self, block, store, cond):
        self.block = block
        self.store = store
        self.cond = cond

def explore(entry):
    work = [PathState(entry, {}, Const(True))]
    out = []

    while work:
        st = work.pop()
        blk = st.block

        for instr in blk.instructions:
            if hasattr(instr, "eval"):
                instr.eval(st.store)

        if blk.condition:
            c = blk.condition

            true_state = PathState(blk.true_branch, dict(st.store), And(st.cond, c))
            false_state = PathState(blk.false_branch, dict(st.store), And(st.cond, Not(c)))

            if solve(true_state.cond):
                work.append(true_state)
            if solve(false_state.cond):
                work.append(false_state)
        else:
            if blk.successors:
                for s in blk.successors:
                    work.append(PathState(s, dict(st.store), st.cond))
            else:
                out.append(st)

    return out
