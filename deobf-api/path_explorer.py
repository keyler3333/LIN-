from copy import deepcopy
from ir_eval import eval_stmt, ir_to_expr
from expr import Const, And, Not
from z3_solver import solve

class State:
    def __init__(self, block, sym):
        self.block = block
        self.sym = sym

def explore(entry):
    work = [State(entry, {})]
    out = []
    while work:
        st = work.pop()
        blk = st.block
        for instr in blk.instructions:
            eval_stmt(instr, st.sym)
        if blk.true and blk.false:
            c = Const(True)
            true_sym = dict(st.sym)
            false_sym = dict(st.sym)
            t = State(blk.true, true_sym)
            f = State(blk.false, false_sym)
            if solve(c):
                work.append(t)
            if solve(Not(c)):
                work.append(f)
        else:
            if blk.next:
                for n in blk.next:
                    work.append(State(n, dict(st.sym)))
            else:
                out.append(st)
    return out
