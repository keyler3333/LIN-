from ir_eval import eval_stmt
from expr import Const, Not
from z3_solver import solve
from symbolic_exec import resolve_condition, SymConst

class State:
    def __init__(self, block, sym):
        self.block = block
        self.sym   = sym

def explore(entry, max_states=500):
    work  = [State(entry, {})]
    out   = []
    seen  = set()
    count = 0
    while work and count < max_states:
        st  = work.pop()
        blk = st.block
        bid = id(blk)
        if bid in seen:
            continue
        seen.add(bid)
        count += 1
        sym_copy = dict(st.sym)
        for instr in blk.instructions:
            try:
                eval_stmt(instr, sym_copy)
            except Exception:
                pass
        if blk.true_branch and blk.false_branch:
            cond = blk.condition
            resolved = None
            if cond is not None:
                try:
                    resolved = resolve_condition(cond)
                except Exception:
                    pass
            if resolved is True:
                work.append(State(blk.true_branch, dict(sym_copy)))
            elif resolved is False:
                work.append(State(blk.false_branch, dict(sym_copy)))
            else:
                work.append(State(blk.true_branch,  dict(sym_copy)))
                work.append(State(blk.false_branch, dict(sym_copy)))
        else:
            for succ in blk.successors:
                work.append(State(succ, dict(sym_copy)))
            if not blk.successors:
                out.append(State(blk, sym_copy))
    return out
