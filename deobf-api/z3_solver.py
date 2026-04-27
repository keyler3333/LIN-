import z3
from expr import Var, Const, BinOp

def to_z3(e, env=None):
    env = env or {}
    if isinstance(e, Const):
        if isinstance(e.value, bool):
            return z3.BoolVal(e.value)
        return z3.IntVal(e.value)
    if isinstance(e, Var):
        if e.name not in env:
            env[e.name] = z3.Int(e.name)
        return env[e.name]
    if isinstance(e, BinOp):
        l = to_z3(e.left, env)
        r = to_z3(e.right, env)
        ops = {
            '+': l + r, '-': l - r, '*': l * r, '/': l / r,
            '==': l == r, '<': l < r, '>': l > r
        }
        if e.op in ops:
            return ops[e.op]
    return None

def solve(expr):
    s = z3.Solver()
    z = to_z3(expr)
    if z is None:
        return True
    s.add(z)
    return s.check() == z3.sat
