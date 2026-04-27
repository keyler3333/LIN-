import z3
from expr import Const, Var, BinOp, Not, And

def to_z3(e, env=None):
    env = env or {}

    if isinstance(e, Const):
        return z3.BoolVal(e.value) if isinstance(e.value, bool) else z3.IntVal(e.value)

    if isinstance(e, Var):
        if e.name not in env:
            env[e.name] = z3.Int(e.name)
        return env[e.name]

    if isinstance(e, BinOp):
        l = to_z3(e.left, env)
        r = to_z3(e.right, env)

        if e.op == "+":
            return l + r
        if e.op == "-":
            return l - r
        if e.op == "*":
            return l * r
        if e.op == "/":
            return l / r
        if e.op == "==":
            return l == r
        if e.op == "<":
            return l < r
        if e.op == ">":
            return l > r

    if isinstance(e, Not):
        return z3.Not(to_z3(e.value, env))

    if isinstance(e, And):
        return z3.And(to_z3(e.left, env), to_z3(e.right, env))

    return None

def solve(expr):
    s = z3.Solver()
    z = to_z3(expr)
    if z is None:
        return True
    s.add(z)
    return s.check() == z3.sat
