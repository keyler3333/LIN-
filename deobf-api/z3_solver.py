try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

from expr import Var, Const, BinOp, Not

def to_z3(e, env=None):
    if not Z3_AVAILABLE:
        return None
    env = env or {}
    if isinstance(e, Const):
        if e.value is None:
            return None
        if isinstance(e.value, bool):
            return z3.BoolVal(e.value)
        if isinstance(e.value, (int, float)):
            return z3.IntVal(int(e.value))
        return None
    if isinstance(e, Var):
        if e.name not in env:
            env[e.name] = z3.Int(e.name)
        return env[e.name]
    if isinstance(e, Not):
        inner = to_z3(e.value, env)
        if inner is None:
            return None
        return z3.Not(inner)
    if isinstance(e, BinOp):
        l = to_z3(e.left,  env)
        r = to_z3(e.right, env)
        if l is None or r is None:
            return None
        try:
            ops = {
                '+':  l + r,
                '-':  l - r,
                '*':  l * r,
                '/':  l / r,
                '==': l == r,
                '~=': l != r,
                '<':  l < r,
                '>':  l > r,
                '<=': l <= r,
                '>=': l >= r,
            }
            return ops.get(e.op)
        except Exception:
            return None
    return None

def solve(expr):
    if not Z3_AVAILABLE:
        # Fall back: unknown conditions are treated as satisfiable
        return True
    z = to_z3(expr)
    if z is None:
        return True  # unknown — assume satisfiable
    try:
        s = z3.Solver()
        s.add(z)
        return s.check() == z3.sat
    except Exception:
        return True
