import z3

def expr_to_z3(expr):
    if expr is True:
        return z3.BoolVal(True)
    if expr is False:
        return z3.BoolVal(False)
    if isinstance(expr, tuple):
        op = expr[0]
        if op == "and":
            return z3.And(expr_to_z3(expr[1]), expr_to_z3(expr[2]))
        if op == "not":
            return z3.Not(expr_to_z3(expr[1]))
    return None

def solve_condition(expr):
    s = z3.Solver()
    z = expr_to_z3(expr)
    if z is None:
        return True
    s.add(z)
    return s.check() == z3.sat
