import z3

def solve_condition(expr):
    solver = z3.Solver()
    solver.add(expr)
    result = solver.check()
    if result == z3.sat:
        return True
    elif result == z3.unsat:
        return False
    return None

def expr_to_z3(expr):
    from symbolic_exec import SymConst, SymVar, SymBinOp
    if isinstance(expr, SymConst):
        return z3.BoolVal(expr.value) if isinstance(expr.value, bool) else z3.RealVal(expr.value)
    if isinstance(expr, SymVar):
        return z3.Real(expr.name)
    if isinstance(expr, SymBinOp):
        left = expr_to_z3(expr.left)
        right = expr_to_z3(expr.right)
        op_map = {
            '+': lambda a,b: a + b, '-': lambda a,b: a - b,
            '*': lambda a,b: a * b, '/': lambda a,b: a / b,
            '==': lambda a,b: a == b, '!=': lambda a,b: a != b,
            '<': lambda a,b: a < b, '<=': lambda a,b: a <= b,
            '>': lambda a,b: a > b, '>=': lambda a,b: a >= b
        }
        if expr.op in op_map:
            return op_map[expr.op](left, right)
    return None
