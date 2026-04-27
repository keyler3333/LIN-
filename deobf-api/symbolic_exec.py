class SymExpr:
    pass

class SymConst(SymExpr):
    def __init__(self, value):
        self.value = value

class SymVar(SymExpr):
    def __init__(self, name):
        self.name = name

class SymBinOp(SymExpr):
    def __init__(self, left, op, right):
        self.left = left
        self.op = op
        self.right = right

def _simplify(expr):
    if isinstance(expr, SymBinOp):
        left = _simplify(expr.left)
        right = _simplify(expr.right)
        if isinstance(left, SymConst) and isinstance(right, SymConst):
            if expr.op == '+': return SymConst(left.value + right.value)
            if expr.op == '-': return SymConst(left.value - right.value)
            if expr.op == '*': return SymConst(left.value * right.value)
            if expr.op == '/' and right.value != 0: return SymConst(left.value / right.value)
            if expr.op == '==': return SymConst(left.value == right.value)
            if expr.op == '<': return SymConst(left.value < right.value)
            if expr.op == '>': return SymConst(left.value > right.value)
        if isinstance(left, SymConst) and left.value == 0 and expr.op == '*':
            return SymConst(0)
        if isinstance(right, SymConst) and right.value == 0 and expr.op == '*':
            return SymConst(0)
        if isinstance(right, SymConst) and right.value == 0 and expr.op == '==':
            return SymConst(left.value == 0 if isinstance(left, SymConst) else None)
        return SymBinOp(left, expr.op, right)
    return expr

def resolve_condition(expr, env=None):
    expr = _simplify(expr)
    if isinstance(expr, SymConst):
        return expr.value
    return None
