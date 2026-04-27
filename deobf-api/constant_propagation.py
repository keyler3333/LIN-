import copy
from ir_builder import (Number, String, Boolean, Nil, BinOp, UnaryOp, Name,
                         LocalDecl, Assignment, Block, If, While, Repeat,
                         ForNumeric, ForGeneric, FunctionDef, Return, FunctionCall,
                         TableConstructor, Index)

def _is_constant(node):
    return isinstance(node, (Number, String, Boolean, Nil))

def _eval_binop(left, op, right):
    if not _is_constant(left) or not _is_constant(right):
        return None
    if isinstance(left, Number) and isinstance(right, Number):
        if op == '+': return Number(left.value + right.value)
        if op == '-': return Number(left.value - right.value)
        if op == '*': return Number(left.value * right.value)
        if op == '/' and right.value != 0:
            return Number(left.value / right.value)
        if op == '%' and right.value != 0:
            return Number(left.value % right.value)
        if op == '^': return Number(left.value ** right.value)
    if isinstance(left, String) and isinstance(right, String) and op == '..':
        return String(left.value + right.value)
    return None

def _eval_unary(op, operand):
    if not _is_constant(operand):
        return None
    if isinstance(operand, Number) and op == '-':
        return Number(-operand.value)
    if isinstance(operand, Boolean) and op == 'not':
        return Boolean(not operand.value)
    return None

def _clone(node):
    return copy.deepcopy(node)

def propagate(node, env=None):
    if env is None:
        env = {}
    if isinstance(node, (Number, String, Boolean, Nil)):
        return _clone(node)
    if isinstance(node, Name):
        val = env.get(node.name)
        return _clone(val) if val is not None else _clone(node)
    if isinstance(node, BinOp):
        left  = propagate(node.left,  env)
        right = propagate(node.right, env)
        result = _eval_binop(left, node.op, right)
        if result:
            return result
        n = _clone(node)
        n.left  = left
        n.right = right
        return n
    if isinstance(node, UnaryOp):
        operand = propagate(node.operand, env)
        result  = _eval_unary(node.op, operand)
        if result:
            return result
        n = _clone(node)
        n.operand = operand
        return n
    if isinstance(node, LocalDecl):
        new_env  = dict(env)
        new_vals = []
        for i, name in enumerate(node.names):
            if i < len(node.values):
                v = propagate(node.values[i], env)
                new_vals.append(v)
                if _is_constant(v):
                    new_env[name.name] = v
            else:
                new_vals.append(Nil())
                new_env[name.name] = Nil()
        env.update(new_env)
        n = _clone(node)
        n.values = new_vals
        return n
    if isinstance(node, Assignment):
        new_vals = [propagate(v, env) for v in node.values]
        for i, target in enumerate(node.targets):
            if isinstance(target, Name) and i < len(new_vals):
                if _is_constant(new_vals[i]):
                    env[target.name] = new_vals[i]
                else:
                    env.pop(target.name, None)
        n = _clone(node)
        n.values = new_vals
        return n
    if isinstance(node, Block):
        new_env   = dict(env)
        new_stmts = []
        for stmt in node.statements:
            new_stmts.append(propagate(stmt, new_env))
        n = _clone(node)
        n.statements = new_stmts
        return n
    if isinstance(node, If):
        test = propagate(node.test, env)
        body = propagate(node.body, dict(env))
        orelse = propagate(node.orelse, dict(env)) if node.orelse else None
        if isinstance(test, Boolean):
            return body if test.value else (orelse if orelse else Block([]))
        n = _clone(node)
        n.test   = test
        n.body   = body
        n.orelse = orelse
        return n
    if isinstance(node, While):
        n = _clone(node)
        n.test = propagate(node.test, env)
        n.body = propagate(node.body, dict(env))
        return n
    if isinstance(node, Repeat):
        n = _clone(node)
        n.body = propagate(node.body, dict(env))
        n.test = propagate(node.test, env)
        return n
    if isinstance(node, ForNumeric):
        n = _clone(node)
        n.start = propagate(node.start, env)
        n.end   = propagate(node.end,   env)
        n.step  = propagate(node.step,  env) if node.step else None
        n.body  = propagate(node.body,  dict(env))
        return n
    if isinstance(node, ForGeneric):
        n = _clone(node)
        n.iterators = [propagate(i, env) for i in node.iterators]
        n.body      = propagate(node.body, dict(env))
        return n
    if isinstance(node, FunctionDef):
        n = _clone(node)
        n.body = propagate(node.body, {})
        return n
    if isinstance(node, Return):
        n = _clone(node)
        n.values = [propagate(v, env) for v in node.values]
        return n
    if isinstance(node, FunctionCall):
        n = _clone(node)
        n.args = [propagate(a, env) for a in node.args]
        return n
    if isinstance(node, Index):
        n = _clone(node)
        n.table = propagate(node.table, env)
        n.key   = propagate(node.key,   env)
        return n
    return _clone(node)
