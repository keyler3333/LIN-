from ir_builder import *

def _is_constant(ir):
    return isinstance(ir, (Number, String, Boolean, Nil))

def _eval_binop(left, op, right):
    try:
        if op == '+': return Number(left.value + right.value)
        if op == '-': return Number(left.value - right.value)
        if op == '*': return Number(left.value * right.value)
        if op == '/': return Number(left.value / right.value) if right.value != 0 else None
        if op == '%': return Number(left.value % right.value) if right.value != 0 else None
        if op == '..': return String(str(left.value) + str(right.value))
    except:
        pass
    return None

def _eval_unary(op, operand):
    if op == '-': return Number(-operand.value)
    if op == 'not': return Boolean(not operand.value)
    if op == '#': return Number(len(operand.value)) if isinstance(operand, String) else None
    return None

def propagate(node, env=None):
    if env is None:
        env = {}
    if isinstance(node, Number) or isinstance(node, String) or isinstance(node, Boolean) or isinstance(node, Nil):
        return node
    if isinstance(node, Name):
        if node.name in env and _is_constant(env[node.name]):
            return env[node.name]
        return node
    if isinstance(node, BinOp):
        left = propagate(node.left, env)
        right = propagate(node.right, env)
        node.left, node.right = left, right
        if _is_constant(left) and _is_constant(right):
            evaluated = _eval_binop(left, node.op, right)
            if evaluated:
                return evaluated
        return node
    if isinstance(node, UnaryOp):
        operand = propagate(node.operand, env)
        node.operand = operand
        if _is_constant(operand):
            evaluated = _eval_unary(node.op, operand)
            if evaluated:
                return evaluated
        return node
    if isinstance(node, LocalDecl):
        new_env = env.copy()
        for i, name in enumerate(node.names):
            if i < len(node.values):
                node.values[i] = propagate(node.values[i], env)
                val = node.values[i]
                if _is_constant(val):
                    new_env[name.name] = val
            else:
                new_env[name.name] = Nil()
        return LocalDecl(node.names, node.values)
    if isinstance(node, Assignment):
        for i, target in enumerate(node.targets):
            if i < len(node.values):
                node.values[i] = propagate(node.values[i], env)
        return node
    if isinstance(node, Block):
        new_env = env.copy()
        for i, stmt in enumerate(node.statements):
            node.statements[i] = propagate(stmt, new_env)
            if isinstance(stmt, LocalDecl):
                for j, name in enumerate(stmt.names):
                    if j < len(stmt.values) and _is_constant(stmt.values[j]):
                        new_env[name.name] = stmt.values[j]
                    else:
                        new_env.pop(name.name, None)
        return node
    if isinstance(node, If):
        node.test = propagate(node.test, env)
        node.body = propagate(node.body, env)
        if node.orelse:
            node.orelse = propagate(node.orelse, env)
        return node
    if isinstance(node, While):
        node.test = propagate(node.test, env)
        node.body = propagate(node.body, env)
        return node
    if isinstance(node, Repeat):
        node.body = propagate(node.body, env)
        node.test = propagate(node.test, env)
        return node
    if isinstance(node, ForNumeric):
        node.start = propagate(node.start, env)
        node.end = propagate(node.end, env)
        if node.step:
            node.step = propagate(node.step, env)
        node.body = propagate(node.body, env)
        return node
    if isinstance(node, FunctionDef):
        node.body = propagate(node.body, env)
        return node
    if isinstance(node, Return):
        node.values = [propagate(v, env) for v in node.values]
        return node
    return node
