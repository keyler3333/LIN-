import luaparser.ast as ast
import luaparser.astnodes as nodes

class IRNode:
    pass

class Number(IRNode):
    def __init__(self, value):
        self.value = value

class String(IRNode):
    def __init__(self, value):
        self.value = value

class Boolean(IRNode):
    def __init__(self, value):
        self.value = value

class Nil(IRNode):
    pass

class Vararg(IRNode):
    pass

class Name(IRNode):
    def __init__(self, name):
        self.name = name

class BinOp(IRNode):
    def __init__(self, left, op, right):
        self.left = left
        self.op = op
        self.right = right

class UnaryOp(IRNode):
    def __init__(self, op, operand):
        self.op = op
        self.operand = operand

class FunctionCall(IRNode):
    def __init__(self, func, args):
        self.func = func
        self.args = args

class TableConstructor(IRNode):
    def __init__(self, fields):
        self.fields = fields

class Index(IRNode):
    def __init__(self, table, key):
        self.table = table
        self.key = key

class Assignment(IRNode):
    def __init__(self, targets, values):
        self.targets = targets
        self.values = values

class LocalDecl(IRNode):
    def __init__(self, names, values):
        self.names = names
        self.values = values

class Block(IRNode):
    def __init__(self, statements):
        self.statements = statements

class If(IRNode):
    def __init__(self, test, body, orelse):
        self.test = test
        self.body = body
        self.orelse = orelse

class While(IRNode):
    def __init__(self, test, body):
        self.test = test
        self.body = body

class Repeat(IRNode):
    def __init__(self, body, test):
        self.body = body
        self.test = test

class ForNumeric(IRNode):
    def __init__(self, var, start, end, step, body):
        self.var = var
        self.start = start
        self.end = end
        self.step = step
        self.body = body

class ForGeneric(IRNode):
    def __init__(self, vars_list, iterators, body):
        self.vars = vars_list
        self.iterators = iterators
        self.body = body

class FunctionDef(IRNode):
    def __init__(self, name, params, body, is_local):
        self.name = name
        self.params = params
        self.body = body
        self.is_local = is_local

class Return(IRNode):
    def __init__(self, values):
        self.values = values

class Break(IRNode):
    pass

def _has_attr(obj, name):
    return hasattr(obj, name)

def _to_ir(node):
    if node is None:
        return None

    if hasattr(node, 'n') and type(node.n) in (int, float):
        return Number(node.n)

    if hasattr(node, 's') and isinstance(node.s, str):
        return String(node.s)

    if hasattr(node, 'b') and isinstance(node.b, bool):
        return Boolean(node.b)

    if type(node).__name__ == 'Nil':
        return Nil()

    if type(node).__name__ == 'Vararg':
        return Vararg()

    if hasattr(node, 'id') and isinstance(node.id, str) and type(node).__name__ == 'Name':
        return Name(node.id)

    if type(node).__name__ == 'UnaryOp':
        operand = _to_ir(node.operand)
        op = node.operator if hasattr(node, 'operator') else '?'
        return UnaryOp(op, operand)

    if type(node).__name__ == 'BinOp':
        left = _to_ir(node.left)
        right = _to_ir(node.right)
        op = node.operator if hasattr(node, 'operator') else '?'
        return BinOp(left, op, right)

    if type(node).__name__ == 'Call':
        func = _to_ir(node.func)
        args = [_to_ir(a) for a in node.args] if hasattr(node, 'args') else []
        return FunctionCall(func, args)

    if type(node).__name__ == 'Table':
        fields = []
        for field in node.fields if hasattr(node, 'fields') else []:
            key = _to_ir(field.key) if hasattr(field, 'key') and field.key else None
            value = _to_ir(field.value)
            fields.append((key, value))
        return TableConstructor(fields)

    if type(node).__name__ == 'Index':
        table = _to_ir(node.value)
        key = _to_ir(node.idx)
        return Index(table, key)

    if type(node).__name__ == 'Assign':
        targets = [_to_ir(t) for t in node.targets]
        values = [_to_ir(v) for v in node.values]
        return Assignment(targets, values)

    if type(node).__name__ == 'LocalAssign':
        names = [Name(n.id) for n in node.targets]
        values = [_to_ir(v) for v in node.values] if hasattr(node, 'values') and node.values else []
        return LocalDecl(names, values)

    if type(node).__name__ == 'Block':
        stmts = [_to_ir(c) for c in node.body]
        return Block(stmts)

    if type(node).__name__ == 'If':
        test = _to_ir(node.test)
        body = _to_ir(node.body)
        orelse = _to_ir(node.orelse) if node.orelse else None
        return If(test, body, orelse)

    if type(node).__name__ == 'While':
        test = _to_ir(node.test)
        body = _to_ir(node.body)
        return While(test, body)

    if type(node).__name__ == 'Repeat':
        body = _to_ir(node.body)
        test = _to_ir(node.test)
        return Repeat(body, test)

    if type(node).__name__ == 'Fornum':
        var = Name(node.target.id)
        start = _to_ir(node.start)
        end = _to_ir(node.end)
        step = _to_ir(node.step) if node.step else Number(1)
        body = _to_ir(node.body)
        return ForNumeric(var, start, end, step, body)

    if type(node).__name__ == 'Forin':
        vars_list = [_to_ir(n) for n in node.targets]
        iterators = [_to_ir(i) for i in node.iterators]
        body = _to_ir(node.body)
        return ForGeneric(vars_list, iterators, body)

    if type(node).__name__ == 'Function':
        name = node.name.id if node.name else None
        params = [Name(p.id) if type(p).__name__ == 'Name' else Vararg() for p in node.args]
        body = _to_ir(node.body)
        is_local = not node.name
        return FunctionDef(name, params, body, is_local)

    if type(node).__name__ == 'Return':
        values = [_to_ir(v) for v in node.values] if node.values else []
        return Return(values)

    if type(node).__name__ == 'Break':
        return Break()

    return None

def build_ir(source):
    tree = ast.parse(source)
    block = tree.body
    stmts = []
    for node in block.body:
        ir = _to_ir(node)
        if ir:
            stmts.append(ir)
    return Block(stmts)
