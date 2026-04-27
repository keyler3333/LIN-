import luaparser.ast as ast
import luaparser.astnodes as nodes

class IRNode:
    pass

class Number(IRNode):
    def __init__(self, value):
        self.value = value
    def __repr__(self):
        return f"Number({self.value})"

class String(IRNode):
    def __init__(self, value):
        self.value = value
    def __repr__(self):
        return f"String('{self.value}')"

class Boolean(IRNode):
    def __init__(self, value):
        self.value = value
    def __repr__(self):
        return f"Boolean({self.value})"

class Nil(IRNode):
    def __repr__(self):
        return "Nil"

class Vararg(IRNode):
    def __repr__(self):
        return "Vararg"

class Name(IRNode):
    def __init__(self, name):
        self.name = name
    def __repr__(self):
        return f"Name({self.name})"

class BinOp(IRNode):
    def __init__(self, left, op, right):
        self.left = left
        self.op = op
        self.right = right
    def __repr__(self):
        return f"BinOp({self.left} {self.op} {self.right})"

class UnaryOp(IRNode):
    def __init__(self, op, operand):
        self.op = op
        self.operand = operand
    def __repr__(self):
        return f"UnaryOp({self.op} {self.operand})"

class FunctionCall(IRNode):
    def __init__(self, func, args):
        self.func = func
        self.args = args
    def __repr__(self):
        return f"Call({self.func}({self.args}))"

class TableConstructor(IRNode):
    def __init__(self, fields):
        self.fields = fields
    def __repr__(self):
        return f"Table({self.fields})"

class Index(IRNode):
    def __init__(self, table, key):
        self.table = table
        self.key = key
    def __repr__(self):
        return f"Index({self.table}[{self.key}])"

class Assignment(IRNode):
    def __init__(self, targets, values):
        self.targets = targets
        self.values = values
    def __repr__(self):
        return f"Assign({self.targets} = {self.values})"

class LocalDecl(IRNode):
    def __init__(self, names, values):
        self.names = names
        self.values = values
    def __repr__(self):
        return f"Local({self.names} = {self.values})"

class Block(IRNode):
    def __init__(self, statements):
        self.statements = statements
    def __repr__(self):
        return f"Block({len(self.statements)} stmts)"

class If(IRNode):
    def __init__(self, test, body, orelse):
        self.test = test
        self.body = body
        self.orelse = orelse
    def __repr__(self):
        return f"If({self.test})"

class While(IRNode):
    def __init__(self, test, body):
        self.test = test
        self.body = body
    def __repr__(self):
        return f"While({self.test})"

class Repeat(IRNode):
    def __init__(self, body, test):
        self.body = body
        self.test = test
    def __repr__(self):
        return f"Repeat({self.test})"

class ForNumeric(IRNode):
    def __init__(self, var, start, end, step, body):
        self.var = var
        self.start = start
        self.end = end
        self.step = step
        self.body = body
    def __repr__(self):
        return f"ForNumeric({self.var})"

class ForGeneric(IRNode):
    def __init__(self, vars_list, iterators, body):
        self.vars = vars_list
        self.iterators = iterators
        self.body = body
    def __repr__(self):
        return f"ForGeneric({self.vars})"

class FunctionDef(IRNode):
    def __init__(self, name, params, body, is_local):
        self.name = name
        self.params = params
        self.body = body
        self.is_local = is_local
    def __repr__(self):
        return f"Function({self.name})"

class Return(IRNode):
    def __init__(self, values):
        self.values = values
    def __repr__(self):
        return f"Return({self.values})"

class Break(IRNode):
    def __repr__(self):
        return "Break"

def _to_ir(node):
    if isinstance(node, nodes.Number):
        return Number(node.n)
    if isinstance(node, nodes.String):
        return String(node.s)
    if isinstance(node, nodes.Boolean):
        return Boolean(node.b)
    if isinstance(node, nodes.Nil):
        return Nil()
    if isinstance(node, nodes.Vararg):
        return Vararg()
    if isinstance(node, nodes.Name):
        return Name(node.id)
    if isinstance(node, nodes.UnaryOp):
        operand = _to_ir(node.operand)
        op = node.operator if hasattr(node, 'operator') else {
            nodes.UMinus: '-', nodes.BNot: '~', nodes.Not: 'not', nodes.Length: '#'
        }.get(type(node), '?')
        return UnaryOp(op, operand)
    if isinstance(node, nodes.BinOp):
        left = _to_ir(node.left)
        right = _to_ir(node.right)
        op = node.operator if hasattr(node, 'operator') else {
            nodes.Add: '+', nodes.Sub: '-', nodes.Mul: '*',
            nodes.Div: '/', nodes.Mod: '%', nodes.Pow: '^',
            nodes.Concat: '..'
        }.get(type(node), '?')
        return BinOp(left, op, right)
    if isinstance(node, nodes.Call):
        func = _to_ir(node.func)
        args = [_to_ir(a) for a in node.args]
        return FunctionCall(func, args)
    if isinstance(node, nodes.Table):
        fields = []
        for field in node.fields:
            if isinstance(field, nodes.Field):
                key = _to_ir(field.key) if field.key else None
                value = _to_ir(field.value)
                fields.append((key, value))
        return TableConstructor(fields)
    if isinstance(node, nodes.Index):
        table = _to_ir(node.value)
        key = _to_ir(node.idx)
        return Index(table, key)
    if isinstance(node, nodes.Assign):
        targets = [_to_ir(t) for t in node.targets]
        values = [_to_ir(v) for v in node.values]
        return Assignment(targets, values)
    if isinstance(node, nodes.LocalAssign):
        names = [Name(n.id) for n in node.targets]
        values = [_to_ir(v) for v in node.values] if node.values else []
        return LocalDecl(names, values)
    if isinstance(node, nodes.Block):
        stmts = []
        for child in node.body:
            stmts.append(_to_ir(child))
        return Block(stmts)
    if isinstance(node, nodes.If):
        test = _to_ir(node.test)
        body = _to_ir(node.body)
        orelse = _to_ir(node.orelse) if node.orelse else None
        return If(test, body, orelse)
    if isinstance(node, nodes.While):
        test = _to_ir(node.test)
        body = _to_ir(node.body)
        return While(test, body)
    if isinstance(node, nodes.Repeat):
        body = _to_ir(node.body)
        test = _to_ir(node.test)
        return Repeat(body, test)
    if isinstance(node, nodes.Fornum):
        var = Name(node.target.id)
        start = _to_ir(node.start)
        end = _to_ir(node.end)
        step = _to_ir(node.step) if node.step else Number(1)
        body = _to_ir(node.body)
        return ForNumeric(var, start, end, step, body)
    if isinstance(node, nodes.Forin):
        vars_list = [_to_ir(n) for n in node.targets]
        iterators = [_to_ir(i) for i in node.iterators]
        body = _to_ir(node.body)
        return ForGeneric(vars_list, iterators, body)
    if isinstance(node, nodes.Function):
        name = node.name.id if node.name else None
        params = [Name(p.id) if isinstance(p, nodes.Name) else Vararg() for p in node.args]
        body = _to_ir(node.body)
        is_local = not node.name
        return FunctionDef(name, params, body, is_local)
    if isinstance(node, nodes.Return):
        values = [_to_ir(v) for v in node.values] if node.values else []
        return Return(values)
    if isinstance(node, nodes.Break):
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
