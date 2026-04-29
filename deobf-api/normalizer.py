import re
from luaparser import ast
from luaparser.astnodes import *

def strip_luau_syntax(code):
    code = re.sub(r':\s*[a-zA-Z_][\w]*(\s*\?)?', '', code)
    code = code.replace('continue', '--[[continue]]')
    code = code.replace('+=', ' = __temp + ')
    code = re.sub(r'local function (\w+)\(([^)]*)\): *\w+', r'local function \1(\2)', code)
    return code

def _number_value(node):
    if isinstance(node, Number): return node.n
    if isinstance(node, UnaryOp) and node.operator == '-' and isinstance(node.operand, Number): return -node.operand.n
    return None

def _string_value(node):
    if isinstance(node, String): return node.s
    return None

def _fold_constants(node):
    if isinstance(node, Call) and isinstance(node.func, Name):
        if node.func.id == 'string.char' and node.args and all(_number_value(a) is not None for a in node.args):
            chars = ''.join(chr(int(_number_value(a))) for a in node.args)
            return String(chars, None)
        node.args = [_fold_constants(a) for a in node.args]
        return node
    if isinstance(node, BinaryOp):
        node.left = _fold_constants(node.left)
        node.right = _fold_constants(node.right)
        ln, rn = _number_value(node.left), _number_value(node.right)
        ls, rs = _string_value(node.left), _string_value(node.right)
        if ln is not None and rn is not None:
            if node.operator == '+': return Number(ln + rn)
            if node.operator == '-': return Number(ln - rn)
            if node.operator == '*': return Number(ln * rn)
            if node.operator == '/' and rn != 0: return Number(ln / rn)
        if ls is not None and rs is not None and node.operator == '..':
            return String(ls + rs, None)
        return node
    if isinstance(node, Block):
        node.body = [_fold_constants(s) for s in node.body]
        return node
    return node

def _de_alias(tree):
    if not isinstance(tree, Block): return tree
    aliases = {}
    for stmt in tree.body:
        if isinstance(stmt, LocalAssign) and len(stmt.targets) == 1 and len(stmt.values) == 1:
            val, target = stmt.values[0], stmt.targets[0]
            if isinstance(val, Name) and val.id in ('_G', 'string', 'math', 'table', 'bit', 'coroutine', 'os',
                                                      'game', 'workspace', 'script', 'Enum', 'Instance', 'Vector3',
                                                      'CFrame', 'Color3', 'UDim2', 'Players', 'RunService',
                                                      'UserInputService', 'TweenService', 'HttpService'):
                aliases[target.id] = val.id
    if not aliases: return tree
    def walk(node):
        if isinstance(node, Name):
            if node.id in aliases: return Name(aliases[node.id])
            return node
        if isinstance(node, Call):
            if isinstance(node.func, Name) and node.func.id in aliases:
                node.func.id = aliases[node.func.id]
            node.args = [walk(a) for a in node.args]
            return node
        if isinstance(node, Index):
            if isinstance(node.value, Name) and node.value.id in aliases:
                node.value.id = aliases[node.value.id]
            node.value = walk(node.value)
            node.idx = walk(node.idx)
            return node
        if isinstance(node, BinaryOp):
            node.left = walk(node.left)
            node.right = walk(node.right)
            return node
        if isinstance(node, UnaryOp):
            node.operand = walk(node.operand)
            return node
        if isinstance(node, LocalAssign):
            node.values = [walk(v) for v in node.values]
            return node
        if isinstance(node, Assign):
            node.targets = [walk(t) for t in node.targets]
            node.values = [walk(v) for v in node.values]
            return node
        if isinstance(node, Block):
            node.body = [walk(s) for s in node.body]
            return node
        if isinstance(node, If):
            node.test = walk(node.test)
            node.body = walk(node.body)
            if node.orelse: node.orelse = walk(node.orelse)
            return node
        if isinstance(node, While):
            node.test = walk(node.test)
            node.body = walk(node.body)
            return node
        if isinstance(node, Repeat):
            node.body = walk(node.body)
            node.test = walk(node.test)
            return node
        if isinstance(node, Fornum):
            node.start = walk(node.start)
            node.end = walk(node.end)
            if node.step: node.step = walk(node.step)
            node.body = walk(node.body)
            return node
        if isinstance(node, Forin):
            node.iterators = [walk(i) for i in node.iterators]
            node.body = walk(node.body)
            return node
        if isinstance(node, Function):
            node.body = walk(node.body)
            return node
        if isinstance(node, Return):
            node.values = [walk(v) for v in node.values]
            return node
        return node
    return walk(tree)

def _remove_dead(node):
    if isinstance(node, Block):
        new_body = []
        for stmt in node.body:
            s = _remove_dead(stmt)
            if s is not None: new_body.append(s)
        node.body = new_body
        return node
    if isinstance(node, If):
        if isinstance(node.test, Boolean):
            return _remove_dead(node.body if node.test.b else node.orelse)
        node.body = _remove_dead(node.body)
        if node.orelse: node.orelse = _remove_dead(node.orelse)
        return node
    if isinstance(node, While):
        if isinstance(node.test, Boolean) and not node.test.b: return None
        node.body = _remove_dead(node.body)
        return node
    return node

def normalize_source(source):
    source = strip_luau_syntax(source)
    tree = ast.parse(source)
    tree = _fold_constants(tree)
    tree = _remove_dead(tree)
    tree = _de_alias(tree)
    return ast.to_lua_source(tree)
