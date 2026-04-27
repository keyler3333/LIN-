import copy
from ir_builder import (Block, If, While, Repeat, ForNumeric, ForGeneric,
                         FunctionDef, LocalDecl, Assignment, Number, String,
                         Boolean, Nil, BinOp, UnaryOp, Name, Return, Break,
                         Vararg, FunctionCall, Index, TableConstructor)

def _collect_used(node, used):
    if node is None:
        return
    if isinstance(node, Name):
        used.add(node.name)
        return
    if isinstance(node, (Number, String, Boolean, Nil, Vararg, Break)):
        return
    if isinstance(node, BinOp):
        _collect_used(node.left, used)
        _collect_used(node.right, used)
    elif isinstance(node, UnaryOp):
        _collect_used(node.operand, used)
    elif isinstance(node, FunctionCall):
        _collect_used(node.func, used)
        for a in node.args:
            _collect_used(a, used)
    elif isinstance(node, Index):
        _collect_used(node.table, used)
        _collect_used(node.key,   used)
    elif isinstance(node, TableConstructor):
        for k, v in node.fields:
            if k: _collect_used(k, used)
            _collect_used(v, used)
    elif isinstance(node, Return):
        for v in node.values:
            _collect_used(v, used)
    elif isinstance(node, Assignment):
        for t in node.targets: _collect_used(t, used)
        for v in node.values:  _collect_used(v, used)
    elif isinstance(node, LocalDecl):
        for v in node.values: _collect_used(v, used)
    elif isinstance(node, Block):
        for s in node.statements: _collect_used(s, used)
    elif isinstance(node, If):
        _collect_used(node.test, used)
        _collect_used(node.body, used)
        if node.orelse: _collect_used(node.orelse, used)
    elif isinstance(node, While):
        _collect_used(node.test, used)
        _collect_used(node.body, used)
    elif isinstance(node, Repeat):
        _collect_used(node.body, used)
        _collect_used(node.test, used)
    elif isinstance(node, ForNumeric):
        _collect_used(node.start, used)
        _collect_used(node.end,   used)
        if node.step: _collect_used(node.step, used)
        _collect_used(node.body, used)
    elif isinstance(node, ForGeneric):
        for i in node.iterators: _collect_used(i, used)
        _collect_used(node.body, used)
    elif isinstance(node, FunctionDef):
        _collect_used(node.body, used)

def remove_dead_code(node):
    if isinstance(node, Block):
        new_stmts = []
        for stmt in node.statements:
            cleaned = remove_dead_code(stmt)
            if cleaned is not None:
                new_stmts.append(cleaned)
        return Block(new_stmts)
    if isinstance(node, If):
        if isinstance(node.test, Boolean):
            if node.test.value is True:
                return remove_dead_code(node.body)
            else:
                return remove_dead_code(node.orelse) if node.orelse else None
        n = copy.copy(node)
        n.test   = remove_dead_code(node.test)
        n.body   = remove_dead_code(node.body)
        n.orelse = remove_dead_code(node.orelse) if node.orelse else None
        return n
    if isinstance(node, While):
        if isinstance(node.test, Boolean) and node.test.value is False:
            return None
        n = copy.copy(node)
        n.test = remove_dead_code(node.test)
        n.body = remove_dead_code(node.body)
        return n
    if isinstance(node, (Repeat, ForNumeric, ForGeneric, FunctionDef)):
        n = copy.copy(node)
        n.body = remove_dead_code(node.body)
        return n
    if isinstance(node, (Number, String, Boolean, Nil, Name, Vararg, Break)):
        return node
    if isinstance(node, BinOp):
        n = copy.copy(node)
        n.left  = remove_dead_code(node.left)
        n.right = remove_dead_code(node.right)
        return n
    if isinstance(node, UnaryOp):
        n = copy.copy(node)
        n.operand = remove_dead_code(node.operand)
        return n
    if isinstance(node, (LocalDecl, Assignment, Return)):
        return node
    return node

def remove_unused_assignments(node):
    if not isinstance(node, Block):
        return node
    used = set()
    for stmt in node.statements:
        if isinstance(stmt, LocalDecl):
            for v in stmt.values:
                _collect_used(v, used)
        elif isinstance(stmt, Assignment):
            for t in stmt.targets:
                _collect_used(t, used)
            for v in stmt.values:
                _collect_used(v, used)
        else:
            _collect_used(stmt, used)
    new_stmts = []
    for stmt in node.statements:
        if isinstance(stmt, LocalDecl):
            all_unused = all(n.name not in used for n in stmt.names)
            all_pure   = all(isinstance(v, (Number, String, Boolean, Nil))
                             for v in stmt.values) if stmt.values else True
            if all_unused and all_pure:
                continue
        new_stmts.append(stmt)
    n = copy.copy(node)
    n.statements = new_stmts
    return n
