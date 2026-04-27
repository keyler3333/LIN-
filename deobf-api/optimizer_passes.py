from ir_builder import Block, If, While, Repeat, ForNumeric, ForGeneric, FunctionDef, LocalDecl, Assignment, Number, String, Boolean, Nil, BinOp, UnaryOp, Name, Return, Break, Vararg

def remove_dead_code(ir_node):
    if isinstance(ir_node, Block):
        new_stmts = []
        for stmt in ir_node.statements:
            cleaned = remove_dead_code(stmt)
            if cleaned is not None:
                new_stmts.append(cleaned)
        return Block(new_stmts)
    if isinstance(ir_node, If):
        if isinstance(ir_node.test, Boolean):
            if ir_node.test.value is True:
                return remove_dead_code(ir_node.body)
            elif ir_node.test.value is False:
                if ir_node.orelse:
                    return remove_dead_code(ir_node.orelse)
                return None
        ir_node.test = remove_dead_code(ir_node.test)
        ir_node.body = remove_dead_code(ir_node.body)
        if ir_node.orelse:
            ir_node.orelse = remove_dead_code(ir_node.orelse)
        return ir_node
    if isinstance(ir_node, While):
        if isinstance(ir_node.test, Boolean) and ir_node.test.value is False:
            return None
        ir_node.test = remove_dead_code(ir_node.test)
        ir_node.body = remove_dead_code(ir_node.body)
        return ir_node
    if isinstance(ir_node, Repeat):
        ir_node.body = remove_dead_code(ir_node.body)
        ir_node.test = remove_dead_code(ir_node.test)
        return ir_node
    if isinstance(ir_node, ForNumeric):
        ir_node.start = remove_dead_code(ir_node.start)
        ir_node.end = remove_dead_code(ir_node.end)
        if ir_node.step:
            ir_node.step = remove_dead_code(ir_node.step)
        ir_node.body = remove_dead_code(ir_node.body)
        return ir_node
    if isinstance(ir_node, ForGeneric):
        ir_node.iterators = [remove_dead_code(i) for i in ir_node.iterators]
        ir_node.body = remove_dead_code(ir_node.body)
        return ir_node
    if isinstance(ir_node, FunctionDef):
        ir_node.body = remove_dead_code(ir_node.body)
        return ir_node
    if isinstance(ir_node, (Number, String, Boolean, Nil, Name, Vararg, Break)):
        return ir_node
    if isinstance(ir_node, BinOp):
        ir_node.left = remove_dead_code(ir_node.left)
        ir_node.right = remove_dead_code(ir_node.right)
        return ir_node
    if isinstance(ir_node, UnaryOp):
        ir_node.operand = remove_dead_code(ir_node.operand)
        return ir_node
    if isinstance(ir_node, LocalDecl):
        ir_node.values = [remove_dead_code(v) for v in ir_node.values]
        return ir_node
    if isinstance(ir_node, Assignment):
        ir_node.targets = [remove_dead_code(t) for t in ir_node.targets]
        ir_node.values = [remove_dead_code(v) for v in ir_node.values]
        return ir_node
    if isinstance(ir_node, Return):
        ir_node.values = [remove_dead_code(v) for v in ir_node.values]
        return ir_node
    return ir_node

def remove_unused_assignments(ir_node, used_vars=None):
    if used_vars is None:
        used_vars = set()
    if isinstance(ir_node, Block):
        new_stmts = []
        for stmt in reversed(ir_node.statements):
            if isinstance(stmt, LocalDecl):
                if all(n.name not in used_vars and isinstance(v, (Number, String, Boolean, Nil)) for n, v in zip(stmt.names, stmt.values) if stmt.values):
                    continue
                new_stmts.append(stmt)
                for n in stmt.names:
                    used_vars.add(n.name)
            elif isinstance(stmt, Assignment):
                new_stmts.append(stmt)
                for t in stmt.targets:
                    if isinstance(t, Name):
                        used_vars.add(t.name)
            else:
                new_stmts.append(stmt)
        new_stmts.reverse()
        return Block(new_stmts)
    if isinstance(ir_node, If):
        ir_node.body = remove_unused_assignments(ir_node.body, used_vars.copy())
        if ir_node.orelse:
            ir_node.orelse = remove_unused_assignments(ir_node.orelse, used_vars.copy())
        return ir_node
    if isinstance(ir_node, While):
        ir_node.body = remove_unused_assignments(ir_node.body, used_vars.copy())
        return ir_node
    if isinstance(ir_node, Repeat):
        ir_node.body = remove_unused_assignments(ir_node.body, used_vars.copy())
        return ir_node
    if isinstance(ir_node, ForNumeric):
        ir_node.body = remove_unused_assignments(ir_node.body, used_vars.copy())
        return ir_node
    if isinstance(ir_node, ForGeneric):
        ir_node.body = remove_unused_assignments(ir_node.body, used_vars.copy())
        return ir_node
    if isinstance(ir_node, FunctionDef):
        ir_node.body = remove_unused_assignments(ir_node.body, used_vars.copy())
        return ir_node
    if isinstance(ir_node, LocalDecl):
        for n in ir_node.names:
            used_vars.add(n.name)
        return ir_node
    if isinstance(ir_node, Assignment):
        for t in ir_node.targets:
            if isinstance(t, Name):
                used_vars.add(t.name)
        return ir_node
    return ir_node
