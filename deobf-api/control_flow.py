import re
from ir_builder import Block, If, While, Boolean, BinOp, Name

def flatten_to_structured(body):
    if not isinstance(body, list):
        return [body]
    statements = []
    for stmt in body:
        if isinstance(stmt, Block):
            statements.extend(flatten_to_structured(stmt.statements))
        else:
            statements.append(stmt)
    return statements

def detect_state_machine(block):
    if not isinstance(block, Block):
        return False
    pattern_while_true = False
    pattern_if_cmp     = False
    for stmt in block.statements:
        if isinstance(stmt, While):
            if isinstance(stmt.test, Boolean) and stmt.test.value is True:
                pattern_while_true = True
                inner = flatten_to_structured(
                    stmt.body.statements if isinstance(stmt.body, Block) else [stmt.body]
                )
                for inner_stmt in inner:
                    if isinstance(inner_stmt, If):
                        test = inner_stmt.test
                        if isinstance(test, BinOp) and test.op in ('==', '<', '<=', '>', '>='):
                            pattern_if_cmp = True
    return pattern_while_true and pattern_if_cmp

def reconstruct_control_flow(block):
    if not isinstance(block, Block):
        return block
    new_stmts = []
    for stmt in block.statements:
        if isinstance(stmt, While):
            if isinstance(stmt.test, Boolean) and stmt.test.value is True:
                inner_stmts = flatten_to_structured(
                    stmt.body.statements if isinstance(stmt.body, Block) else [stmt.body]
                )
                if not inner_stmts:
                    continue
                state_var = None
                cases     = []
                fallback  = None
                for inner_stmt in inner_stmts:
                    if isinstance(inner_stmt, If):
                        test = inner_stmt.test
                        if isinstance(test, BinOp) and test.op in ('==', '<', '<=', '>', '>='):
                            if not state_var:
                                state_var = test.left
                            cases.append((test, inner_stmt.body))
                            if inner_stmt.orelse:
                                fallback = inner_stmt.orelse
                if state_var and len(cases) > 1:
                    new_stmts.append(_build_switch(state_var, cases, fallback))
                    continue
        new_stmts.append(stmt)
    return Block(new_stmts)

def _build_switch(var, cases, fallback):
    if_final = None
    for test, body in reversed(cases):
        if if_final is None:
            if_final = If(test, body, fallback)
        else:
            if_final = If(test, body, if_final)
    return if_final if if_final else fallback
