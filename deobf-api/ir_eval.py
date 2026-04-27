from ir_builder import (
    Name, Number, String, Boolean, Nil,
    BinOp as IRBinOp, UnaryOp, FunctionCall, Index,
    Assignment, LocalDecl, If, While, Repeat,
    ForNumeric, ForGeneric, FunctionDef, Return, Break, Block
)
from expr import Expr, Const, Var, BinOp, Not, And

def ir_to_expr(node, env=None):
    env = env or {}
    if isinstance(node, Number):
        return Const(node.value)
    if isinstance(node, String):
        return Const(node.value)
    if isinstance(node, Boolean):
        return Const(node.value)
    if isinstance(node, Nil):
        return Const(None)
    if isinstance(node, Name):
        return Var(node.name)
    if isinstance(node, IRBinOp):
        left = ir_to_expr(node.left, env)
        right = ir_to_expr(node.right, env)
        return BinOp(left, node.op, right)
    if isinstance(node, UnaryOp):
        operand = ir_to_expr(node.operand, env)
        if node.op == '-':
            return BinOp(Const(0), '-', operand)
        if node.op == 'not':
            return Not(operand)
        return operand
    return Const(None)

def eval_stmt(stmt, store):
    if isinstance(stmt, LocalDecl):
        for i, name in enumerate(stmt.names):
            if i < len(stmt.values):
                val = ir_to_expr(stmt.values[i], store)
                store[name.name] = val
            else:
                store[name.name] = Const(None)
    elif isinstance(stmt, Assignment):
        for target in stmt.targets:
            if isinstance(target, Name) and stmt.values:
                val = ir_to_expr(stmt.values[0], store)
                store[target.name] = val
