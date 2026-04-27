import re
from ir_builder import *

def ir_to_lua(node, indent=0):
    spaces = '    ' * indent
    if isinstance(node, Number):
        return str(node.value)
    if isinstance(node, String):
        return repr(node.value)
    if isinstance(node, Boolean):
        return 'true' if node.value else 'false'
    if isinstance(node, Nil):
        return 'nil'
    if isinstance(node, Vararg):
        return '...'
    if isinstance(node, Name):
        return node.name
    if isinstance(node, BinOp):
        return f"({ir_to_lua(node.left)} {node.op} {ir_to_lua(node.right)})"
    if isinstance(node, UnaryOp):
        return f"{node.op}{ir_to_lua(node.operand)}"
    if isinstance(node, FunctionCall):
        args = ', '.join(ir_to_lua(a) for a in node.args)
        return f"{ir_to_lua(node.func)}({args})"
    if isinstance(node, TableConstructor):
        fields = []
        for i, (k, v) in enumerate(node.fields):
            if k:
                fields.append(f"[{ir_to_lua(k)}] = {ir_to_lua(v)}")
            else:
                fields.append(ir_to_lua(v))
        return '{' + ', '.join(fields) + '}'
    if isinstance(node, Index):
        return f"{ir_to_lua(node.table)}[{ir_to_lua(node.key)}]"
    if isinstance(node, LocalDecl):
        names = 'local ' + ', '.join(n.name for n in node.names)
        if node.values:
            values = ', '.join(ir_to_lua(v) for v in node.values)
            return f"{spaces}{names} = {values}"
        return f"{spaces}{names}"
    if isinstance(node, Assignment):
        targets = ', '.join(ir_to_lua(t) for t in node.targets)
        values = ', '.join(ir_to_lua(v) for v in node.values)
        return f"{spaces}{targets} = {values}"
    if isinstance(node, Block):
        return '\n'.join(ir_to_lua(s, indent) for s in node.statements)
    if isinstance(node, If):
        lines = [f"{spaces}if {ir_to_lua(node.test)} then"]
        lines.append(ir_to_lua(node.body, indent+1))
        if node.orelse:
            if isinstance(node.orelse, If):
                lines.append(f"{spaces}elseif {ir_to_lua(node.orelse.test)} then")
                lines.append(ir_to_lua(node.orelse.body, indent+1))
                if node.orelse.orelse:
                    lines.append(f"{spaces}else")
                    lines.append(ir_to_lua(node.orelse.orelse, indent+1))
            elif isinstance(node.orelse, Block):
                lines.append(f"{spaces}else")
                lines.append(ir_to_lua(node.orelse, indent+1))
        lines.append(f"{spaces}end")
        return '\n'.join(lines)
    if isinstance(node, While):
        lines = [f"{spaces}while {ir_to_lua(node.test)} do"]
        lines.append(ir_to_lua(node.body, indent+1))
        lines.append(f"{spaces}end")
        return '\n'.join(lines)
    if isinstance(node, Repeat):
        lines = [f"{spaces}repeat"]
        lines.append(ir_to_lua(node.body, indent+1))
        lines.append(f"{spaces}until {ir_to_lua(node.test)}")
        return '\n'.join(lines)
    if isinstance(node, ForNumeric):
        step = f", {ir_to_lua(node.step)}" if node.step and not (isinstance(node.step, Number) and node.step.value == 1) else ""
        lines = [f"{spaces}for {node.var.name} = {ir_to_lua(node.start)}, {ir_to_lua(node.end)}{step} do"]
        lines.append(ir_to_lua(node.body, indent+1))
        lines.append(f"{spaces}end")
        return '\n'.join(lines)
    if isinstance(node, ForGeneric):
        vars = ', '.join(n.name for n in node.vars)
        iters = ', '.join(ir_to_lua(i) for i in node.iterators)
        lines = [f"{spaces}for {vars} in {iters} do"]
        lines.append(ir_to_lua(node.body, indent+1))
        lines.append(f"{spaces}end")
        return '\n'.join(lines)
    if isinstance(node, FunctionDef):
        params = ', '.join(p.name if isinstance(p, Name) else '...' for p in node.params)
        prefix = 'local function' if node.is_local else 'function'
        lines = [f"{spaces}{prefix} {node.name}({params})"]
        lines.append(ir_to_lua(node.body, indent+1))
        lines.append(f"{spaces}end")
        return '\n'.join(lines)
    if isinstance(node, Return):
        vals = ', '.join(ir_to_lua(v) for v in node.values)
        return f"{spaces}return {vals}"
    if isinstance(node, Break):
        return f"{spaces}break"
    return '-- unknown'
