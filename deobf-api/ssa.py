class SSAVar:
    def __init__(self, name, version=0):
        self.name = name
        self.version = version

    def __repr__(self):
        return f"{self.name}_{self.version}"

class SSAValue:
    pass

class SSANumber(SSAValue):
    def __init__(self, value):
        self.value = value

class SSAString(SSAValue):
    def __init__(self, value):
        self.value = value

class SSAOperand(SSAValue):
    def __init__(self, var):
        self.var = var

class SSAInstruction:
    def __init__(self, opcode, dest=None, left=None, right=None):
        self.opcode = opcode
        self.dest = dest
        self.left = left
        self.right = right

class SSABlock:
    def __init__(self):
        self.instructions = []
        self.predecessors = []
        self.successors = []
        self.phi_nodes = {}

def convert_to_ssa(ir_block, initial_vars=None):
    var_versions = {}
    if initial_vars:
        var_versions.update(initial_vars)
    ssa_instructions = []
    for stmt in (ir_block.statements if hasattr(ir_block, 'statements') else []):
        _convert_stmt_to_ssa(stmt, var_versions, ssa_instructions)
    return ssa_instructions, var_versions

def _convert_stmt_to_ssa(stmt, var_versions, output):
    from ir_builder import LocalDecl, Assignment, Number, String, Boolean, BinOp, UnaryOp, FunctionCall, Name
    if isinstance(stmt, LocalDecl):
        for i, name in enumerate(stmt.names):
            version = var_versions.get(name.name, 0) + 1
            var_versions[name.name] = version
            ssa_var = SSAVar(name.name, version)
            if i < len(stmt.values):
                val = stmt.values[i]
                if isinstance(val, Number):
                    output.append(SSAInstruction('load_const', ssa_var, SSANumber(val.value)))
                elif isinstance(val, String):
                    output.append(SSAInstruction('load_const', ssa_var, SSAString(val.value)))
    elif isinstance(stmt, Assignment):
        for target in stmt.targets:
            if isinstance(target, Name):
                version = var_versions.get(target.name, 0) + 1
                var_versions[target.name] = version
                if stmt.values:
                    val = stmt.values[0]
                    ssa_val = _convert_expr_to_ssa(val, var_versions, output)
                    output.append(SSAInstruction('assign', SSAVar(target.name, version), ssa_val))

def _convert_expr_to_ssa(expr, var_versions, output):
    from ir_builder import Number, String, Boolean, BinOp, UnaryOp, Name
    if isinstance(expr, Number):
        return SSANumber(expr.value)
    if isinstance(expr, String):
        return SSAString(expr.value)
    if isinstance(expr, Name):
        version = var_versions.get(expr.name, 0)
        return SSAOperand(SSAVar(expr.name, version))
    if isinstance(expr, BinOp):
        left = _convert_expr_to_ssa(expr.left, var_versions, output)
        right = _convert_expr_to_ssa(expr.right, var_versions, output)
        tmp = SSAVar('tmp', len(output))
        output.append(SSAInstruction(expr.op, tmp, left, right))
        return SSAOperand(tmp)
    return None
