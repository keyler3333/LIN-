from ir_builder import *

class SSAVar:
    def __init__(self, name, version=0):
        self.name = name
        self.version = version

class SSAPhi:
    def __init__(self, var, incoming):
        self.var = var
        self.incoming = incoming  # list of (block, SSAVar)

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

def _insert_phi(blocks, var_name, versions):
    for blk in blocks:
        preds = blk.predecessors
        if len(preds) > 1:
            incoming = {}
            for p in preds:
                v = versions.get((p.id, var_name), SSAVar(var_name, 0))
                incoming[p.id] = v
            phi = SSAPhi(SSAVar(var_name, max(v.version for v in incoming.values()) + 100), incoming)
            blk.phi_nodes[var_name] = phi

def convert_to_ssa(ir_node):
    blocks = build_cfg(ir_node)  # from cfg.py
    var_versions = {}
    ssa_blocks = []
    for blk in blocks:
        ssa_blk = SSABlock()
        ssa_blk.instructions = []
        ssa_blk.predecessors = [b.id for b in blk.predecessors]
        ssa_blk.successors = [b.id for b in blk.successors]
        for instr in blk.instructions:
            _convert_stmt_to_ssa(instr, var_versions, ssa_blk.instructions, blk.id)
        ssa_blocks.append(ssa_blk)
        # simple phi: if block has predecessors, insert phi for each variable assigned in multiple preds
        all_vars = set()
        for pred in blk.predecessors:
            for i in pred.instructions:
                if isinstance(i, LocalDecl):
                    for n in i.names:
                        all_vars.add(n.name)
        for v in all_vars:
            _insert_phi(ssa_blocks, v, var_versions)
    return ssa_blocks, var_versions

def _convert_stmt_to_ssa(stmt, var_versions, output, block_id):
    from ir_builder import LocalDecl, Assignment, Number, String, Boolean, BinOp, UnaryOp, FunctionCall, Name
    if isinstance(stmt, LocalDecl):
        for i, name in enumerate(stmt.names):
            version = var_versions.get((block_id, name.name), 0) + 1
            var_versions[(block_id, name.name)] = version
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
                version = var_versions.get((block_id, target.name), 0) + 1
                var_versions[(block_id, target.name)] = version
                if stmt.values:
                    val = stmt.values[0]
                    ssa_val = _convert_expr_to_ssa(val, var_versions, output, block_id)
                    output.append(SSAInstruction('assign', SSAVar(target.name, version), ssa_val))

def _convert_expr_to_ssa(expr, var_versions, output, block_id):
    from ir_builder import Number, String, Boolean, BinOp, UnaryOp, Name
    if isinstance(expr, Number):
        return SSANumber(expr.value)
    if isinstance(expr, String):
        return SSAString(expr.value)
    if isinstance(expr, Name):
        version = var_versions.get((block_id, expr.name), 0)
        return SSAOperand(SSAVar(expr.name, version))
    if isinstance(expr, BinOp):
        left = _convert_expr_to_ssa(expr.left, var_versions, output, block_id)
        right = _convert_expr_to_ssa(expr.right, var_versions, output, block_id)
        tmp = SSAVar('tmp', len(output))
        output.append(SSAInstruction(expr.op, tmp, left, right))
        return SSAOperand(tmp)
    return None
