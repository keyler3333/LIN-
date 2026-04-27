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
    # we need to create a list of basic blocks from the IR; for simplicity we treat each statement as a block
    blocks = []
    current_block = SSABlock()
    for stmt in (ir_block.statements if hasattr(ir_block, 'statements') else []):
        if isinstance(stmt, (If, While, Repeat)):
            # finish current block
            if current_block.instructions:
                blocks.append(current_block)
                current_block = SSABlock()
            # process structured control flow later
            blocks.append(stmt)  # temporarily keep as placeholder
        else:
            current_block.instructions.append(stmt)
    if current_block.instructions:
        blocks.append(current_block)
    for blk in blocks:
        if isinstance(blk, SSABlock):
            for instr in blk.instructions:
                _convert_stmt_to_ssa(instr, var_versions, ssa_instructions)
        else:
            ssa_instructions.append(blk)
    return ssa_instructions, var_versions
