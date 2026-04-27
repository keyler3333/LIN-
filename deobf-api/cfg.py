from ir_builder import *

class BasicBlock:
    def __init__(self, id):
        self.id = id
        self.instructions = []
        self.successors = []
        self.predecessors = []
        self.true_branch = None
        self.false_branch = None
        self.dominators = set()

def _flatten(ir_node):
    if isinstance(ir_node, Block):
        stmts = []
        for s in ir_node.statements:
            stmts += _flatten(s)
        return stmts
    else:
        return [ir_node]

def build_cfg(ir_node):
    stmts = _flatten(ir_node)
    blocks = []
    current = BasicBlock(0)
    blocks.append(current)
    label_to_block = {}
    i = 0
    while i < len(stmts):
        stmt = stmts[i]
        if isinstance(stmt, If):
            current.successors = []
            true_block = BasicBlock(len(blocks))
            blocks.append(true_block)
            current.true_branch = true_block
            true_block.predecessors.append(current)
            true_block.instructions = _flatten(stmt.body.statements) if isinstance(stmt.body, Block) else [stmt.body]
            if stmt.orelse:
                false_block = BasicBlock(len(blocks))
                blocks.append(false_block)
                current.false_branch = false_block
                false_block.predecessors.append(current)
                false_block.instructions = _flatten(stmt.orelse.statements) if isinstance(stmt.orelse, Block) else [stmt.orelse]
            current = BasicBlock(len(blocks))
            blocks.append(current)
            i += 1
            continue
        elif isinstance(stmt, While):
            body_block = BasicBlock(len(blocks))
            blocks.append(body_block)
            current.successors.append(body_block)
            body_block.predecessors.append(current)
            body_block.instructions = _flatten(stmt.body.statements) if isinstance(stmt.body, Block) else [stmt.body]
            after = BasicBlock(len(blocks))
            blocks.append(after)
            body_block.successors.append(after)
            body_block.successors.append(current)  # back edge
            current = after
            i += 1
            continue
        else:
            current.instructions.append(stmt)
        i += 1
    return blocks
