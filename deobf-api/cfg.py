from ssa import SSAInstruction

class BasicBlock:
    def __init__(self, id):
        self.id = id
        self.instructions = []
        self.successors = []
        self.predecessors = []
        self.dominators = set()

def build_cfg(ssa_instructions):
    blocks = []
    current = BasicBlock(len(blocks))
    for instr in ssa_instructions:
        current.instructions.append(instr)
        if instr.opcode in ('jmp', 'if', 'call'):
            blocks.append(current)
            current = BasicBlock(len(blocks))
    if current.instructions:
        blocks.append(current)
    for i in range(len(blocks)-1):
        last = blocks[i].instructions[-1]
        if last.opcode != 'jmp':
            blocks[i].successors.append(blocks[i+1])
            blocks[i+1].predecessors.append(blocks[i])
    blocks[0].dominators = {blocks[0]}
    changed = True
    while changed:
        changed = False
        for b in blocks[1:]:
            new_dom = set.intersection(*(p.dominators for p in b.predecessors)) if b.predecessors else set()
            new_dom.add(b)
            if new_dom != b.dominators:
                b.dominators = new_dom
                changed = True
    return blocks
