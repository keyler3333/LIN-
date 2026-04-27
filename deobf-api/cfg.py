from ir_builder import Block, If, While

class BasicBlock:
    def __init__(self, id):
        self.id = id
        self.instructions = []
        self.true_branch = None
        self.false_branch = None
        self.successors = []
        self.predecessors = []
        self.condition = None

def _flatten(node):
    if isinstance(node, Block):
        out = []
        for s in node.statements:
            out.extend(_flatten(s))
        return out
    return [node]

def build_cfg(ir):
    stmts = _flatten(ir)

    entry = BasicBlock(0)
    blocks = [entry]
    current = entry
    bid = 1

    i = 0
    while i < len(stmts):
        stmt = stmts[i]

        if isinstance(stmt, If):
            cond_block = current
            true_block = BasicBlock(bid); bid += 1
            false_block = BasicBlock(bid); bid += 1
            join_block = BasicBlock(bid); bid += 1

            blocks += [true_block, false_block, join_block]

            cond_block.condition = stmt.test
            cond_block.true_branch = true_block
            cond_block.false_branch = false_block

            cond_block.successors = [true_block, false_block]
            true_block.predecessors.append(cond_block)
            false_block.predecessors.append(cond_block)

            true_block.successors.append(join_block)
            false_block.successors.append(join_block)

            join_block.predecessors += [true_block, false_block]

            current = join_block
            i += 1
            continue

        if isinstance(stmt, While):
            head = current
            body = BasicBlock(bid); bid += 1
            exitb = BasicBlock(bid); bid += 1

            blocks += [body, exitb]

            head.condition = stmt.test
            head.true_branch = body
            head.false_branch = exitb

            head.successors = [body, exitb]
            body.successors = [head]

            body.predecessors.append(head)
            head.predecessors.append(body)

            current = exitb
            i += 1
            continue

        current.instructions.append(stmt)
        i += 1

    return blocks, entry
