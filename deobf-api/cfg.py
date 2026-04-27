from ir_builder import If, While, Block

class BlockNode:
    def __init__(self, id):
        self.id = id
        self.instructions = []
        self.true = None
        self.false = None
        self.next = []

def build_cfg(ir):
    stmts = ir.statements
    blocks = []
    current = BlockNode(0)
    blocks.append(current)
    bid = 1
    for s in stmts:
        if isinstance(s, If):
            t = BlockNode(bid); bid += 1
            f = BlockNode(bid); bid += 1
            j = BlockNode(bid); bid += 1
            current.true = t
            current.false = f
            t.next.append(j)
            f.next.append(j)
            blocks += [t, f, j]
            current = j
        elif isinstance(s, While):
            head = current
            body = BlockNode(bid); bid += 1
            exit_block = BlockNode(bid); bid += 1
            head.true = body
            head.false = exit_block
            body.next.append(head)
            head.next.append(exit_block)
            blocks += [body, exit_block]
            current = exit_block
        else:
            current.instructions.append(s)
    return blocks
