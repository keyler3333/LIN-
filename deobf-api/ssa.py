from expr import Var

class SSAVar:
    def __init__(self, name, version):
        self.name = name
        self.version = version

    def __repr__(self):
        return f"{self.name}_{self.version}"

class SSAConst:
    def __init__(self, value):
        self.value = value

class SSAOp:
    def __init__(self, op, dest, a, b=None):
        self.op = op
        self.dest = dest
        self.a = a
        self.b = b

class SSAPhi:
    def __init__(self, dest, incoming):
        self.dest = dest
        self.incoming = incoming

class SSAState:
    def __init__(self):
        self.versions = {}

    def new(self, name):
        v = self.versions.get(name, 0) + 1
        self.versions[name] = v
        return SSAVar(name, v)

def to_ssa(blocks):
    state = SSAState()
    out = []
    for b in blocks:
        for i in b.instructions:
            if hasattr(i, "target") and hasattr(i, "value"):
                dest = state.new(i.target)
                out.append(SSAOp("mov", dest, i.value))
            elif hasattr(i, "op"):
                a = i.left
                b_ = i.right
                dest = state.new("tmp")
                out.append(SSAOp(i.op, dest, a, b_))
    return out, state
