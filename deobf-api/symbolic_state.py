from expr import Var, Const, BinOp

class SymState:
    def __init__(self):
        self.env = {}
        self.path = Const(True)

    def read(self, v):
        return self.env.get(v, Var(v))

    def write(self, v, val):
        self.env[v] = val

    def copy(self):
        s = SymState()
        s.env = dict(self.env)
        s.path = self.path
        return s
