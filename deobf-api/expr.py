class Expr:
    pass

class Const(Expr):
    def __init__(self, value):
        self.value = value

class Var(Expr):
    def __init__(self, name):
        self.name = name

class BinOp(Expr):
    def __init__(self, left, op, right):
        self.left = left
        self.op = op
        self.right = right

class Not(Expr):
    def __init__(self, value):
        self.value = value

class And(Expr):
    def __init__(self, left, right):
        self.left = left
        self.right = right
