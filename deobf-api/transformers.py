import re
import struct


class Transformer:
    def transform(self, code):
        raise NotImplementedError


class EscapeSequenceTransformer(Transformer):
    def transform(self, code):
        code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), code)
        code = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)
        return code


class MathTransformer(Transformer):
    _PAT = re.compile(r'\((-?\d+)\s*([\+\-\*\/\^])\s*(-?\d+)\)')

    def transform(self, code):
        for _ in range(20):
            new = self._PAT.sub(self._fold, code)
            if new == code:
                break
            code = new
        return code

    @staticmethod
    def _fold(m):
        try:
            a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
            if op == '+': return str(a + b)
            if op == '-': return str(a - b)
            if op == '*': return str(a * b)
            if op == '/' and b != 0: return str(a // b)
            if op == '^': return str(int(a ** b))
        except Exception:
            pass
        return m.group(0)


class HexNameRenamer(Transformer):
    def transform(self, code):
        mapping, ctr = {}, [0]

        def rep(m):
            h = m.group(0)
            if h not in mapping:
                ctr[0] += 1
                mapping[h] = f'var{ctr[0]}'
            return mapping[h]

        return re.sub(r'_0x[0-9a-fA-F]+', rep, code)


class Lua51Parser:
    def __init__(self, bc):
        self.bc = bc
        self.pos = [0]
        self._parse_header()

    def _byte(self):
        v = self.bc[self.pos[0]]
        self.pos[0] += 1
        return v

    def _int(self):
        data = self.bc[self.pos[0]:self.pos[0] + self.int_size]
        self.pos[0] += self.int_size
        return int.from_bytes(data, 'little' if self.little_endian else 'big')

    def _sizet(self):
        data = self.bc[self.pos[0]:self.pos[0] + self.sizet_size]
        self.pos[0] += self.sizet_size
        return int.from_bytes(data, 'little' if self.little_endian else 'big')

    def _double(self):
        data = self.bc[self.pos[0]:self.pos[0] + 8]
        self.pos[0] += 8
        fmt = '<d' if self.little_endian else '>d'
        return struct.unpack(fmt, data)[0]

    def _string(self):
        size = self._sizet()
        if size == 0:
            return None
        s = self.bc[self.pos[0]:self.pos[0] + size - 1].decode('latin-1', errors='replace')
        self.pos[0] += size
        return s

    def _instruction(self):
        data = self.bc[self.pos[0]:self.pos[0] + 4]
        self.pos[0] += 4
        v = int.from_bytes(data, 'little' if self.little_endian else 'big')
        op = v & 0x3F
        a = (v >> 6) & 0xFF
        c = (v >> 14) & 0x1FF
        b = (v >> 23) & 0x1FF
        bx = (v >> 14) & 0x3FFFF
        sbx = bx - 131071
        return {'op': op, 'a': a, 'b': b, 'c': c, 'bx': bx, 'sbx': sbx}

    def _parse_header(self):
        assert self.bc[:4] == b'\x1bLua'
        assert self.bc[4] == 0x51
        self.pos[0] = 5
        self._byte()
        self.little_endian = self._byte() == 1
        self.int_size = self._byte()
        self.sizet_size = self._byte()
        self._byte()
        self._byte()
        self._byte()

    def parse_function(self):
        func = {
            'source': self._string(),
            'line_defined': self._int(),
            'last_line': self._int(),
            'nups': self._byte(),
            'numparams': self._byte(),
            'is_vararg': self._byte(),
            'maxstack': self._byte(),
        }
        n = self._int()
        func['code'] = [self._instruction() for _ in range(n)]
        n = self._int()
        consts = []
        for _ in range(n):
            t = self._byte()
            if t == 0:
                consts.append(None)
            elif t == 1:
                consts.append(bool(self._byte()))
            elif t == 3:
                consts.append(self._double())
            elif t == 4:
                consts.append(self._string())
            else:
                consts.append(None)
        func['constants'] = consts
        n = self._int()
        func['protos'] = [self.parse_function() for _ in range(n)]
        n = self._int()
        self.pos[0] += n * self.int_size
        n = self._int()
        for _ in range(n):
            self._string()
            self._int()
            self._int()
        n = self._int()
        func['upvalue_names'] = [self._string() for _ in range(n)]
        return func


class Lua51Decompiler:
    OPCODES = {
        0: 'MOVE', 1: 'LOADK', 2: 'LOADBOOL', 3: 'LOADNIL',
        4: 'GETUPVAL', 5: 'GETGLOBAL', 6: 'GETTABLE', 7: 'SETGLOBAL',
        8: 'SETUPVAL', 9: 'SETTABLE', 10: 'NEWTABLE', 11: 'SELF',
        12: 'ADD', 13: 'SUB', 14: 'MUL', 15: 'DIV', 16: 'MOD', 17: 'POW',
        18: 'UNM', 19: 'NOT', 20: 'LEN', 21: 'CONCAT', 22: 'JMP', 23: 'EQ',
        24: 'LT', 25: 'LE', 26: 'TEST', 27: 'TESTSET', 28: 'CALL', 29: 'TAILCALL',
        30: 'RETURN', 31: 'FORLOOP', 32: 'FORPREP', 33: 'TFORLOOP', 34: 'SETLIST',
        35: 'CLOSE', 36: 'CLOSURE', 37: 'VARARG',
    }
    BINOP = {12: '+', 13: '-', 14: '*', 15: '/', 16: '%', 17: '^'}
    UNOP = {18: '-', 19: 'not ', 20: '#'}

    def __init__(self, func):
        self.root = func
        self.lines = []
        self.indent = 0
        self._tmp = [0]

    def decompile(self):
        self._func(self.root, '__main__', True)
        return '\n'.join(self.lines)

    def _emit(self, s):
        self.lines.append('    ' * self.indent + s)

    def _t(self):
        self._tmp[0] += 1
        return f't{self._tmp[0]}'

    @staticmethod
    def _fc(c):
        if c is None:
            return 'nil'
        if isinstance(c, bool):
            return 'true' if c else 'false'
        if isinstance(c, str):
            return repr(c)
        if isinstance(c, float):
            return str(int(c)) if c == int(c) and abs(c) < 1e15 else repr(c)
        return str(c)

    @staticmethod
    def _ident(s):
        return bool(re.match(r'^[A-Za-z_]\w*$', s))

    def _rk(self, v, consts, regs):
        if v & 0x100:
            idx = v & 0xFF
            return self._fc(consts[idx] if idx < len(consts) else None)
        return regs.get(v, f'r{v}')

    def _tget(self, obj, key):
        if (key.startswith('"') or key.startswith("'")) and self._ident(key[1:-1]):
            return f'{obj}.{key[1:-1]}'
        return f'{obj}[{key}]'

    def _tset(self
