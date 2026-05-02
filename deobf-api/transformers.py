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
        prev = None
        while prev != code:
            prev = code
            code = self._PAT.sub(self._fold, code)
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
    _PAT = re.compile(r'\b(_0x[0-9a-fA-F]+)\b')

    def transform(self, code):
        mapping = {}
        counter = [0]

        def replace(m):
            h = m.group(1)
            if h not in mapping:
                counter[0] += 1
                mapping[h] = f'var{counter[0]}'
            return mapping[h]

        return self._PAT.sub(replace, code)


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
        sz = self.int_size
        data = self.bc[self.pos[0]:self.pos[0] + sz]
        self.pos[0] += sz
        return int.from_bytes(data, 'little' if self.little_endian else 'big')

    def _sizet(self):
        sz = self.sizet_size
        data = self.bc[self.pos[0]:self.pos[0] + sz]
        self.pos[0] += sz
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
        order = 'little' if self.little_endian else 'big'
        v = int.from_bytes(data, order)
        op  = v & 0x3F
        a   = (v >> 6)  & 0xFF
        c   = (v >> 14) & 0x1FF
        b   = (v >> 23) & 0x1FF
        bx  = (v >> 14) & 0x3FFFF
        sbx = bx - 131071
        return {'op': op, 'a': a, 'b': b, 'c': c, 'bx': bx, 'sbx': sbx}

    def _parse_header(self):
        assert self.bc[:4] == b'\x1bLua'
        assert self.bc[4] == 0x51
        self.pos[0] = 5
        self._byte()
        self.little_endian = self._byte() == 1
        self.int_size   = self._byte()
        self.sizet_size = self._byte()
        self._byte()
        self._byte()
        self._byte()

    def parse_function(self):
        func = {
            'source':       self._string(),
            'line_defined': self._int(),
            'last_line':    self._int(),
            'nups':         self._byte(),
            'numparams':    self._byte(),
            'is_vararg':    self._byte(),
            'maxstack':     self._byte(),
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
         0: 'MOVE',      1: 'LOADK',     2: 'LOADBOOL',  3: 'LOADNIL',
         4: 'GETUPVAL',  5: 'GETGLOBAL', 6: 'GETTABLE',  7: 'SETGLOBAL',
         8: 'SETUPVAL',  9: 'SETTABLE', 10: 'NEWTABLE',  11: 'SELF',
        12: 'ADD',      13: 'SUB',      14: 'MUL',       15: 'DIV',
        16: 'MOD',      17: 'POW',      18: 'UNM',       19: 'NOT',
        20: 'LEN',      21: 'CONCAT',   22: 'JMP',       23: 'EQ',
        24: 'LT',       25: 'LE',       26: 'TEST',      27: 'TESTSET',
        28: 'CALL',     29: 'TAILCALL', 30: 'RETURN',    31: 'FORLOOP',
        32: 'FORPREP',  33: 'TFORLOOP', 34: 'SETLIST',   35: 'CLOSE',
        36: 'CLOSURE',  37: 'VARARG',
    }

    BINOP_SYM = {12: '+', 13: '-', 14: '*', 15: '/', 16: '%', 17: '^'}
    UNOP_SYM  = {18: '-', 19: 'not ', 20: '#'}

    def __init__(self, func):
        self.root   = func
        self.lines  = []
        self.indent = 0
        self._tmp   = [0]

    def decompile(self):
        self._decompile_func(self.root, name='__main__', is_main=True)
        return '\n'.join(self.lines)

    def _emit(self, line):
        self.lines.append('    ' * self.indent + line)

    def _tmp_name(self):
        self._tmp[0] += 1
        return f't{self._tmp[0]}'

    @staticmethod
    def _fmt_const(c):
        if c is None:           return 'nil'
        if isinstance(c, bool): return 'true' if c else 'false'
        if isinstance(c, str):  return repr(c)
        if isinstance(c, float):
            if c == int(c) and abs(c) < 1e15:
                return str(int(c))
            return repr(c)
        return str(c)

    @staticmethod
    def _is_ident(s):
        return bool(re.match(r'^[A-Za-z_]\w*$', s))

    def _rk(self, v, consts, regs):
        if v & 0x100:
            idx = v & 0xFF
            return self._fmt_const(consts[idx] if idx < len(consts) else None)
        return regs.get(v, f'r{v}')

    def _table_get(self, obj, key):
        if (key.startswith('"') or key.startswith("'")) and self._is_ident(key[1:-1]):
            return f'{obj}.{key[1:-1]}'
        return f'{obj}[{key}]'

    def _table_set(self, obj, key, val):
        if (key.startswith('"') or key.startswith("'")) and self._is_ident(key[1:-1]):
            return f'{obj}.{key[1:-1]} = {val}'
        return f'{obj}[{key}] = {val}'

    def _decompile_func(self, func, name='f', is_main=False):
        code     = func['code']
        consts   = func['constants']
        protos   = func['protos']
        upvnames = func.get('upvalue_names') or []

        params = [f'p{i}' for i in range(func['numparams'])]
        if func['is_vararg']:
            params.append('...')

        if not is_main:
            self._emit(f'local function {name}({", ".join(params)})')
            self.indent += 1

        regs = {}

        def R(r):
            return regs.get(r, f'r{r}')

        def RK(v):
            return self._rk(v, consts, regs)

        i = 0
        while i < len(code):
            ins = code[i]
            op, a, b, c, bx, sbx = (
                ins['op'], ins['a'], ins['b'], ins['c'], ins['bx'], ins['sbx']
            )

            if op == 0:
                regs[a] = R(b)
            elif op == 1:
                regs[a] = self._fmt_const(consts[bx] if bx < len(consts) else None)
            elif op == 2:
                regs[a] = 'true' if b else 'false'
                if c:
                    i += 1
            elif op == 3:
                for r in range(a, b + 1):
                    regs[r] = 'nil'
            elif op == 4:
                upn = upvnames[b] if b < len(upvnames) else f'upv{b}'
                regs[a] = upn or f'upv{b}'
            elif op == 5:
                regs[a] = self._fmt_const(consts[bx] if bx < len(consts) else None)
            elif op == 6:
                regs[a] = self._table_get(R(b), RK(c))
            elif op == 7:
                gname = self._fmt_const(consts[bx] if bx < len(consts) else None)
                if gname.startswith('"') or gname.startswith("'"):
                    gname = gname[1:-1]
                self._emit(f'{gname} = {R(a)}')
            elif op == 8:
                upn = upvnames[b] if b < len(upvnames) else f'upv{b}'
                self._emit(f'{upn} = {R(a)}')
            elif op == 9:
                self._emit(self._table_set(R(a), RK(b), RK(c)))
            elif op == 10:
                regs[a] = '{}'
                self._emit(f'local r{a} = {{}}')
            elif op == 11:
                key = RK(c)
                obj = R(b)
                if (key.startswith('"') or key.startswith("'")) and self._is_ident(key[1:-1]):
                    regs[a] = f'{obj}:{key[1:-1]}'
                else:
                    regs[a] = f'{obj}[{key}]'
                regs[a + 1] = obj
            elif op in self.BINOP_SYM:
                regs[a] = f'({RK(b)} {self.BINOP_SYM[op]} {RK(c)})'
            elif op in self.UNOP_SYM:
                regs[a] = f'({self.UNOP_SYM[op]}{R(b)})'
            elif op == 21:
                regs[a] = ' .. '.join(R(r) for r in range(b, c + 1))
            elif op == 22:
                self._emit(f'-- jmp -> pc {i + 1 + sbx}')
            elif op == 23:
                self._emit(f'if {RK(b)} {"==" if a == 0 else "~="} {RK(c)} then')
                self.indent += 1
            elif op == 24:
                self._emit(f'if {RK(b)} {"<" if a == 0 else ">="} {RK(c)} then')
                self.indent += 1
            elif op == 25:
                self._emit(f'if {RK(b)} {"<=" if a == 0 else ">"} {RK(c)} then')
                self.indent += 1
            elif op == 26:
                self._emit(f'if {"not " if c == 0 else ""}{R(a)} then')
                self.indent += 1
            elif op == 27:
                regs[a] = R(b)
                self._emit(f'if {"not " if c == 0 else ""}{R(b)} then')
                self.indent += 1
            elif op == 28:
                fn = R(a)
                args = '...' if b == 0 else ('' if b == 1 else ', '.join(R(a + k) for k in range(1, b)))
                call = f'{fn}({args})'
                if c == 0:
                    regs[a] = call
                elif c == 1:
                    self._emit(call)
                elif c == 2:
                    t = self._tmp_name()
                    self._emit(f'local {t} = {call}')
                    regs[a] = t
                else:
                    rets = [self._tmp_name() for _ in range(c - 1)]
                    self._emit(f'local {", ".join(rets)} = {call}')
                    for k, t in enumerate(rets):
                        regs[a + k] = t
            elif op == 29:
                args = '' if b == 1 else ', '.join(R(a + k) for k in range(1, b))
                self._emit(f'return {R(a)}({args})')
            elif op == 30:
                if b == 1:
                    self._emit('return')
                elif b == 0:
                    self._emit(f'return {R(a)}')
                else:
                    self._emit(f'return {", ".join(R(a + k) for k in range(b - 1))}')
            elif op == 31:
                self.indent = max(0, self.indent - 1)
                self._emit('end')
            elif op == 32:
                loopv = f'i_{a}'
                regs[a + 3] = loopv
                self._emit(f'for {loopv} = {R(a)}, {R(a+1)}, {R(a+2)} do')
                self.indent += 1
            elif op == 33:
                vs = [self._tmp_name() for _ in range(c)]
                for k, v in enumerate(vs):
                    regs[a + 3 + k] = v
                self._emit(f'for {", ".join(vs)} in {R(a)} do')
                self.indent += 1
            elif op == 34:
                obj  = R(a)
                base = (c - 1) * 50
                cnt  = b if b != 0 else (func['maxstack'] - a - 1)
                for k in range(1, cnt + 1):
                    self._emit(f'{obj}[{base + k}] = {R(a + k)}')
            elif op == 35:
                pass
            elif op == 36:
                pname = f'func_{bx}'
                if bx < len(protos):
                    saved = self.indent
                    self._decompile_func(protos[bx], name=pname, is_main=False)
                    self.indent = saved
                regs[a] = pname
            elif op == 37:
                if b == 0:
                    regs[a] = '...'
                else:
                    vs = [self._tmp_name() for _ in range(b - 1)]
                    self._emit(f'local {", ".join(vs)} = ...')
                    for k, v in enumerate(vs):
                        regs[a + k] = v
            else:
                self._emit(f'-- {self.OPCODES.get(op, f"OP_{op}")} A={a} B={b} C={c}')

            i += 1

        if not is_main:
            self.indent -= 1
            self._emit('end')


class WeAreDevsLifter(Transformer):
    def transform(self, code):
        result = self._try_static_lift(code)
        return result if result else code

    def _try_static_lift(self, source):
        char_map = self._find_char_map(source)
        if not char_map or len(char_map) < 40:
            return None

        data_strings = self._find_data_table(source)
        if not data_strings:
            return None

        shuffle_pairs = self._find_shuffle_pairs(source)
        if shuffle_pairs:
            data_strings = self._unshuffle(data_strings, shuffle_pairs)

        payload = bytearray()
        for s in data_strings:
            chunk = self._decode_custom_b64(s, char_map)
            if chunk:
                payload.extend(chunk)

        data = bytes(payload)
        if len(data) >= 12 and data[:4] == b'\x1bLua' and data[4] == 0x51:
            return self._decompile_bytecode(data)
        return None

    def _find_char_map(self, source):
        best = {}
        for m in re.finditer(r'\{([^{}]{300,})\}', source, re.DOTALL):
            body = m.group(1)
            pairs = re.findall(r'\["(.)"\]\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', body)
            if len(pairs) < 40:
                continue
            cmap = {}
            for key, expr in pairs:
                try:
                    cmap[key] = eval(expr.replace(' ', '')) & 0x3F
                except Exception:
                    pass
            if len(cmap) > len(best):
                best = cmap
        return best

    def _find_data_table(self, source):
        best = []
        for m in re.finditer(
            r'\{((?:\s*"(?:[^"\\]|\\.)*"\s*,?\s*)+)\}',
            source, re.DOTALL
        ):
            entries = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
            if len(entries) > len(best):
                best = entries
        return best if len(best) >= 6 else None

    def _find_shuffle_pairs(self, source):
        pairs = []
        for a_s, b_s in re.findall(
            r'\{(-?\d+(?:\s*[+\-]\s*\d+)*)\s*,\s*(-?\d+(?:\s*[+\-]\s*\d+)*)\}',
            source
        ):
            try:
                a = eval(a_s.replace(' ', ''))
                b = eval(b_s.replace(' ', ''))
                if a > 0 and b > 0:
                    pairs.append((a, b))
            except Exception:
                pass
        return pairs

    def _unshuffle(self, strings, pairs):
        res = list(strings)
        for a, b in reversed(pairs):
            lo, hi = a - 1, b - 1
            if 0 <= lo < len(res) and 0 <= hi < len(res) and lo < hi:
                res[lo:hi + 1] = res[lo:hi + 1][::-1]
        return res

    def _decode_custom_b64(self, s, char_map):
        buf   = bytearray()
        acc   = 0
        count = 0
        for ch in s:
            if ch == '=':
                if count == 3:
                    buf.append((acc >> 16) & 0xFF)
                    buf.append((acc >> 8)  & 0xFF)
                elif count == 2:
                    buf.append((acc >> 16) & 0xFF)
                break
            val = char_map.get(ch)
            if val is None:
                continue
            acc = (acc << 6) | val
            count += 1
            if count == 4:
                buf.extend([(acc >> 16) & 0xFF, (acc >> 8) & 0xFF, acc & 0xFF])
                acc = count = 0
        return bytes(buf) if buf else None

    def _decompile_bytecode(self, bc):
        try:
            parser = Lua51Parser(bc)
            func   = parser.parse_function()
            return Lua51Decompiler(func).decompile()
        except Exception as exc:
            return f'-- decompilation failed: {exc}\n-- length: {len(bc)}\n-- header: {bc[:16].hex()}\n'
