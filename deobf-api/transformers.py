import re


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
