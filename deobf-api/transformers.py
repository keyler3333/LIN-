import re

class Transformer:
    def transform(self, code):
        raise NotImplementedError

class MathTransformer(Transformer):
    def transform(self, code):
        def safe_calc(match):
            try:
                a_str, op, b_str = match.groups()
                a, b = int(a_str), int(b_str)
                if op == '+': return str(a + b)
                if op == '-': return str(a - b)
                if op == '*': return str(a * b)
                if op == '/' and b != 0: return str(a // b)
                if op == '^': return str(a ** b)
            except:
                pass
            return match.group(0)
        code = re.sub(r'\((-?\d+)\s*([\+\-\*\/\^])\s*(-?\d+)\)', safe_calc, code)
        return code

class CipherMapTransformer(Transformer):
    def transform(self, code):
        cipher_map = self._extract_mapping(code)
        if not cipher_map:
            return code

        table_match = re.search(r'local\s+[a-zA-Z_]\w*\s*=\s*\{(.*?)\}', code, re.DOTALL)
        if not table_match:
            return code

        encoded_strings = re.findall(r'"((?:\\.|[^"\\])*)"', table_match.group(1))
        shuffle_pairs = self._extract_shuffles(code)
        if shuffle_pairs:
            encoded_strings = self._unshuffle(encoded_strings, shuffle_pairs)

        for s in encoded_strings:
            decoded = self._decode(s, cipher_map)
            if decoded and any(c.isprintable() for c in decoded):
                code = code.replace(f'"{s}"', f'"{decoded}"')
        return code

    def _extract_mapping(self, code):
        for match in re.finditer(r'local\s+\w+\s*=\s*\{(.*?)\}', code, re.DOTALL):
            content = match.group(1)
            if '=' not in content or content.count('=') < 10:
                continue
            mapping = {}
            pairs = re.findall(r'\[?"?([^"\]]+)"?\]?\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', content)
            for k, expr in pairs:
                try:
                    val = eval(expr.replace(' ', ''), {"__builtins__": None}, {})
                    mapping[k.strip()] = val & 0x3F
                except:
                    continue
            if len(mapping) > 30:
                return mapping
        return None

    def _extract_shuffles(self, code):
        pairs = []
        for a_expr, b_expr in re.findall(r'\{(-?\d+(?:\s*[+\-]\s*-?\d+)*)\s*,\s*(-?\d+(?:\s*[+\-]\s*-?\d+)*)\}', code):
            try:
                a = eval(a_expr.replace(' ', ''), {"__builtins__": None}, {})
                b = eval(b_expr.replace(' ', ''), {"__builtins__": None}, {})
                pairs.append([a, b])
            except:
                continue
        return pairs

    def _unshuffle(self, strings, pairs):
        res = list(strings)
        for a, b in reversed(pairs):
            a_idx, b_idx = a - 1, b - 1
            if a_idx < 0 or b_idx >= len(res):
                continue
            while a_idx < b_idx:
                res[a_idx], res[b_idx] = res[b_idx], res[a_idx]
                a_idx += 1
                b_idx -= 1
        return res

    def _decode(self, s, cmap):
        buf = bytearray()
        acc = count = 0
        for ch in s:
            if ch == '=':
                if count == 3:
                    buf.extend([(acc >> 16) & 0xFF, (acc >> 8) & 0xFF])
                elif count == 2:
                    buf.append((acc >> 16) & 0xFF)
                break
            val = cmap.get(ch)
            if val is None:
                continue
            acc = (acc << 6) | val
            count += 1
            if count == 4:
                buf.extend([(acc >> 16) & 0xFF, (acc >> 8) & 0xFF, acc & 0xFF])
                acc = count = 0
        try:
            return buf.decode('utf-8', errors='ignore')
        except:
            return buf.decode('latin-1', errors='ignore')

class EscapeSequenceTransformer(Transformer):
    def transform(self, code):
        code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), code)
        code = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)
        return code

class HexNameRenamer(Transformer):
    def __init__(self):
        self.mapping = {}
        self.counter = 0

    def transform(self, code):
        self.mapping = {}
        self.counter = 0
        def replace_hex(match):
            hex_name = match.group(0)
            if hex_name not in self.mapping:
                self.counter += 1
                self.mapping[hex_name] = f"var{self.counter}"
            return self.mapping[hex_name]
        code = re.sub(r'(?<![^\s\[\(\)\.\=\+\-\*\/\^\%\#\<\>\~\&\|\,])(_0x[0-9a-fA-F]+)(?=[^\w]|$)', replace_hex, code)
        return code
