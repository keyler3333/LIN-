import re
import base64
import hashlib


class EscapeCleaner:
    def transform(self, code):
        code = re.sub(r'\\x([0-9a-fA-F]{2})',
                      lambda m: chr(int(m.group(1), 16)), code)
        code = re.sub(r'\\(\d{1,3})',
                      lambda m: chr(int(m.group(1)))
                      if int(m.group(1)) < 256 else m.group(0),
                      code)
        return code


class MathCleaner:
    def transform(self, code):
        for _ in range(10):
            new = re.sub(r'\((\d+)\s*([\+\-\*\/])\s*(\d+)\)',
                         self._calc, code)
            if new == code:
                break
            code = new
        return code

    def _calc(self, m):
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        if op == '+': return str(a + b)
        if op == '-': return str(a - b)
        if op == '*': return str(a * b)
        if op == '/': return str(a // b if b else a)
        return m.group(0)


def _safe_eval(expr):
    expr = expr.replace(' ', '')
    return int(expr) if re.match(r'^-?\d+$', expr) else 0


class CustomBase64Decoder:
    def __init__(self):
        self.alphabet = None

    def extract_alphabet(self, code):
        for m in re.finditer(r'local\s+\w+\s*=\s*\{([^}]+)\}', code, re.DOTALL):
            body = m.group(1)

            pairs = re.findall(
                r'\[?"?([^"\]]+)"?\]?\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)',
                body
            )

            if len(pairs) >= 40:
                mapping = {}
                for key, expr in pairs:
                    mapping[key.strip()] = _safe_eval(expr) & 0x3F
                if len(mapping) >= 40:
                    self.alphabet = mapping
                    return True

            chars = re.findall(r'"([^"]*)"', body)
            if len(chars) >= 40:
                self.alphabet = {c: i for i, c in enumerate(chars)}
                return True

        return False

    def decode(self, s):
        if not self.alphabet:
            return None

        buf, acc, cnt = bytearray(), 0, 0

        for ch in s:
            if ch == '=':
                if cnt == 3:
                    buf.append((acc >> 16) & 0xFF)
                    buf.append((acc >> 8) & 0xFF)
                elif cnt == 2:
                    buf.append((acc >> 16) & 0xFF)
                break

            val = self.alphabet.get(ch)
            if val is None:
                continue

            acc = (acc << 6) | val
            cnt += 1

            if cnt == 4:
                buf.extend([(acc >> 16) & 0xFF, (acc >> 8) & 0xFF, acc & 0xFF])
                acc = 0
                cnt = 0

        return bytes(buf)


class WeAreDevsExtractor:
    def __init__(self):
        self.custom_b64 = CustomBase64Decoder()
        self.seen = set()

    def transform(self, code):
        self.custom_b64.extract_alphabet(code)

        candidates = []
        candidates += self._extract_loadstring_payload(code)
        candidates += self._extract_table_concat_payload(code)
        candidates += self._extract_large_string_blob(code)
        candidates += self._extract_all_strings(code)

        scored = []

        for c in candidates:
            score = self._score(c)
            if score > 5:
                scored.append((score, c))

        if scored:
            scored.sort(key=lambda x: x[0], reverse=True)
            return scored[0][1]

        return code

    def _extract_loadstring_payload(self, code):
        out = []
        matches = re.findall(r'loadstring\s*\(\s*(.+?)\s*\)', code, re.DOTALL)

        for raw in reversed(matches):
            raw = self._clean_b64(raw)
            if len(raw) < 20:
                continue
            decoded = self._try_decode(raw)
            if decoded:
                out.append(decoded)

        return out

    def _extract_table_concat_payload(self, code):
        out = []
        matches = re.findall(r'table\.concat\s*\(\s*([^)]+)\s*\)', code)

        for args in matches:
            parts = [p.strip() for p in args.split(',')]
            if not parts:
                continue

            table_ref = parts[0]

            if re.match(r'^[\w.\[\]"\']+$', table_ref):
                m = re.search(
                    rf'local\s+{re.escape(table_ref)}\s*=\s*\{{(.*?)\}}',
                    code,
                    re.DOTALL
                )
                if not m:
                    continue
                body = m.group(1)

            elif re.match(r'^\{(.*?)\}$', table_ref, re.DOTALL):
                body = table_ref[1:-1]

            else:
                continue

            strings = re.findall(r"""['"]((?:[^'\\]|\\.)*)['"]""", body)
            if not strings:
                continue

            joined = self._clean_b64(''.join(strings))
            decoded = self._try_decode(joined)

            if decoded:
                out.append(decoded)

        return out

    def _extract_large_string_blob(self, code):
        out = []
        strings = re.findall(r"""['"]((?:[^'\\]|\\.){30,})['"]""", code)

        if strings:
            joined = self._clean_b64(''.join(strings))
            decoded = self._try_decode(joined)
            if decoded:
                out.append(decoded)

        return out

    def _extract_all_strings(self, code):
        out = []
        strings = re.findall(r"""['"]((?:[^'\\]|\\.)*)['"]""", code)

        if strings:
            joined = self._clean_b64(''.join(strings))
            decoded = self._try_decode(joined)
            if decoded:
                out.append(decoded)

        return out

    def _clean_b64(self, s):
        if self.custom_b64.alphabet:
            return s
        return re.sub(r'[^A-Za-z0-9+/=]', '', s)

    def _try_decode(self, s):
        if not s:
            return None

        h = hashlib.md5(s.encode()).hexdigest()
        if h in self.seen:
            return None
        self.seen.add(h)

        decoded = self._decode(s)
        if decoded:
            for _ in range(3):
                nxt = self._decode(decoded)
                if not nxt or nxt == decoded:
                    break
                decoded = nxt
            return decoded

        return None

    def _decode(self, s):
        if len(set(s)) < 10:
            return None

        if self.custom_b64.alphabet:
            try:
                raw = self.custom_b64.decode(s)
                if raw:
                    txt = raw.decode('utf-8', errors='ignore')
                    if self._valid(txt):
                        return txt
            except:
                pass

        try:
            pad = len(s) % 4
            s2 = s + '=' * (4 - pad) if pad else s
            data = base64.b64decode(s2)
            txt = data.decode('utf-8', errors='ignore')
            if self._valid(txt):
                return txt
        except:
            pass

        for key in range(1, 32):
            try:
                raw = s.encode('latin-1', errors='ignore')
                txt = ''.join(chr(b ^ key) for b in raw)
                if self._valid(txt):
                    return txt
            except:
                pass

        return None

    def _valid(self, text):
        if not text or len(text) < 15:
            return False
        if text.count('\x00') > 5:
            return False

        lines = text.split('\n')
        if lines and max(len(l) for l in lines) > 500:
            return False

        kws = ['function', 'local', 'return', 'end', 'if', 'then', 'for', 'while']
        if sum(1 for k in kws if k in text.lower()) >= 2:
            return True

        if len(lines) > 3:
            alpha = sum(1 for c in text if c.isalpha() or c in ' \t\n_.,;(){}[]=')
            if alpha / max(len(text), 1) > 0.3:
                return True

        return False

    def _score(self, text):
        if not text:
            return 0

        s = 0
        t = text.lower()

        s += t.count('function') * 5
        s += t.count('local') * 4
        s += t.count('return') * 3
        s += t.count('end') * 2
        s += t.count('if') * 2

        lines = text.split('\n')
        if lines:
            ml = max(len(l) for l in lines)
            if ml < 200:
                s += 10
            elif ml < 400:
                s += 5

        alpha = sum(1 for c in text if c.isalpha() or c in ' \t\n_.,;(){}[]=')
        s += int((alpha / max(len(text), 1)) * 20)

        return s


class WRDPipeline:
    def __init__(self):
        self.steps = [
            EscapeCleaner(),
            MathCleaner()
        ]
        self.extractor = WeAreDevsExtractor()

    def run(self, code):
        current = code

        for _ in range(5):
            prev = current

            for step in self.steps:
                try:
                    out = step.transform(current)
                    if out and out != current:
                        current = out
                except:
                    pass

            extracted = self.extractor.transform(current)
            if extracted and extracted != current:
                current = extracted

            if current == prev:
                break

        return current
