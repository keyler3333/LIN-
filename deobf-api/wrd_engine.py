import re
import base64


class EscapeCleaner:
    def transform(self, code):
        code = re.sub(r'\\x([0-9a-fA-F]{2})',
                      lambda m: chr(int(m.group(1), 16)), code)
        code = re.sub(r'\\(\d{1,3})',
                      lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0),
                      code)
        return code


class MathCleaner:
    def transform(self, code):
        for _ in range(5):
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


class CustomBase64Decoder:
    def __init__(self):
        self.alphabet = None

    def extract_alphabet(self, code):
        for m in re.finditer(r'local\s+\w+\s*=\s*\{([^}]+)\}', code, re.DOTALL):
            body = m.group(1)
            pairs = re.findall(r'\[?"?([^"\]]+)"?\]?\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', body)
            if len(pairs) < 40:
                continue
            mapping = {}
            for key, expr in pairs:
                try:
                    val = eval(expr.replace(' ', '')) & 0x3F
                    mapping[key.strip()] = val
                except:
                    pass
            if len(mapping) >= 40:
                self.alphabet = mapping
                return True
        return False

    def decode(self, s):
        if not self.alphabet:
            return None
        buf = bytearray()
        acc = 0
        cnt = 0
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

        payload = self._extract_loadstring_payload(code)
        if payload:
            return payload

        payload = self._extract_table_concat_payload(code)
        if payload:
            return payload

        payload = self._extract_large_string_blob(code)
        if payload:
            return payload

        return code

    def _extract_loadstring_payload(self, code):
        matches = re.findall(r'loadstring\s*\((.+?)\)', code, re.DOTALL)
        for raw in reversed(matches):
            raw = self._clean_b64(raw)
            if len(raw) < 20:
                continue
            decoded = self._try_decode(raw)
            if decoded:
                return decoded
        return None

    def _extract_table_concat_payload(self, code):
        concat_match = re.search(r'table\.concat\s*\(\s*(\w+)\s*\)', code)
        if not concat_match:
            return None
        table_name = concat_match.group(1)
        table_match = re.search(
            rf'local\s+{re.escape(table_name)}\s*=\s*\{{(.*?)\}}',
            code, re.DOTALL
        )
        if not table_match:
            return None
        body = table_match.group(1)
        strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
        if not strings:
            return None
        joined = ''.join(strings)
        joined = self._clean_b64(joined)
        decoded = self._try_decode(joined)
        if decoded:
            return decoded
        return None

    def _extract_large_string_blob(self, code):
        strings = re.findall(r'"((?:[^"\\]|\\.){30,})"', code)
        if not strings:
            return None
        joined = ''.join(strings)
        joined = self._clean_b64(joined)
        decoded = self._try_decode(joined)
        if decoded:
            return decoded
        return None

    def _clean_b64(self, s):
        s = re.sub(r'[^A-Za-z0-9+/=]', '', s)
        return s

    def _try_decode(self, s):
        if s in self.seen:
            return None
        self.seen.add(s)

        result = None
        if self.custom_b64.alphabet:
            raw = self.custom_b64.decode(s)
            if raw:
                try:
                    text = raw.decode('utf-8', errors='ignore')
                    if self._looks_valid(text):
                        result = text
                except:
                    pass

        if not result:
            try:
                pad = len(s) % 4
                if pad:
                    s += '=' * (4 - pad)
                data = base64.b64decode(s)
                text = data.decode('utf-8', errors='ignore')
                if self._looks_valid(text):
                    result = text
            except:
                pass

        return result

    def _looks_valid(self, text):
        if not text or len(text) < 15:
            return False
        keywords = ['function', 'local', 'return', 'end', 'if', 'then', 'for', 'while']
        found = sum(1 for kw in keywords if kw in text.lower())
        if found >= 2:
            return True

        lines = text.split('\n')
        if len(lines) > 3 and max(len(l) for l in lines) < 300:
            alpha = sum(1 for ch in text if ch.isalpha() or ch in ' \t\n_.,;(){}[]=')
            if (alpha / max(len(text), 1)) > 0.3:
                return True
        return False


class WRDPipeline:
    def __init__(self):
        self.steps = [
            EscapeCleaner(),
            MathCleaner(),
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
