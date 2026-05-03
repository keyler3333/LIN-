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


class WeAreDevsExtractor:
    def transform(self, code):
        # 1. direct loadstring capture
        match = re.search(r'loadstring\s*\((.+)\)', code)
        if match:
            inner = match.group(1)
            inner = self._strip_noise(inner)
            decoded = self._try_decode(inner)
            if decoded:
                return decoded

        # 2. fallback: giant string arrays
        strings = re.findall(r'"((?:[^"\\]|\\.){30,})"', code)
        if strings:
            joined = ''.join(strings)
            decoded = self._try_decode(joined)
            if decoded:
                return decoded

        return code

    def _strip_noise(self, s):
        s = re.sub(r'[^A-Za-z0-9+/=]', '', s)
        return s

    def _try_decode(self, s):
        try:
            pad = len(s) % 4
            if pad:
                s += "=" * (4 - pad)
            data = base64.b64decode(s)
            text = data.decode('utf-8', errors='ignore')
            if "function" in text or "local" in text:
                return text
        except Exception:
            pass
        return None


class WRDPipeline:
    def __init__(self):
        self.steps = [
            EscapeCleaner(),
            MathCleaner(),
            WeAreDevsExtractor(),
        ]

    def run(self, code):
        current = code
        for step in self.steps:
            try:
                out = step.transform(current)
                if out and out != current:
                    current = out
            except Exception:
                pass
        return current
