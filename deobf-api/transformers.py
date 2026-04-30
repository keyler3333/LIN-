import re
import base64
import struct

class Transformer:
    def transform(self, code):
        raise NotImplementedError

class MathTransformer(Transformer):
    def transform(self, code):
        def safe_calc(match):
            try:
                a, op, b = match.groups()
                a, b = int(a), int(b)
                if op == '+': return str(a + b)
                if op == '-': return str(a - b)
                if op == '*': return str(a * b)
                if op == '/': return str(a // b)
            except:
                return match.group(0)
            return match.group(0)
        return re.sub(r'\((\d+)\s*([\+\-\*\/])\s*(\d+)\)', safe_calc, code)

class ConstantTableTransformer(Transformer):
    def transform(self, code):
        table_match = re.search(r'local\s+\w+\s*=\s*\{(\s*"[A-Za-z0-9+/=]+",?\s*)+\}', code)
        if not table_match:
            return code
        strings = re.findall(r'"([A-Za-z0-9+/=]+)"', table_match.group(0))
        decoded_map = {}
        for s in strings:
            if len(s) > 4:
                try:
                    padded = s + '=' * ((4 - len(s) % 4) % 4)
                    dec = base64.b64decode(padded).decode('latin-1', errors='replace')
                    if any(c.isprintable() for c in dec):
                        decoded_map[s] = dec
                except:
                    continue
        for enc, dec in decoded_map.items():
            code = code.replace(f'"{enc}"', f'"{enc}" --[[ "{dec}" ]]')
        return code

class StringTransformer(Transformer):
    def __init__(self):
        self.cipher_map = None

    def _extract_cipher_map(self, code):
        mapping_pattern = r'local\s+(\w+)\s*=\s*\{(.*?)\}'
        for match in re.finditer(mapping_pattern, code, re.DOTALL):
            mapping_content = match.group(2)
            if '=' not in mapping_content or mapping_content.count('=') <= 10:
                continue
            mapping_dict = {}
            pairs = re.findall(r'\["([^"]+)"\]\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', mapping_content)
            if not pairs:
                pairs = re.findall(r'"([^"]+)"\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', mapping_content)
            if not pairs:
                pairs = re.findall(r'\[?"?([^"\]]+)"?\]?\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', mapping_content)
            for key, expr in pairs:
                try:
                    val = int(eval(expr.replace(' ', '')))
                    mapping_dict[key.strip()] = val & 0x3F
                except:
                    continue
            if len(mapping_dict) > 30:
                self.cipher_map = mapping_dict
                return

    def _decode_string(self, s):
        byte_buffer = bytearray()
        accumulator = 0
        count = 0
        for ch in s:
            if ch == '=':
                if count == 3:
                    byte_buffer.append((accumulator >> 16) & 0xFF)
                    byte_buffer.append((accumulator >> 8) & 0xFF)
                elif count == 2:
                    byte_buffer.append((accumulator >> 16) & 0xFF)
                break
            val = self.cipher_map.get(ch)
            if val is None:
                continue
            accumulator = (accumulator << 6) | val
            count += 1
            if count == 4:
                byte_buffer.extend([
                    (accumulator >> 16) & 0xFF,
                    (accumulator >> 8) & 0xFF,
                    accumulator & 0xFF,
                ])
                accumulator = 0
                count = 0
        return bytes(byte_buffer)

    def transform(self, code):
        self._extract_cipher_map(code)
        if not self.cipher_map:
            return code

        table_match = re.search(r'local\s+N\s*=\s*\{(.*?)\}', code, re.DOTALL)
        if not table_match:
            table_match = re.search(r'local\s+\w+\s*=\s*\{("[^"]*".*?)\}', code, re.DOTALL)
        if not table_match:
            return code
        raw_table = table_match.group(1)
        encoded_strings = re.findall(r'"((?:\\.|[^"\\])*)"', raw_table)

        shuffle_pairs = re.findall(r'\{(-?\d+(?:\s*[+\-]\s*-?\d+)*)\s*,\s*(-?\d+(?:\s*[+\-]\s*-?\d+)*)\}', code)
        if shuffle_pairs:
            pairs = []
            for a_expr, b_expr in shuffle_pairs:
                try:
                    a = int(eval(a_expr.replace(' ', '')))
                    b = int(eval(b_expr.replace(' ', '')))
                    pairs.append([a, b])
                except:
                    continue
            if pairs:
                enc_list = list(encoded_strings)
                for a, b in reversed(pairs):
                    a_idx = a - 1
                    b_idx = b - 1
                    while a_idx < b_idx:
                        enc_list[a_idx], enc_list[b_idx] = enc_list[b_idx], enc_list[a_idx]
                        a_idx += 1
                        b_idx -= 1
                encoded_strings = enc_list

        decoded_texts = []
        for s in encoded_strings:
            raw = self._decode_string(s)
            try:
                text = raw.decode('utf-8')
            except:
                text = raw.decode('latin-1', errors='replace')
            decoded_texts.append(text)

        for text in decoded_texts:
            if len(text) > 200 and ('function' in text or 'local' in text):
                return text

        return code

class JunkTransformer(Transformer):
    def transform(self, code):
        return code
