import re
import base64
import struct


class Deobfuscator:
    def __init__(self):
        self.decrypted_data  = {}
        self.decryption_keys = {}

    def process_base64(self, encoded_data):
        try:
            missing = len(encoded_data) % 4
            if missing:
                encoded_data += '=' * (4 - missing)
            return base64.b64decode(encoded_data).decode('latin-1', errors='ignore')
        except Exception:
            return encoded_data

    def process_hex_data(self, hex_data):
        try:
            if hex_data.startswith('0x'):
                hex_data = hex_data[2:]
            hex_data = re.sub(r'[^0-9A-Fa-f]', '', hex_data)
            if len(hex_data) % 2 != 0:
                hex_data = '0' + hex_data
            return bytes.fromhex(hex_data).decode('latin-1', errors='ignore')
        except Exception:
            return hex_data

    def process_octal_data(self, octal_data):
        return re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1), 8)), octal_data)

    def apply_xor_cipher(self, input_data, cipher_key):
        try:
            key_bytes  = str(cipher_key).encode() if not isinstance(cipher_key, bytes) else cipher_key
            out = []
            for i, ch in enumerate(input_data):
                kv = key_bytes[i % len(key_bytes)]
                out.append(chr(ord(ch) ^ kv) if isinstance(ch, str) else chr(ch ^ kv))
            return ''.join(out)
        except Exception:
            return input_data

    def locate_data_tables(self, script_content):
        found_tables = []
        for table_match in re.finditer(r'local\s+(\w+)\s*=\s*\{(.*?)\}', script_content, re.DOTALL):
            table_id       = table_match.group(1)
            table_elements = table_match.group(2)
            element_list   = []
            pos = 0
            while pos < len(table_elements):
                ch = table_elements[pos]
                if ch in ('"', "'"):
                    quote  = ch
                    end    = pos + 1
                    while end < len(table_elements):
                        if table_elements[end] == quote and table_elements[end - 1] != '\\':
                            break
                        end += 1
                    if end < len(table_elements):
                        raw = table_elements[pos + 1:end]
                        element_list.append(self.process_string_escapes(raw))
                        pos = end + 1
                        continue
                pos += 1
            if element_list:
                found_tables.append({'name': table_id, 'elements': element_list})
        return found_tables

    def process_string_escapes(self, raw_string):
        replacements = [
            ('\\n',  '\n'),
            ('\\r',  '\r'),
            ('\\t',  '\t'),
            ('\\"',  '"'),
            ("\\'",  "'"),
            ('\\\\', '\\'),
            ('\\a',  '\a'),
            ('\\b',  '\b'),
            ('\\f',  '\f'),
            ('\\v',  '\v'),
        ]
        for pattern, replacement in replacements:
            raw_string = raw_string.replace(pattern, replacement)
        raw_string = re.sub(r'\\x([0-9a-fA-F]{2})',
                            lambda m: chr(int(m.group(1), 16)), raw_string)
        return raw_string

    def find_encryption_functions(self, script_content):
        function_patterns = [
            r'function\s+(\w+)\s*\([^)]*\)\s*local\s+.*string\.char',
            r'local\s+function\s+(\w+)\s*\([^)]*\).*bit32\.',
            r'(\w+)\s*=\s*function\s*\([^)]*\).*table\.concat',
        ]
        results = []
        for pattern in function_patterns:
            for m in re.finditer(pattern, script_content, re.DOTALL):
                fn_start = m.start()
                fn_end   = script_content.find('end', fn_start)
                if fn_end != -1:
                    results.append({
                        'name': m.group(1),
                        'body': script_content[fn_start:fn_end + 3],
                    })
        return results

    def extract_cipher_mapping(self, script_content):
        for m in re.finditer(r'local\s+(\w+)\s*=\s*\{(.*?)\}', script_content, re.DOTALL):
            content = m.group(2)
            if '=' not in content or content.count('=') <= 10:
                continue
            mapping = {}
            pairs = re.findall(r'\["(.)"\]\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', content)
            if not pairs:
                pairs = re.findall(r'"(.)"\s*=\s*(-?\d+(?:\s*[+\-]\s*\d+)*)', content)
            for key, expr in pairs:
                try:
                    mapping[key.strip()] = eval(expr.replace(' ', '')) & 0x3F
                except Exception:
                    continue
            if len(mapping) > 30:
                return mapping
        return {}

    def reconstruct_strings(self, encrypted_strings, cipher_map):
        reconstructed = []
        for enc in encrypted_strings:
            if not isinstance(enc, str):
                reconstructed.append('')
                continue
            buf = bytearray(); acc = 0; cnt = 0
            for ch in enc:
                if ch in cipher_map:
                    acc = (acc << 6) | cipher_map[ch]; cnt += 1
                    if cnt == 4:
                        buf.extend([(acc >> 16) & 0xFF, (acc >> 8) & 0xFF, acc & 0xFF])
                        acc = cnt = 0
                elif ch == '=':
                    if cnt == 3: buf.append((acc >> 16) & 0xFF); buf.append((acc >> 8) & 0xFF)
                    elif cnt == 2: buf.append((acc >> 16) & 0xFF)
                    break
            try:    reconstructed.append(buf.decode('latin-1', errors='replace'))
            except: reconstructed.append('[Binary Data]')
        return reconstructed

    def analyze_script(self, file_path_or_content, is_content=False):
        if is_content:
            script_data = file_path_or_content
        else:
            with open(file_path_or_content, 'r', encoding='utf-8', errors='ignore') as f:
                script_data = f.read()
        data_tables          = self.locate_data_tables(script_data)
        cipher_mapping       = self.extract_cipher_mapping(script_data)
        encryption_functions = self.find_encryption_functions(script_data)
        final_strings        = []
        for table in data_tables:
            if cipher_mapping and len(cipher_mapping) > 30:
                final_strings.extend(self.reconstruct_strings(table['elements'], cipher_mapping))
            else:
                final_strings.extend(self.process_string_escapes(e) for e in table['elements'])
        return {
            'script_file':          '' if is_content else file_path_or_content,
            'data_tables_found':    len(data_tables),
            'cipher_mapping_size':  len(cipher_mapping),
            'encryption_functions': len(encryption_functions),
            'decrypted_strings':    final_strings,
            'cipher_map':           cipher_mapping,
        }


class PatternScanner:
    def __init__(self):
        self.registered_patterns = {}

    def register_pattern_type(self, name, pattern, weight_value=1):
        self.registered_patterns[name] = {
            'pattern_string':   pattern,
            'weight_value':     weight_value,
            'compiled_pattern': re.compile(pattern, re.MULTILINE | re.DOTALL),
        }

    def scan_text_content(self, text_input):
        results = {}
        for name, data in self.registered_patterns.items():
            matches = data['compiled_pattern'].findall(text_input)
            if matches:
                results[name] = {
                    'match_count':    len(matches),
                    'pattern_weight': data['weight_value'],
                    'total_score':    len(matches) * data['weight_value'],
                    'sample_matches': matches[:3],
                }
        return results

    def load_default_patterns(self):
        self.register_pattern_type('base64_pattern',   r'[A-Za-z0-9+/]+={0,2}', 2)
        self.register_pattern_type('hex_pattern',      r'0x[0-9A-Fa-f]+', 1)
        self.register_pattern_type('data_table',       r'local\s+\w+\s*=\s*\{[^}]+\}', 3)
        self.register_pattern_type('function_call',    r'\w+\([^)]*\)', 1)
        self.register_pattern_type('concat_operation', r'table\.concat\s*\([^)]+\)', 2)
        self.register_pattern_type('char_function',    r'string\.char\([^)]+\)', 2)
        self.register_pattern_type('bit_operation',    r'bit32\.[a-z]+\([^)]+\)', 2)
        self.register_pattern_type('load_function',    r'loadstring\s*\([^)]+\)', 3)
        self.register_pattern_type('env_access',       r'getfenv|setfenv|getgenv', 3)
        self.register_pattern_type('numeric_sequence', r'\b\d{4,}\b', 1)

    def analyze_target_content(self, content):
        self.load_default_patterns()
        detection_data    = self.scan_text_content(content)
        total_score_value = sum(item['total_score'] for item in detection_data.values())
        return {
            'content_size':       len(content),
            'detection_data':     detection_data,
            'total_score_value':  total_score_value,
            'risk_assessment':    self.assess_risk_level(total_score_value),
        }

    def assess_risk_level(self, score_value):
        if   score_value > 50: return 'High'
        elif score_value > 20: return 'Medium'
        elif score_value > 5:  return 'Low'
        else:                  return 'Minimal'
