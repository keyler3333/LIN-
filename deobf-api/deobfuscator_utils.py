import re
import base64
import struct

class Deobfuscator:
    def __init__(self):
        self.decrypted_data = {}
        self.decryption_keys = {}

    def process_base64(self, encoded_data):
        try:
            missing_padding = len(encoded_data) % 4
            if missing_padding:
                encoded_data += '=' * (4 - missing_padding)
            return base64.b64decode(encoded_data).decode('latin-1', errors='ignore')
        except:
            return encoded_data

    def process_hex_data(self, hex_data):
        try:
            if hex_data.startswith('0x'):
                hex_data = hex_data[2:]
            hex_data = re.sub(r'[^0-9A-Fa-f]', '', hex_data)
            if len(hex_data) % 2 != 0:
                hex_data = '0' + hex_data
            return bytes.fromhex(hex_data).decode('latin-1', errors='ignore')
        except:
            return hex_data

    def process_octal_data(self, octal_data):
        def replace_octal(match):
            return chr(int(match.group(1), 8))
        return re.sub(r'\\(\d{1,3})', replace_octal, octal_data)

    def apply_xor_cipher(self, input_data, cipher_key):
        try:
            output_chars = []
            key_bytes = str(cipher_key).encode() if not isinstance(cipher_key, bytes) else cipher_key
            for i, char_val in enumerate(input_data):
                key_val = key_bytes[i % len(key_bytes)]
                if isinstance(char_val, str):
                    output_chars.append(chr(ord(char_val) ^ key_val))
                else:
                    output_chars.append(chr(char_val ^ key_val))
            return ''.join(output_chars)
        except:
            return input_data

    def locate_data_tables(self, script_content):
        found_tables = []
        table_pattern = r'local\s+(\w+)\s*=\s*\{(.*?)\}'
        for table_match in re.finditer(table_pattern, script_content, re.DOTALL):
            table_identifier = table_match.group(1)
            table_elements = table_match.group(2)
            element_list = []
            current_position = 0
            while current_position < len(table_elements):
                if table_elements[current_position] in ['"', "'"]:
                    quote_symbol = table_elements[current_position]
                    element_end = current_position + 1
                    while element_end < len(table_elements):
                        if table_elements[element_end] == quote_symbol and table_elements[element_end-1] != '\\':
                            break
                        element_end += 1
                    if element_end < len(table_elements):
                        raw_element = table_elements[current_position + 1:element_end]
                        processed_element = self.process_string_escapes(raw_element)
                        element_list.append(processed_element)
                        current_position = element_end + 1
                        continue
                current_position += 1
            if element_list:
                found_tables.append({'name': table_identifier, 'elements': element_list})
        return found_tables

    def process_string_escapes(self, raw_string):
        escape_replacements = {
            r'\\n': '\n', r'\\r': '\r', r'\\t': '\t',
            r'\\"': '"', r"\\'": "'", r'\\\\': '\\',
            r'\\a': '\a', r'\\b': '\b', r'\\f': '\f', r'\\v': '\v'
        }
        def replace_hex(match):
            return chr(int(match.group(1), 16))
        for pattern, replacement in escape_replacements.items():
            raw_string = raw_string.replace(pattern, replacement)
        raw_string = re.sub(r'\\x([0-9a-fA-F]{2})', replace_hex, raw_string)
        return raw_string

    def find_encryption_functions(self, script_content):
        function_patterns = [
            r'function\s+(\w+)\s*\([^)]*\)\s*local\s+.*string\.char',
            r'local\s+function\s+(\w+)\s*\([^)]*\)\s*.*bit32\.',
            r'(\w+)\s*=\s*function\s*\([^)]*\)\s*.*table\.concat'
        ]
        encryption_functions = []
        for pattern in function_patterns:
            matches = re.finditer(pattern, script_content, re.DOTALL)
            for match in matches:
                if match.group(1):
                    function_start = match.start()
                    function_end = script_content.find('end', function_start)
                    if function_end != -1:
                        function_body = script_content[function_start:function_end + 3]
                        encryption_functions.append({'name': match.group(1), 'body': function_body})
        return encryption_functions

    def extract_cipher_mapping(self, script_content):
        mapping_pattern = r'local\s+(\w+)\s*=\s*\{(.*?)\}'
        for match in re.finditer(mapping_pattern, script_content, re.DOTALL):
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
                    val = eval(expr.replace(' ', ''))
                    mapping_dict[key.strip()] = val & 0x3F
                except:
                    continue
            if len(mapping_dict) > 30:
                return mapping_dict
        return {}

    def reconstruct_strings(self, encrypted_strings, cipher_map):
        reconstructed = []
        for enc_string in encrypted_strings:
            if not isinstance(enc_string, str):
                reconstructed.append("")
                continue
            byte_buffer = bytearray()
            accumulator = 0
            position_counter = 0
            for char in enc_string:
                if char in cipher_map:
                    char_value = cipher_map[char]
                    accumulator = (accumulator << 6) | char_value
                    position_counter += 1
                    if position_counter == 4:
                        byte_buffer.append((accumulator >> 16) & 0xFF)
                        byte_buffer.append((accumulator >> 8) & 0xFF)
                        byte_buffer.append(accumulator & 0xFF)
                        accumulator = 0
                        position_counter = 0
                elif char == '=':
                    if position_counter == 3:
                        byte_buffer.append((accumulator >> 16) & 0xFF)
                        byte_buffer.append((accumulator >> 8) & 0xFF)
                    elif position_counter == 2:
                        byte_buffer.append((accumulator >> 16) & 0xFF)
                    break
            try:
                decoded_string = byte_buffer.decode('latin-1', errors='replace')
                reconstructed.append(decoded_string)
            except:
                reconstructed.append("[Binary Data]")
        return reconstructed

    def analyze_script(self, file_path_or_content, is_content=False):
        if is_content:
            script_data = file_path_or_content
        else:
            with open(file_path_or_content, 'r', encoding='utf-8', errors='ignore') as f:
                script_data = f.read()
        data_tables = self.locate_data_tables(script_data)
        cipher_mapping = self.extract_cipher_mapping(script_data)
        encryption_functions = self.find_encryption_functions(script_data)
        final_strings = []
        for table in data_tables:
            if cipher_mapping and len(cipher_mapping) > 30:
                decrypted = self.reconstruct_strings(table['elements'], cipher_mapping)
                final_strings.extend(decrypted)
            else:
                for element in table['elements']:
                    processed = self.process_string_escapes(element)
                    final_strings.append(processed)
        return {
            'script_file': '' if is_content else file_path_or_content,
            'data_tables_found': len(data_tables),
            'cipher_mapping_size': len(cipher_mapping),
            'encryption_functions': len(encryption_functions),
            'decrypted_strings': final_strings,
            'cipher_map': cipher_mapping
        }


class PatternScanner:
    def __init__(self):
        self.registered_patterns = {}
        self.scan_results = {}

    def register_pattern_type(self, name, pattern, weight_value=1):
        self.registered_patterns[name] = {
            'pattern_string': pattern,
            'weight_value': weight_value,
            'compiled_pattern': re.compile(pattern, re.MULTILINE | re.DOTALL)
        }

    def scan_text_content(self, text_input):
        results = {}
        for pattern_name, pattern_data in self.registered_patterns.items():
            pattern_object = pattern_data['compiled_pattern']
            found_matches = pattern_object.findall(text_input)
            if found_matches:
                results[pattern_name] = {
                    'match_count': len(found_matches),
                    'pattern_weight': pattern_data['weight_value'],
                    'total_score': len(found_matches) * pattern_data['weight_value'],
                    'sample_matches': found_matches[:3] if found_matches else []
                }
        return results

    def load_default_patterns(self):
        self.register_pattern_type('base64_pattern', r'[A-Za-z0-9+/]+={0,2}', 2)
        self.register_pattern_type('hex_pattern', r'0x[0-9A-Fa-f]+', 1)
        self.register_pattern_type('data_table', r'local\s+\w+\s*=\s*\{[^}]+\}', 3)
        self.register_pattern_type('function_call', r'\w+\([^)]*\)', 1)
        self.register_pattern_type('concat_operation', r'table\.concat\s*\([^)]+\)', 2)
        self.register_pattern_type('char_function', r'string\.char\([^)]+\)', 2)
        self.register_pattern_type('bit_operation', r'bit32\.[a-z]+\([^)]+\)', 2)
        self.register_pattern_type('load_function', r'loadstring\s*\([^)]+\)', 3)
        self.register_pattern_type('env_access', r'getfenv|setfenv|getgenv', 3)
        self.register_pattern_type('numeric_sequence', r'\b\d{4,}\b', 1)

    def analyze_target_content(self, content):
        self.load_default_patterns()
        detection_data = self.scan_text_content(content)
        total_score_value = sum(item['total_score'] for item in detection_data.values())
        return {
            'content_size': len(content),
            'detection_data': detection_data,
            'total_score_value': total_score_value,
            'risk_assessment': self.assess_risk_level(total_score_value)
        }

    def assess_risk_level(self, score_value):
        if score_value > 50:
            return "High"
        elif score_value > 20:
            return "Medium"
        elif score_value > 5:
            return "Low"
        else:
            return "Minimal"
