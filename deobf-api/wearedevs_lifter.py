import re
import base64
import struct

def _extract_cipher_mapping(source):
    mapping_pattern = r'local\s+(\w+)\s*=\s*\{(.*?)\}'
    for match in re.finditer(mapping_pattern, source, re.DOTALL):
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
    return None

def _extract_shuffle_pairs(source):
    pattern = r'\{(-?\d+(?:\s*[+\-]\s*-?\d+)*)\s*,\s*(-?\d+(?:\s*[+\-]\s*-?\d+)*)\}'
    matches = re.findall(pattern, source)
    pairs = []
    for a_expr, b_expr in matches:
        try:
            a = eval(a_expr.replace(' ', ''))
            b = eval(b_expr.replace(' ', ''))
            pairs.append([a, b])
        except:
            continue
    return pairs

def _apply_unshuffle(strings, pairs):
    result = list(strings)
    for a, b in reversed(pairs):
        a_idx = a - 1
        b_idx = b - 1
        if a_idx < 0 or b_idx >= len(result):
            continue
        while a_idx < b_idx:
            result[a_idx], result[b_idx] = result[b_idx], result[a_idx]
            a_idx += 1
            b_idx -= 1
    return result

def _decode_string_with_map(s, cipher_map):
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
        val = cipher_map.get(ch)
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
    return bytes(byte_buffer) if byte_buffer else None

def _decode_wearedevs_strings(source):
    cipher_map = _extract_cipher_mapping(source)
    if cipher_map is None:
        return None

    table_match = re.search(r'local\s+N\s*=\s*\{(.*?)\}', source, re.DOTALL)
    if not table_match:
        table_match = re.search(r'local\s+\w+\s*=\s*\{("[^"]*".*?)\}', source, re.DOTALL)
    if not table_match:
        return None
    raw_table = table_match.group(1)
    encoded_strings = re.findall(r'"((?:\\.|[^"\\])*)"', raw_table)
    if not encoded_strings:
        return None

    shuffle_pairs = _extract_shuffle_pairs(source)
    if shuffle_pairs:
        encoded_strings = _apply_unshuffle(encoded_strings, shuffle_pairs)

    decoded_list = []
    for s in encoded_strings:
        decoded = _decode_string_with_map(s, cipher_map)
        if decoded is None:
            continue
        try:
            text = decoded.decode('utf-8', errors='replace')
        except:
            text = decoded.decode('latin-1', errors='replace')
        decoded_list.append(text)

    return decoded_list

def lift_wearedevs(source):
    decoded_strings = _decode_wearedevs_strings(source)
    if not decoded_strings:
        return None

    for s in decoded_strings:
        if len(s) > 200 and ('function' in s or 'local' in s):
            return s

    full = '\n'.join(decoded_strings)
    if len(full) > 200 and ('function' in full or 'local' in full):
        return full

    return None
