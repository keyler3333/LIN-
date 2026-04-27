import re

def lift_vm(source):
    if not re.search(r'local\s+\w+\s*=\s*\{\s*[0-9]+\s*[,\s]', source):
        return None
    const_match = re.search(r'local\s+(\w+)\s*=\s*\{\s*([^\}]+)\}', source)
    if not const_match:
        return None
    const_name = const_match.group(1)
    consts = [int(c.strip()) for c in const_match.group(2).split(',') if c.strip().isdigit()]
    if not consts:
        return None
    chars = ''.join(chr(c) for c in consts if 0 < c < 256)
    if len(chars) > 4 and re.match(r'^[\x20-\x7e\r\n\t]+$', chars):
        return f"-- VM constants lifted to string:\n\"{chars}\""
    return None
