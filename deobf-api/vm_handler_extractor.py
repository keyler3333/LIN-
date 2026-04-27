import re

def detect_dispatch_loop(source):
    if re.search(r'while\s+true\s+do\s+local\s+\w+\s*=\s*\w+\s*\[', source):
        return True
    if re.search(r'pc\s*=\s*pc\s*\+\s*1', source) and re.search(r'op\s*=\s*\w+\[pc\]', source):
        return True
    return False

def extract_handlers(source):
    handlers = {}
    block_match = re.finditer(r'if\s+op\s*==\s*(\d+)\s+then\s+(.*?)\s+elseif|end', source, re.DOTALL)
    for m in block_match:
        op_num = int(m.group(1))
        body = m.group(2).strip()
        if 'return' in body or 'pc' in body:
            handlers[op_num] = body[:80]
    return handlers
