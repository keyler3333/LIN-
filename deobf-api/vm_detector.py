import re

def detect_vm(source):
    score = 0
    patterns = [
        r'local\s+\w+\s*=\s*\{\s*[0-9]+\s*[,\s]',   # instruction table
        r'while\s+true\s+do\s+local\s+\w+\s*=\s*\w+\[',  # dispatch loop
        r'pc\s*=\s*pc\s*\+\s*1',                   # program counter increment
        r'op\s*=\s*instr\s*%\s*\d+',               # opcode extraction
        r'local\s+\w+\s*=\s*\w+\(\w+\)',           # op handler call
        r'if\s+op\s*==\s*\d+\s+then',                # opcode dispatch
    ]
    for pat in patterns:
        if re.search(pat, source):
            score += 1
    return score >= 3

def extract_vm_info(source):
    info = {}
    const_match = re.search(r'local\s+(\w+)\s*=\s*\{\s*([^\}]+)\}', source)
    if const_match:
        info['const_table'] = const_match.group(1)
    return info
