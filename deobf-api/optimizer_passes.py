import re

def remove_unused_locals(code):
    lines = code.split('\n')
    used = set()
    for line in lines:
        for match in re.finditer(r'\b([a-zA-Z_]\w*)\b', line):
            used.add(match.group(1))
    result = []
    for line in lines:
        m = re.match(r'local\s+([a-zA-Z_]\w*)\s*=\s*', line)
        if m:
            var = m.group(1)
            if var not in used:
                continue
        result.append(line)
    return '\n'.join(result)

def remove_dead_branches(code):
    code = re.sub(r'if\s+false\s+then.*?end', '', code, flags=re.DOTALL)
    code = re.sub(r'while\s+false\s+do.*?end', '', code, flags=re.DOTALL)
    return code

def collapse_redundant_expressions(code):
    code = re.sub(r'not\s+not\s+', '', code)
    code = re.sub(r'\(\((.+?)\)\)', r'(\1)', code)
    return code
