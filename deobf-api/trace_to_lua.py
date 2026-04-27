import re
import os
from collections import defaultdict

def parse_constants_section(text):
    constants = {}
    const_match = re.search(r'--- CONSTANTS ---\n(.*?)(?:\n\n|---|\Z)', text, re.DOTALL)
    if not const_match:
        return constants
    const_text = const_match.group(1)
    local_match = re.search(r'local\s+Constants\s*=\s*\{(.*?)\}', const_text, re.DOTALL)
    if not local_match:
        return constants
    table_body = local_match.group(1)
    entries = re.findall(r'\[(\d+)\]\s*=\s*"((?:[^"\\]|\\.)*)"', table_body)
    for idx, value in entries:
        constants[int(idx)] = value.encode().decode('unicode_escape') if '\\' in value else value
    return constants

def parse_access_traces(trace_lines):
    traces = []
    in_loadstring = False
    loadstring_lines = []
    for line in trace_lines:
        line = line.strip()
        if not line:
            continue
        if in_loadstring:
            if line == "LOADSTRING CONTENT END":
                in_loadstring = False
                traces.append({'type': 'loadstring_code', 'code': '\n'.join(loadstring_lines)})
                loadstring_lines = []
            else:
                loadstring_lines.append(line)
            continue
        if line == "LOADSTRING CONTENT START":
            in_loadstring = True
            continue
        accessed = re.match(r'ACCESSED --> (.+)', line)
        if accessed:
            path = accessed.group(1)
            parts = path.replace('-->', '.').split('.')
            traces.append({'type': 'access', 'path': parts, 'raw': path})
            continue
        set_global = re.match(r'SET GLOBAL --> (.+?) = (.+)', line)
        if set_global:
            traces.append({'type': 'set_global', 'name': set_global.group(1), 'value': set_global.group(2)})
            continue
        call_result = re.match(r'CALL_RESULT --> local (\w+) = (.+)', line)
        if call_result:
            traces.append({'type': 'call_result', 'var': call_result.group(1), 'call': call_result.group(2)})
            continue
        prop_set = re.match(r'PROP_SET --> (.+?) = (.+)', line)
        if prop_set:
            traces.append({'type': 'prop_set', 'path': prop_set.group(1), 'value': prop_set.group(2)})
            continue
        loadstring = re.match(r'LOADSTRING DETECTED: size=(\d+)', line)
        if loadstring:
            traces.append({'type': 'loadstring_detected', 'size': int(loadstring.group(1))})
            continue
        unpack_call = re.match(r'UNPACK CALLED WITH TABLE.*size=(\d+)', line)
        if unpack_call:
            traces.append({'type': 'unpack', 'size': int(unpack_call.group(1))})
            continue
        chunk = re.match(r'CAPTURED CHUNK STRING: (.+)', line)
        if chunk:
            traces.append({'type': 'captured_chunk', 'data': chunk.group(1)})
            continue
        url = re.match(r'URL DETECTED.*--> (.+)', line)
        if url:
            traces.append({'type': 'url', 'url': url.group(1)})
            continue
        trace_print = re.match(r'TRACE_PRINT --> (.+)', line)
        if trace_print:
            traces.append({'type': 'print', 'text': trace_print.group(1)})
            continue
    return traces

def reconstruct_from_traces(traces, constants):
    code_lines = []
    indent = 0
    seen_vars = set()
    code_lines.append('require = nil')
    code_lines.append('loadstring = nil')
    code_lines.append('loadfile = nil')
    code_lines.append('dofile = nil')
    code_lines.append('')
    def add_line(line):
        nonlocal indent
        stripped = line.strip()
        if stripped.startswith('end') or stripped.startswith('else') or stripped.startswith('elseif') or stripped.startswith('until'):
            indent = max(0, indent - 1)
        code_lines.append('    ' * indent + stripped)
        if stripped.startswith('if ') or stripped.startswith('for ') or stripped.startswith('while ') or stripped.startswith('repeat'):
            indent += 1
        elif stripped.startswith('function ') or stripped.startswith('local function '):
            indent += 1
    for trace in traces:
        if trace['type'] == 'loadstring_code':
            code = trace['code']
            code_lines.append('')
            code_lines.append('-- Deobfuscated payload extracted from loadstring:')
            code_lines.append('')
            for line in code.split('\n'):
                add_line(line)
            code_lines.append('')
            break
        elif trace['type'] == 'call_result':
            func_call = trace['call'].rstrip(')')
            func_name = trace['var']
            seen_vars.add(func_name)
            if 'game.HttpGet' in func_call or 'syn.request' in func_call:
                add_line(f'local {func_name} = nil')
            elif 'GetObjects' in func_call:
                add_line(f'local {func_name} = nil')
            elif 'InsertService' in func_call:
                add_line(f'local {func_name} = nil')
            elif 'MarketplaceService' in func_call:
                add_line(f'local {func_name} = nil')
            elif 'TeleportService' in func_call:
                add_line(f'local {func_name} = nil')
            else:
                if 'require' in func_call:
                    module_id = re.search(r'require\((\d+)\)', func_call)
                    if module_id:
                        module_num = int(module_id.group(1))
                        if module_num in constants:
                            add_line(f'local {func_name} = require({module_num})')
                        else:
                            add_line(f'local {func_name} = nil')
                    else:
                        add_line(f'local {func_name} = nil')
                else:
                    add_line(f'local {func_name} = nil')
        elif trace['type'] == 'set_global':
            name = trace['name']
            value = trace['value']
            seen_vars.add(name)
            add_line(f'{name} = {value}')
        elif trace['type'] == 'prop_set':
            path = trace['path']
            value = trace['value']
            add_line(f'{path} = {value}')
        elif trace['type'] == 'url':
            add_line(f'-- URL: {trace["url"]}')
        elif trace['type'] == 'print':
            add_line(f'-- {trace["text"]}')
    if not any(t['type'] == 'loadstring_code' for t in traces):
        code_lines.append('')
        code_lines.append('-- No loadstring payload captured.')
        code_lines.append('-- Script uses custom VM or failed to deobfuscate.')
        code_lines.append('')
        code_lines.append('-- Constants extracted from bytecode:')
        if constants:
            for k, v in sorted(constants.items()):
                if len(v) < 200:
                    code_lines.append(f'--   [{k}] = "{v}"')
                else:
                    code_lines.append(f'--   [{k}] = "{v[:100]}..."')
    return '\n'.join(code_lines)

def reconstruct_from_chunks(traces):
    for trace in traces:
        if trace['type'] == 'captured_chunk':
            chunk_data = trace['data']
            parts = chunk_data.split(',')
            decoded = []
            for part in parts:
                clean = part.strip().strip('"')
                decoded.append(clean)
            return '\n'.join(decoded)
    return None

def parse_trace_string(report_text):
    constant_text = ""
    trace_lines = []
    in_constants = False
    for line in report_text.splitlines():
        ln = line.strip()
        if ln == "--- CONSTANTS START ---":
            in_constants = True
            continue
        if ln == "--- CONSTANTS END ---":
            in_constants = False
            continue
        if in_constants:
            constant_text += ln + "\n"
        elif any(ln.startswith(p) for p in ("ACCESSED", "CALL_RESULT", "URL DETECTED",
                                             "SET GLOBAL", "UNPACK CALLED",
                                             "LOADSTRING", "TRACE_PRINT", "CAPTURED")):
            trace_lines.append(ln)
    constants = parse_constants_section("--- CONSTANTS ---\n" + constant_text)
    traces = parse_access_traces(trace_lines)
    from_chunks = reconstruct_from_chunks(traces)
    if from_chunks:
        return from_chunks
    return reconstruct_from_traces(traces, constants)

def parse_trace(report_file):
    with open(report_file, 'r', encoding='utf-8') as f:
        text = f.read()
    result = parse_trace_string(text)
    out_name = report_file.replace('.report.txt', '.deobf.lua')
    with open(out_name, 'w', encoding='utf-8') as f:
        f.write(result)
    return result
