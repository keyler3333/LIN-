import os, subprocess, tempfile, re, math
from collections import Counter
from ir_builder import build_ir
from constant_propagation import propagate
from control_flow import reconstruct_control_flow, detect_state_machine
from vm_detector import detect_vm, extract_vm_info
from vm_lifter import lift_vm_from_source
from symbolic_exec import resolve_condition
from optimizer_passes import remove_unused_locals, remove_dead_branches, collapse_redundant_expressions
from beautifier import ir_to_lua

LUA_BIN = os.environ.get('LUA_BIN', 'lua5.1')

def entropy(s):
    if not s: return 0
    c = Counter(s)
    ln = len(s)
    return -sum((v/ln)*math.log2(v/ln) for v in c.values())

def score_layer(code):
    return (
        code.count('function'),
        code.count('local'),
        code.count('end'),
        -entropy(code),
        len(code),
    )

def static_decode(code):
    code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), code)
    code = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)
    code = re.sub(r'string\.char\s*\(\s*([\d,\s]+)\s*\)',
                  lambda m: '"' + ''.join(chr(int(n)) for n in re.findall(r'\d+', m.group(1)) if int(n) < 256) + '"', code)
    return code

def run_sandbox(source, timeout=8):
    sandbox_path = os.path.join(os.path.dirname(__file__), 'sandbox', 'runtime.lua')
    with open(sandbox_path) as f:
        sandbox_script = f.read()
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, 'input.lua'), 'w') as f:
            f.write(source)
        driver = sandbox_script + '\nlocal _outdir = "' + d.replace('\\', '\\\\') + '"\n' + '''
        local f = io.open("''' + d.replace('\\', '\\\\') + '''/input.lua", "r")
        local code = f:read("*a")
        f:close()
        local chunk, err = loadstring(code)
        if chunk then
            setfenv(chunk, _env)
            _running = true
            pcall(chunk)
            _running = false
        end
        '''
        driver_path = os.path.join(d, 'driver.lua')
        with open(driver_path, 'w') as f:
            f.write(driver)
        try:
            subprocess.run([LUA_BIN, driver_path], timeout=timeout, cwd=d)
        except:
            pass
        layers = []
        i = 1
        while True:
            p = os.path.join(d, f'layer_{i}.lua')
            if not os.path.exists(p):
                break
            with open(p) as f:
                layers.append(f.read())
            i += 1
        return layers

def deep_deobfuscate(source):
    source = static_decode(source)
    for _ in range(5):
        layers = run_sandbox(source)
        if layers:
            source = max(layers, key=score_layer)
        if detect_vm(source):
            lifted = lift_vm_from_source(source)
            if lifted:
                source = lifted
                break
    try:
        ir = build_ir(source)
    except:
        return source
    ir = propagate(ir)
    ir = reconstruct_control_flow(ir)
    code = ir_to_lua(ir)
    code = remove_unused_locals(code)
    code = remove_dead_branches(code)
    code = collapse_redundant_expressions(code)
    return code
