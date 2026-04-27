import os, subprocess, tempfile, re, math, json
from collections import Counter
from ir_builder import build_ir
from constant_propagation import propagate
from control_flow import reconstruct_control_flow, detect_state_machine
from vm_detector import detect_vm, extract_vm_info
from vm_lifter import lift_vm_from_source
from symbolic_exec import resolve_condition
from optimizer_passes import remove_dead_code, remove_unused_assignments
from beautifier import ir_to_lua
from worker_pool import run_parallel

LUA_BIN = os.environ.get('LUA_BIN', 'lua5.1')

# Load strategies
_strategies = []
_strategies_dir = os.path.join(os.path.dirname(__file__), 'strategies')
for module_name in ['wearedevs', 'ironbrew', 'luraph']:
    try:
        mod = __import__(f'strategies.{module_name}', fromlist=['strategy'])
        if hasattr(mod, 'strategy'):
            _strategies.append(mod.strategy)
    except:
        pass

# Load signature DB
_sig_db = {}
_sig_path = os.path.join(os.path.dirname(__file__), 'signature_db.json')
if os.path.exists(_sig_path):
    with open(_sig_path) as f:
        _sig_db = json.load(f)

def entropy(s):
    if not s: return 0
    c = Counter(s)
    ln = len(s)
    return -sum((v/ln)*math.log2(v/ln) for v in c.values())

def score_layer(code, trace_text=''):
    base = (
        code.count('function'),
        code.count('local'),
        code.count('end'),
        -entropy(code),
        len(code),
    )
    if trace_text and ('loadstring' in trace_text or 'decode' in trace_text):
        return (base[0]+10, base[1], base[2], base[3], base[4])
    return base

def static_decode(code):
    code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), code)
    code = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)
    def sc(m):
        nums = re.findall(r'\d+', m.group(1))
        try: return '"' + ''.join(chr(int(n)) for n in nums if int(n) < 256) + '"'
        except: return m.group(0)
    code = re.sub(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', sc, code)
    return code

def deep_deobfuscate(source, force_trace=False, force_sandbox=False, force_vm_lift=False):
    # Choose strategy based on detection
    for strat in _strategies:
        if strat.detect(source):
            return strat.deobfuscate(source, None)
    # Fallback to signature DB
    for name, entry in _sig_db.items():
        if all(re.search(p, source) for p in entry['patterns']):
            if entry['strategy'] == 'trace_deobfuscation' or force_trace:
                return static_decode(source)  # placeholder for trace deobf
            elif entry['strategy'] == 'sandbox_peel' or force_sandbox:
                return sandbox_peel(source)
            elif entry['strategy'] == 'vm_lift' or force_vm_lift:
                return vm_lift(source)
            break
    # Default: parallel sandbox then IR optimization
    best, traces = run_parallel(static_decode(source))
    if best:
        source = best
    try:
        ir = build_ir(source)
        ir = propagate(ir)
        ir = remove_dead_code(ir)
        ir = remove_unused_assignments(ir)
        ir = reconstruct_control_flow(ir)
        return ir_to_lua(ir)
    except:
        return source

def sandbox_peel(source):
    decoded = static_decode(source)
    best, _ = run_parallel(decoded, timeouts=[5, 8])
    return best if best else decoded

def vm_lift(source):
    lifted = lift_vm_from_source(source)
    if lifted:
        return lifted
    return sandbox_peel(source)
