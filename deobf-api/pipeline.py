import os, subprocess, tempfile, re, math, json, hashlib
from collections import Counter
from ir_builder import build_ir, If, While, Block
from constant_propagation import propagate
from control_flow import reconstruct_control_flow
from vm_detector import detect_vm, extract_vm_info
from vm_lifter import lift_vm_from_source
from symbolic_exec import resolve_condition
from symbolic_engine import SymState, execute_symbolic, SymStore
from ssa import convert_to_ssa
from cfg import build_cfg
from optimizer_passes import remove_dead_code, remove_unused_assignments
from beautifier import ir_to_lua
from worker_pool import run_parallel
from knowledge_base import KnowledgeBase, hash_source
from learning_engine import LearningEngine
from path_explorer import explore_paths
from vm_handler_extractor import detect_dispatch_loop, extract_handlers
from anti_analysis import apply_anti_analysis
from z3_solver import expr_to_z3, solve_condition
from strategies.wearedevs import WeAreDevsStrategy
from strategies.ironbrew import IronBrewStrategy
from strategies.luraph import LuraphStrategy

LUA_BIN = os.environ.get('LUA_BIN', 'lua5.1')

kb = KnowledgeBase(os.path.join(os.path.dirname(__file__), 'sig_db.json'))
learn = LearningEngine(os.path.join(os.path.dirname(__file__), 'learn_db.json'))

strategies = [
    WeAreDevsStrategy(),
    IronBrewStrategy(),
    LuraphStrategy()
]

def entropy(s):
    if not s: return 0
    c = Counter(s)
    ln = len(s)
    return -sum((v/ln)*math.log2(v/ln) for v in c.values())

def static_decode(code):
    code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), code)
    code = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)
    def sc(m):
        nums = re.findall(r'\d+', m.group(1))
        try: return '"' + ''.join(chr(int(n)) for n in nums if int(n) < 256) + '"'
        except: return m.group(0)
    code = re.sub(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', sc, code)
    return code

def deep_deobfuscate(source, skip_strategies=False):
    ch = hash_source(source)
    cached = kb.get_result(ch)
    if cached:
        learn.record_result(ch, 'cache', True)
        return cached['result']
    if not skip_strategies:
        best_strat = learn.best_strategy(ch)
        if best_strat:
            for strat in strategies:
                if strat.name == best_strat and strat.detect(source):
                    return strat.deobfuscate(source, None)
        for strat in strategies:
            if strat.detect(source):
                result = strat.deobfuscate(source, None)
                learn.record_result(ch, strat.name, True)
                return result
    decoded = static_decode(source)
    best, traces = run_parallel(decoded, timeouts=[5,8,12], env_patches=['', apply_anti_analysis('')])
    if best:
        decoded = best
    if detect_vm(decoded):
        lifted = lift_vm_from_source(decoded)
        if lifted:
            decoded = lifted
        else:
            handlers = extract_handlers(decoded)
            if handlers:
                decoded = '-- VM handlers:\n' + json.dumps(handlers, indent=2)
    try:
        ir = build_ir(decoded)
    except:
        return decoded
    blocks = build_cfg(ir)
    paths = explore_paths(blocks)
    viable_states = [p.sym_state for p in paths]
    for state in viable_states:
        for block in blocks:
            for instr in block.instructions:
                execute_symbolic(instr, state)
    ssa_instrs, _ = convert_to_ssa(ir)
    ir = propagate(ir)
    ir = remove_dead_code(ir)
    ir = remove_unused_assignments(ir)
    ir = reconstruct_control_flow(ir)
    code = ir_to_lua(ir)
    code = re.sub(r'^\s*if\s+false\s+then.*?end', '', code, flags=re.DOTALL|re.MULTILINE)
    code = re.sub(r'^\s*while\s+false\s+do.*?end', '', code, flags=re.DOTALL|re.MULTILINE)
    learn.record_result(ch, 'full_pipeline', True)
    kb.add_result(ch, code, 'full_pipeline')
    return code
