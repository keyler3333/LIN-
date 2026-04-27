import os, re, math, json, hashlib
from collections import Counter
from ir_builder import build_ir
from constant_propagation import propagate
from optimizer_passes import remove_dead_code, remove_unused_assignments
from beautifier import ir_to_lua
from worker_pool import run_parallel
from knowledge_base import KnowledgeBase, hash_source
from learning_engine import LearningEngine
from cfg import build_cfg
from path_explorer import explore
from anti_analysis import apply_anti_analysis
from vm_detector import detect_vm
from vm_lifter import lift_vm_from_source
from vm_handler_extractor import extract_handlers
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
    ir = build_ir(decoded)
    blocks, entry = build_cfg(ir)
    paths = explore(entry)
    best_code = None
    best_score = -1
    for p in paths:
        try:
            optimized = propagate(ir)
            optimized = remove_dead_code(optimized)
            optimized = remove_unused_assignments(optimized)
            code = ir_to_lua(optimized)
            score = len(code) + len(str(p.state.store.data))
            if score > best_score:
                best_score = score
                best_code = code
        except:
            continue
    if best_code:
        kb.add_result(ch, best_code, 'full_pipeline')
        learn.record_result(ch, 'full_pipeline', True)
        return best_code
    return decoded
