from cfg import build_cfg
from path_explorer import explore
from ir_builder import build_ir
from constant_propagation import propagate
from optimizer_passes import remove_dead_code, remove_unused_assignments
from beautifier import ir_to_lua

def deep_deobfuscate(source):
    ir = build_ir(source)

    blocks, entry = build_cfg(ir)

    paths = explore(entry)


    best = None
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
                best = code
        except:
            continue

    return best or source
