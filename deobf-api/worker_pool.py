import os, subprocess, tempfile, concurrent.futures, hashlib, time
from collections import Counter
import math

LUA_BIN = os.environ.get('LUA_BIN', 'lua5.1')

def _entropy(s):
    if not s: return 0
    c = Counter(s)
    ln = len(s)
    return -sum((v/ln)*math.log2(v/ln) for v in c.values())

def _score_layer(code, trace_text=''):
    score = (
        code.count('function'),
        code.count('local'),
        code.count('end'),
        -_entropy(code),
        len(code),
    )
    if trace_text and ('loadstring' in trace_text or 'decode' in trace_text):
        return (score[0]+10, score[1], score[2], score[3], score[4])
    return score

def _run_single(source, timeout, env_patch=''):
    sandbox_path = os.path.join(os.path.dirname(__file__), 'sandbox', 'runtime.lua')
    with open(sandbox_path) as f:
        sandbox = f.read()
    if env_patch:
        sandbox = sandbox + '\n' + env_patch
    with tempfile.TemporaryDirectory() as d:
        in_path = os.path.join(d, 'input.lua')
        with open(in_path, 'w') as f:
            f.write(source)
        escaped = d.replace('\\', '\\\\')
        driver = sandbox + '\nlocal _outdir = "' + escaped + '"\n' + f'''
        local f = io.open("{escaped}\\input.lua", "r")
        local code = f:read("*a")
        f:close()
        local chunk, err = loadstring(code)
        if chunk then
            setfenv(chunk, _env)
            _running = true
            pcall(chunk)
            _running = false
        end
        _dump_trace()
        '''
        drv_path = os.path.join(d, 'driver.lua')
        with open(drv_path, 'w') as f:
            f.write(driver)
        try:
            subprocess.run([LUA_BIN, drv_path], timeout=timeout, cwd=d)
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
        trace_text = ''
        trace_path = os.path.join(d, 'trace.json')
        if os.path.exists(trace_path):
            with open(trace_path) as f:
                trace_text = f.read()
        return layers, trace_text

def run_parallel(source, timeouts=[5,7,10], env_patches=None):
    if env_patches is None:
        env_patches = [''] * len(timeouts)
    results = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=len(timeouts)) as executor:
        futures = [executor.submit(_run_single, source, t, e) for t, e in zip(timeouts, env_patches)]
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except:
                pass
    all_layers = []
    all_traces = []
    for layers, trace in results:
        all_layers.extend(layers)
        if trace:
            all_traces.append(trace)
    seen = set()
    unique = []
    for l in all_layers:
        h = hashlib.md5(l.encode()).hexdigest()
        if h not in seen:
            seen.add(h)
            unique.append(l)
    if unique:
        best = max(unique, key=lambda x: _score_layer(x, all_traces[0] if all_traces else ''))
        return best, all_traces
    return None, []
