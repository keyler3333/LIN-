import os, subprocess, tempfile, concurrent.futures
from collections import Counter
import math

LUA_BIN = os.environ.get('LUA_BIN', 'lua5.1')

def _entropy(s):
    if not s: return 0
    c = Counter(s)
    ln = len(s)
    return -sum((v/ln)*math.log2(v/ln) for v in c.values())

def _score_layer(code, trace_text=''):
    return (
        code.count('function'),
        code.count('local'),
        code.count('end'),
        -_entropy(code),
        len(code),
        bool(trace_text and ('loadstring' in trace_text or 'decode' in trace_text))
    )

def _run_single(source, timeout):
    sandbox_path = os.path.join(os.path.dirname(__file__), 'sandbox', 'runtime.lua')
    with open(sandbox_path) as f:
        sandbox = f.read()
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

def run_parallel(source, timeouts=[5, 7, 10]):
    results = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=len(timeouts)) as executor:
        futures = [executor.submit(_run_single, source, t) for t in timeouts]
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
    if all_layers:
        best = max(all_layers, key=lambda l: _score_layer(l, all_traces[0] if all_traces else ''))
        return best, all_traces
    return None, []
