from sandbox import execute_sandbox

class DeobfEngine:
    def __init__(self):
        self.max_depth = 5

    def process(self, source, depth=0):
        if depth >= self.max_depth:
            return source, 'max_depth', 'Max recursion depth reached'

        layers, captures = execute_sandbox(source, timeout=45)

        best = ""
        for cap in captures:
            if len(cap) > len(best) and ('function' in cap or 'local' in cap or 'print' in cap):
                best = cap

        if best:
            return self._beautify(best), 'sandbox', 'Decrypted payload captured'

        for layer in layers:
            if isinstance(layer, str) and len(layer) > 50:
                if 'function' in layer or 'local' in layer or 'print' in layer:
                    return self._beautify(layer), 'sandbox_layer', 'Captured layer'

        return source, 'unable', 'Sandbox executed but no payload captured – the script may not have called loadstring.'

    def _beautify(self, code):
        try:
            from luaparser import ast as lua_ast
            return lua_ast.to_lua_source(lua_ast.parse(code))
        except Exception:
            out, ind = [], 0
            for raw in code.split('\n'):
                line = raw.strip()
                if not line:
                    continue
                if any(line.startswith(w) for w in ('end', 'else', 'elseif', 'until', '}', ')')):
                    ind = max(0, ind - 1)
                out.append('    ' * ind + line)
                if any(line.startswith(w) for w in ('if ', 'for ', 'while ', 'repeat', 'function ', 'local function ')) and not line.endswith('end'):
                    ind += 1
            return '\n'.join(out)
