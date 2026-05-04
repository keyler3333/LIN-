from transformers import (
    Lua51Parser,
    Lua51Decompiler,
    WeAreDevsLifter,
    EscapeSequenceTransformer,
    MathTransformer,
    HexNameRenamer,
)
from sandbox import execute_sandbox


class DeobfEngine:
    def __init__(self):
        self.lifter = WeAreDevsLifter()
        self.cleaners = [
            EscapeSequenceTransformer(),
            MathTransformer(),
            self.lifter,
            HexNameRenamer(),
        ]
        self.max_depth = 5

    def process(self, source, depth=0):
        if depth >= self.max_depth:
            return source, 'max_depth', 'Max recursion depth reached'

        current = source
        for t in self.cleaners:
            try:
                current = t.transform(current)
            except:
                pass

        if current != source and self._looks_decoded(current):
            return self._beautify(current), 'static_lift', 'Static lift succeeded'

        layers, captures, diag = execute_sandbox(current, timeout=60)

        for item in layers:
            if isinstance(item, bytes) and item.startswith(b'\x1bLua'):
                lifted = self._lift_bc(item)
                if lifted:
                    return self._beautify(lifted), 'sandbox_dump', 'Bytecode dump decompiled'

        best = ""
        for cap in captures:
            if len(cap) > len(best) and ('function' in cap or 'local' in cap or 'print' in cap):
                best = cap

        if best:
            return self._beautify(best), 'sandbox_capture', 'Captured payload'

        for layer in layers:
            if isinstance(layer, str) and len(layer) > 50:
                if 'function' in layer or 'local' in layer or 'print' in layer:
                    return self._beautify(layer), 'sandbox_layer', 'Captured layer'

        reason = diag or self.lifter.diagnostic or 'No payload produced.'
        return source, 'unable', reason

    def _lift_bc(self, bc):
        try:
            parser = Lua51Parser(bc)
            func = parser.parse_function()
            return Lua51Decompiler(func).decompile()
        except Exception:
            return None

    @staticmethod
    def _looks_decoded(code):
        if not code or len(code) < 20:
            return False
        lines = code.split('\n')
        if max((len(l) for l in lines), default=0) > 500:
            return False
        alpha = sum(1 for ch in code if ch.isalpha() or ch in ' \t\n_.,;(){}[]=')
        return (alpha / max(len(code), 1)) > 0.25

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
