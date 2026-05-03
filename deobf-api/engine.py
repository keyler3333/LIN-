from transformers import (
    EscapeSequenceTransformer,
    MathTransformer,
    HexNameRenamer,
    WeAreDevsLifter,
    Lua51Parser,
    Lua51Decompiler,
)
from sandbox import execute_sandbox

class DeobfEngine:
    def __init__(self):
        self.static_transformers = [
            EscapeSequenceTransformer(),
            MathTransformer(),
            WeAreDevsLifter(),
            HexNameRenamer(),
        ]
        self.max_depth = 5

    def process(self, source, depth=0):
        if depth >= self.max_depth:
            return self._beautify(source), 'max_depth', 'Max recursion depth reached'

        current = source
        for t in self.static_transformers:
            try:
                current = t.transform(current)
            except Exception:
                pass

        if current != source and self._looks_decoded(current):
            return self._beautify(current), 'static_lift', 'Static lift succeeded'

        layers, captures = execute_sandbox(current, timeout=30)

        for layer in layers:
            if isinstance(layer, bytes):
                if layer[:4] == b'\x1bLua':
                    lifted = self._lift_bc(layer)
                    if lifted:
                        return self._beautify(lifted), 'sandbox_bytecode', 'Bytecode dump lifted'
            elif isinstance(layer, str):
                if len(layer) > 50:
                    return self.process(layer, depth + 1)

        for cap in captures:
            if isinstance(cap, str) and cap.startswith('\x1bLua'):
                lifted = self._lift_bc(cap.encode('latin-1'))
                if lifted:
                    return self._beautify(lifted), 'capture_bytecode', 'Captured bytecode lifted'
            if isinstance(cap, str) and len(cap) > 100 and self._looks_decoded(cap):
                return self._beautify(cap), 'capture_string', 'Captured string payload'

        return self._beautify(current), 'done', 'No further layers found'

    def _lift_bc(self, bc):
        try:
            func = Lua51Parser(bc).parse_function()
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
            openers = ('if ', 'for ', 'while ', 'repeat', 'function ', 'local function ', 'do\n', 'do ')
            closers = ('end', 'else', 'elseif ', 'until ')
            for raw in code.split('\n'):
                line = raw.strip()
                if not line:
                    continue
                if any(line.startswith(c) for c in closers):
                    ind = max(0, ind - 1)
                out.append('    ' * ind + line)
                if any(line.startswith(o) for o in openers) and not line.endswith('end'):
                    ind += 1
            return '\n'.join(out)
