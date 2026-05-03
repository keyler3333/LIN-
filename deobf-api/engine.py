from transformers import (
    EscapeSequenceTransformer,
    MathTransformer,
    HexNameRenamer,
)
from sandbox import execute_sandbox


class DeobfEngine:
    def __init__(self):
        self.cleaners = [
            EscapeSequenceTransformer(),
            MathTransformer(),
            HexNameRenamer(),
        ]
        self.max_depth = 5

    def process(self, source, depth=0):
        if depth >= self.max_depth:
            return self._beautify(source), 'max_depth', 'Max recursion depth reached'

        current = source
        for t in self.cleaners:
            try:
                current = t.transform(current)
            except Exception:
                pass

        layers, captures = execute_sandbox(current, timeout=45)

        for layer in layers:
            if isinstance(layer, bytes):
                if layer[:4] == b'\x1bLua':
                    lifted = self._lift_bc(layer)
                    if lifted:
                        return self._beautify(lifted), 'sandbox', 'Bytecode dump lifted'
            elif isinstance(layer, str):
                if len(layer) > 50 and self._looks_decoded(layer):
                    return self._beautify(layer), 'sandbox', 'Decrypted layer captured'

        for cap in captures:
            if isinstance(cap, str) and len(cap) > 100 and self._looks_decoded(cap):
                return self._beautify(cap), 'sandbox', 'Captured payload'

        return self._beautify(current), 'sandbox', 'No decrypted payload found – environment incomplete'

    def _lift_bc(self, bc):
        try:
            from transformers import Lua51Parser, Lua51Decompiler
            parser = Lua51Parser(bc)
            func = parser.parse_function()
            return Lua51Decompiler(func).decompile()
        except Exception:
            return None

    @staticmethod
    def _looks_decoded(code):
        if not code or len(code) < 50:
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
            openers = ('if ', 'for ', 'while ', 'repeat', 'function ', 'local function ')
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
