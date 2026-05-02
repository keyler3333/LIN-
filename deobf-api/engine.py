import re
from transformers import *
from sandbox import execute_sandbox


class DeobfEngine:
    def __init__(self):
        self.transformers = [
            EscapeSequenceTransformer(),
            MathTransformer(),
            HexNameRenamer(),
        ]
        self.max_depth = 5

    def process(self, source, depth=0):
        if depth >= self.max_depth:
            return self._beautify(source), 'max_depth', 'Max recursion depth reached'

        current = source
        for t in self.transformers:
            try:
                current = t.transform(current)
            except Exception:
                pass

        if self._is_wearedevs(current) or True:  # always true for now
            layers, captures = execute_sandbox(current, use_emulator=False)

            if layers:
                payload = max(layers, key=len)
                return self.process(payload, depth + 1)

            if captures:
                for cap in captures:
                    if cap.startswith('\x1bLua') and len(cap) > 50:
                        bc = cap.encode('latin-1') if isinstance(cap, str) else cap
                        lifted = self._lift_bytecode(bc)
                        if lifted:
                            return self._beautify(lifted), 'sandbox_lift', 'Bytecode dumped and lifted'
                    if len(cap) > 100 and 'function' in cap:
                        return self._beautify(cap), 'captured', 'Sandbox extracted payload'

        return self._beautify(current), 'done', 'Analysis complete'

    @staticmethod
    def _is_wearedevs(code):
        return 'wearedevs' in code.lower() and 'local N={' in code

    def _lift_bytecode(self, bc):
        try:
            from transformers import Lua51Parser, Lua51Decompiler
            parser = Lua51Parser(bc)
            func = parser.parse_function()
            return Lua51Decompiler(func).decompile()
        except Exception:
            return None

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
