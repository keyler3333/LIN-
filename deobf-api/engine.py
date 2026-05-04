from transformers import Lua51Parser, Lua51Decompiler, EscapeSequenceTransformer, MathTransformer, HexNameRenamer
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
            return source, 'max_depth', 'Max recursion depth reached'

        current = source
        for t in self.cleaners:
            try:
                current = t.transform(current)
            except:
                pass

        layers, captures, diag = execute_sandbox(current, timeout=90)

        for cap in captures:
            for offset in range(len(cap)):
                if cap[offset:offset+4] == '\x1bLua':
                    if offset + 5 <= len(cap) and ord(cap[offset+4]) == 0x51:
                        bc = cap[offset:].encode('latin-1')
                        lifted = self._lift_bc(bc)
                        if lifted:
                            return self._beautify(lifted), 'rawset_bytcode', 'Bytecode captured via rawset hook'

        for item in layers:
            if isinstance(item, bytes) and item.startswith(b'\x1bLua'):
                lifted = self._lift_bc(item)
                if lifted:
                    return self._beautify(lifted), 'sandbox_bytecode', 'Decompiled from bytecode dump'

        best = ''
        for cap in captures:
            if len(cap) > len(best) and ('function' in cap or 'local' in cap or 'print' in cap):
                best = cap

        if best:
            return self._beautify(best), 'rawset_string', 'Readable source captured via rawset'

        for layer in layers:
            if isinstance(layer, str) and len(layer) > 50:
                if 'function' in layer or 'local' in layer or 'print' in layer:
                    return self._beautify(layer), 'sandbox_layer', 'Layer captured'

        reason = diag if diag else 'Sandbox executed but no bytecode or source was captured.'
        return source, 'unable', reason

    def _lift_bc(self, bc):
        try:
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
