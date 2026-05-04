from sandbox import execute_sandbox


class DeobfEngine:
    def __init__(self):
        self.max_depth = 5

    def process(self, source, depth=0):
        if depth >= self.max_depth:
            return source, 'max_depth', 'Max recursion depth reached'

        layers, captures = execute_sandbox(source, timeout=30)

        for cap in captures:
            if cap.startswith('\x1bLua') and len(cap) > 50:
                lifted = self._lift_bc(cap.encode('latin-1'))
                if lifted:
                    return self._beautify(lifted), 'sandbox', 'Bytecode captured and lifted'
            if len(cap) > 50 and ('function' in cap or 'local' in cap):
                return self._beautify(cap), 'sandbox', 'Decoded string captured'

        for layer in layers:
            if isinstance(layer, bytes) and layer[:4] == b'\x1bLua':
                lifted = self._lift_bc(layer)
                if lifted:
                    return self._beautify(lifted), 'sandbox', 'Bytecode dump lifted'
            if isinstance(layer, str) and len(layer) > 50:
                if 'function' in layer or 'local' in layer:
                    return self._beautify(layer), 'sandbox', 'Decrypted layer captured'

        return source, 'sandbox', 'No payload captured'

    def _lift_bc(self, bc):
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
