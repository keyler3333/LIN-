from transformers import *
from sandbox import execute_sandbox

class DeobfEngine:
    def __init__(self):
        self.transformers = [
            EscapeSequenceTransformer(),
            MathTransformer(),
            HexNameRenamer(),
        ]

    def process(self, source):
        current = source
        for t in self.transformers:
            try:
                current = t.transform(current)
            except:
                pass

        layers, captures = execute_sandbox(current, use_emulator=False)

        for layer in layers:
            if layer.startswith('\x1bLua') and len(layer) > 50:
                bc = layer.encode('latin-1', errors='replace') if isinstance(layer, str) else layer
                lifted = self._lift_bytecode(bc)
                if lifted:
                    return self._beautify(lifted), 'wearedevs', 'Bytecode dumped and lifted'
            if len(layer) > 100 and 'function' in layer:
                return self._beautify(layer), 'wearedevs', 'Sandbox extracted layer'

        for cap in captures:
            if cap.startswith('\x1bLua') and len(cap) > 50:
                bc = cap.encode('latin-1', errors='replace') if isinstance(cap, str) else cap
                lifted = self._lift_bytecode(bc)
                if lifted:
                    return self._beautify(lifted), 'wearedevs', 'Captured bytecode lifted'
            if len(cap) > 100 and 'function' in cap:
                return self._beautify(cap), 'wearedevs', 'Sandbox captured payload'

        return self._beautify(current), 'wearedevs', 'Sandbox ran, no decrypted payload found. Check obfuscation version.'

    def _lift_bytecode(self, bc):
        try:
            from transformers import Lua51Parser, Lua51Decompiler
            parser = Lua51Parser(bc)
            func = parser.parse_function()
            return Lua51Decompiler(func).decompile()
        except:
            return None

    def _beautify(self, code):
        try:
            from luaparser import ast
            return ast.to_lua_source(ast.parse(code))
        except:
            out, ind = [], 0
            for line in code.split('\n'):
                line = line.strip()
                if not line:
                    continue
                if any(line.startswith(w) for w in ('end', 'else', 'elseif', 'until', '}', ')')):
                    ind = max(0, ind - 1)
                out.append('    ' * ind + line)
                if any(line.startswith(w) for w in ('if ', 'for ', 'while ', 'repeat', 'function ', 'local function ')) and not line.endswith('end'):
                    ind += 1
            return '\n'.join(out)
