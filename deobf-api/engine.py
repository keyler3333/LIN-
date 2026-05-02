from transformers import *
from sandbox import execute_sandbox


class DeobfEngine:
    def __init__(self):
        self.cleaners = [
            EscapeSequenceTransformer(),
            MathTransformer(),
        ]
        self.lifter = WeAreDevsLifter()
        self.renamer = HexNameRenamer()

    def process(self, source):
        current = source
        for t in self.cleaners:
            try:
                current = t.transform(current)
            except:
                pass

        lifted = self.lifter.transform(current)
        if lifted is not None and lifted != current and 'function' in lifted:
            renamed = self.renamer.transform(lifted)
            return self._beautify(renamed), 'wearedevs', 'Static bytecode lift successful'

        layers, captures = execute_sandbox(current, use_emulator=False)

        for layer in layers:
            if isinstance(layer, bytes) and layer.startswith(b'\x1bLua'):
                lifted = self._lift_bytecode(layer)
                if lifted:
                    renamed = self.renamer.transform(lifted)
                    return self._beautify(renamed), 'wearedevs', 'Sandbox dump lifted'
            if isinstance(layer, str) and layer.startswith('\x1bLua'):
                lifted = self._lift_bytecode(layer.encode('latin-1'))
                if lifted:
                    renamed = self.renamer.transform(lifted)
                    return self._beautify(renamed), 'wearedevs', 'Sandbox layer lifted'
            if isinstance(layer, str) and len(layer) > 100 and 'function' in layer:
                return self._beautify(layer), 'wearedevs', 'Sandbox extracted layer'

        for cap in captures:
            if cap.startswith('\x1bLua') and len(cap) > 50:
                lifted = self._lift_bytecode(cap.encode('latin-1'))
                if lifted:
                    renamed = self.renamer.transform(lifted)
                    return self._beautify(renamed), 'wearedevs', 'Captured bytecode lifted'
            if len(cap) > 100 and 'function' in cap:
                return self._beautify(cap), 'wearedevs', 'Sandbox captured payload'

        return self._beautify(current), 'wearedevs', 'No decrypted payload found'

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
