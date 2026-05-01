from transformers import (
    WeAreDevsLifter,
    EscapeSequenceTransformer,
    MathTransformer,
    HexNameRenamer
)
from sandbox import execute_sandbox

class DeobfEngine:
    def __init__(self):
        self.transformers = [
            EscapeSequenceTransformer(),
            MathTransformer(),
            WeAreDevsLifter(),
            HexNameRenamer()
        ]
        self.max_depth = 5

    def process(self, source, depth=0):
        if depth >= self.max_depth:
            return self._beautify(source), "max_depth", "Max recursion depth reached"

        current_code = source
        for t in self.transformers:
            current_code = t.transform(current_code)

        if depth > 0 and len(current_code) > 200 and ('function(' in current_code or 'local' in current_code):
            return self._beautify(current_code), "lifted", "Static lift succeeded"

        layers, captures = execute_sandbox(current_code, use_emulator=False)
        if layers:
            payload = max(layers, key=len)
            return self.process(payload, depth + 1)
        if captures:
            for cap in captures:
                if len(cap) > 100 and "function" in cap:
                    return self._beautify(cap), "captured", "Sandbox extracted payload"

        return self._beautify(current_code), "done", "Analysis complete"

    def _beautify(self, code):
        try:
            from luaparser import ast
            return ast.to_lua_source(ast.parse(code))
        except Exception:
            out, ind = [], 0
            for line in code.split('\n'):
                line = line.strip()
                if not line:
                    continue
                if line.startswith(('end', 'else', 'elseif', 'until', '}', ')')):
                    ind = max(0, ind - 1)
                out.append('    ' * ind + line)
                if line.startswith(('if', 'for', 'while', 'repeat', 'function', 'local function')) and not line.endswith('end'):
                    ind += 1
            return '\n'.join(out)
