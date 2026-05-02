from transformers import (
    WeAreDevsLifter,
    EscapeSequenceTransformer,
    MathTransformer,
    HexNameRenamer,
)
from sandbox import execute_sandbox


class DeobfEngine:
    def __init__(self):
        self.transformers = [
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
        for t in self.transformers:
            try:
                current = t.transform(current)
            except Exception:
                pass

        if current != source and self._looks_decoded(current):
            return self._beautify(current), 'static_lift', 'Static transformer succeeded'

        layers, captures = execute_sandbox(current, use_emulator=False)

        if layers:
            payload = max(layers, key=len)
            return self.process(payload, depth + 1)

        if captures:
            for cap in captures:
                if len(cap) > 100 and self._looks_decoded(cap):
                    return self._beautify(cap), 'captured', 'Sandbox extracted payload'

        return self._beautify(current), 'done', 'Analysis complete'

    @staticmethod
    def _looks_decoded(code):
        if not code or len(code) < 20:
            return False
        lines = code.split('\n')
        if max((len(l) for l in lines), default=0) > 500:
            return False
        letter_chars = sum(1 for ch in code if ch.isalpha() or ch in '(){}[]=.,_:; \t\n')
        return (letter_chars / max(len(code), 1)) > 0.40

    def _beautify(self, code):
        try:
            from luaparser import ast as lua_ast
            return lua_ast.to_lua_source(lua_ast.parse(code))
        except Exception:
            out, ind = [], 0
            openers = ('if ', 'elseif ', 'for ', 'while ', 'repeat',
                       'function ', 'local function ', 'do')
            closers = ('end', 'else', 'elseif ', 'until ', '}', ')')
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
