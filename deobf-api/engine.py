from transformers import (
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
            return self._beautify(source), 'max_depth', 'Max recursion depth reached'

        current = source
        for t in self.cleaners:
            try:
                current = t.transform(current)
            except:
                pass

        if current != source and self._looks_decoded(current):
            return self._beautify(current), 'static_lift', 'Static lift succeeded'

        layers, captures = execute_sandbox(source, timeout=30)

        best = ''
        for cap in captures:
            if len(cap) > len(best) and ('function' in cap or 'local' in cap):
                best = cap

        if best:
            return self._beautify(best), 'sandbox_capture', 'Decrypted payload captured from sandbox'

        for layer in layers:
            if isinstance(layer, str) and len(layer) > 50:
                best = layer
                break

        if best:
            return self._beautify(best), 'layer', 'Layer captured'

        return self._beautify(current), 'unable', 'No decrypted payload found – static lift and sandbox both failed.'

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
