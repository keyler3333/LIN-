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
            if isinstance(layer, bytes) and layer[:4] == b'\x1bLua':
                lifted = self._lift_bc(layer)
                if lifted:
                    return self._beautify(lifted), 'sandbox_bytecode', 'Bytecode dump lifted'
            if isinstance(layer, str) and len(layer) > 50:
                return self.process(layer, depth + 1)

        best = self._best_capture(captures)
        if best:
            if isinstance(best, str) and best.startswith('\x1bLua'):
                lifted = self._lift_bc(best.encode('latin-1'))
                if lifted:
                    return self._beautify(lifted), 'capture_bytecode', 'Captured bytecode lifted'
            return self._beautify(best), 'capture_string', 'VM output captured'

        return self._beautify(current), 'done', 'No payload extracted'

    def _best_capture(self, captures):
        if not captures:
            return None
        candidates = []
        for cap in captures:
            if not isinstance(cap, str) or len(cap) < 30:
                continue
            score = self._lua_score(cap)
            if score > 0:
                candidates.append((score, len(cap), cap))
        if not candidates:
            scored = [(len(c), c) for c in captures if isinstance(c, str) and len(c) > 50]
            if scored:
                return max(scored)[1]
            return None
        candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
        return candidates[0][2]

    @staticmethod
    def _lua_score(code):
        if not code or len(code) < 20:
            return 0
        lines = code.split('\n')
        max_line = max((len(l) for l in lines), default=0)
        if max_line > 2000:
            return 0
        score = 0
        keywords = ('function', 'local', 'return', 'end', 'if', 'then',
                    'for', 'while', 'do', 'repeat', 'until', 'not',
                    'and', 'or', 'nil', 'true', 'false')
        code_lower = code.lower()
        for kw in keywords:
            score += code_lower.count(kw) * 2
        alpha = sum(1 for ch in code if ch.isalpha() or ch in ' \t\n_.,;(){}[]=')
        ratio = alpha / max(len(code), 1)
        if ratio > 0.25:
            score += int(ratio * 100)
        if max_line < 300:
            score += 10
        return score

    @staticmethod
    def _looks_decoded(code):
        if not code or len(code) < 20:
            return False
        lines = code.split('\n')
        if max((len(l) for l in lines), default=0) > 500:
            return False
        alpha = sum(1 for ch in code if ch.isalpha() or ch in ' \t\n_.,;(){}[]=')
        return (alpha / max(len(code), 1)) > 0.25

    def _lift_bc(self, bc):
        try:
            func = Lua51Parser(bc).parse_function()
            return Lua51Decompiler(func).decompile()
        except Exception:
            return None

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
