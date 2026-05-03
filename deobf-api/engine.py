from transformers import (
    EscapeSequenceTransformer,
    MathTransformer,
    HexNameRenamer,
    WeAreDevsLifter,
    Lua51Parser,
    Lua51Decompiler,
)
from sandbox import execute_sandbox

_DIAG_PREFIXES = ('__SANDBOX_ERROR__', '__SANDBOX_DIAG__', '__LUA_STDERR__')


class StaticPipeline:
    def __init__(self):
        self.transformers = [
            EscapeSequenceTransformer(),
            MathTransformer(),
            WeAreDevsLifter(),
            HexNameRenamer(),
        ]

    def run(self, source):
        current = source
        changed = False
        for t in self.transformers:
            try:
                result = t.transform(current)
                if result != current:
                    changed = True
                current = result
            except Exception:
                pass
        return current, changed


class SandboxLoop:
    def __init__(self, max_depth=5):
        self.max_depth = max_depth

    def run(self, source):
        all_layers   = []
        all_captures = []
        current      = source
        depth        = 0
        while depth < self.max_depth:
            layers, captures = execute_sandbox(current, timeout=35)
            all_layers.extend(layers)
            all_captures.extend(captures)
            best_layer = self._best_next_layer(layers)
            if best_layer is None:
                break
            if isinstance(best_layer, bytes):
                break
            if best_layer == current:
                break
            current = best_layer
            depth  += 1
        return all_layers, all_captures

    def _best_next_layer(self, layers):
        if not layers:
            return None
        for layer in layers:
            if isinstance(layer, bytes) and layer[:4] == b'\x1bLua':
                return layer
        str_layers = [l for l in layers if isinstance(l, str) and len(l) > 50]
        if not str_layers:
            return None
        return max(str_layers, key=len)


class Ranker:
    LUA_KEYWORDS = (
        'function', 'local', 'return', 'end', 'if', 'then',
        'for', 'while', 'do', 'repeat', 'until', 'not',
        'and', 'or', 'nil', 'true', 'false', 'else', 'elseif',
        'in', 'break',
    )

    def rank(self, candidates):
        scored = []
        for c in candidates:
            if not c or not isinstance(c, (str, bytes)):
                continue
            score = self._score(c)
            scored.append((score, len(c) if isinstance(c, str) else 0, c))
        scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
        return [item[2] for item in scored]

    def _score(self, candidate):
        if isinstance(candidate, bytes):
            return 1000 if candidate[:4] == b'\x1bLua' else -1

        code = candidate
        if not code or len(code) < 10:
            return -1
        if any(code.startswith(p) for p in _DIAG_PREFIXES):
            return -1

        lines    = code.split('\n')
        max_line = max((len(l) for l in lines), default=0)
        if max_line > 10000 and code.count('\n') < 5:
            return -1

        score      = 0
        code_lower = code.lower()
        for kw in self.LUA_KEYWORDS:
            score += code_lower.count(kw) * 3

        alpha = sum(1 for ch in code if ch.isalpha() or ch in ' \t\n_.,;(){}[]=')
        score += int((alpha / max(len(code), 1)) * 80)

        if max_line < 200:  score += 20
        elif max_line < 500: score += 10

        if 'function' in code_lower and 'end' in code_lower:
            score += 30
        if code.count('\n') > 3:
            score += 10

        return score


class DeobfEngine:
    def __init__(self):
        self.static  = StaticPipeline()
        self.sandbox = SandboxLoop(max_depth=5)
        self.ranker  = Ranker()

    def process(self, source):
        static_out, changed = self.static.run(source)

        if changed and self._is_clean(static_out):
            return self._beautify(static_out), 'static', 'Static pipeline succeeded'

        all_layers, all_captures = self.sandbox.run(static_out)

        candidates = []

        for layer in all_layers:
            if isinstance(layer, bytes) and layer[:4] == b'\x1bLua':
                lifted = self._lift_bc(layer)
                if lifted:
                    candidates.append(lifted)
            elif isinstance(layer, str) and len(layer) > 20:
                candidates.append(layer)

        for cap in all_captures:
            if isinstance(cap, str):
                if any(cap.startswith(p) for p in _DIAG_PREFIXES):
                    continue
                if cap.startswith('\x1bLua'):
                    lifted = self._lift_bc(cap.encode('latin-1'))
                    if lifted:
                        candidates.append(lifted)
                elif len(cap) > 20:
                    candidates.append(cap)

        if static_out and static_out not in candidates:
            candidates.append(static_out)

        ranked = self.ranker.rank(candidates)

        if ranked:
            best = ranked[0]
            if isinstance(best, bytes):
                lifted = self._lift_bc(best)
                if lifted:
                    return self._beautify(lifted), 'bytecode', 'Bytecode lifted'
            if isinstance(best, str):
                score  = self.ranker._score(best)
                method = 'sandbox' if best != static_out else 'static'
                if score > 0:
                    return self._beautify(best), method, f'Best candidate selected (score: {score})'
                non_src = [c for c in ranked if isinstance(c, str) and c != static_out and len(c) > 20]
                if non_src:
                    pick = max(non_src, key=len)
                    return self._beautify(pick), 'fallback', f'Best available (score: {self.ranker._score(pick)})'
                return self._beautify(best), 'fallback', 'Returning best available output'

        return self._beautify(static_out if changed else source), 'fallback', 'No candidates produced'

    def _is_clean(self, code):
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
            return self._indent_fallback(code)

    @staticmethod
    def _indent_fallback(code):
        out, ind = [], 0
        openers = ('if ', 'for ', 'while ', 'repeat', 'function ', 'local function ', 'do ')
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
            if line.startswith('else') or line.startswith('elseif '):
                ind += 1
        return '\n'.join(out)
