from scanner import ObfuscationScanner
from transformers import MathTransformer, CipherMapTransformer, EscapeSequenceTransformer
from sandbox import execute_sandbox

class DeobfEngine:
    def __init__(self):
        self.scanner = ObfuscationScanner()
        self.transformers = [
            EscapeSequenceTransformer(),
            MathTransformer(),
            CipherMapTransformer()
        ]
        self.max_depth = 5

    def process(self, source, depth=0):
        if depth >= self.max_depth:
            return self._beautify(source), "max_depth", "Max recursion depth reached"

        current_code = source
        for t in self.transformers:
            current_code = t.transform(current_code)

        obf_type, method = self.scanner.analyze(current_code)

        if len(current_code) > 500 and ('function(' in current_code or 'local' in current_code) and depth > 0:
            if obf_type == 'generic':
                return self._beautify(current_code), obf_type, "Static Payload Recovered"

        use_emu = (method == 'dynamic')
        layers, captures = execute_sandbox(current_code, use_emulator=use_emu)

        if layers:
            payload = max(layers, key=len)
            return self.process(payload, depth + 1)

        if captures:
            for cap in captures:
                if cap.startswith('\x1bLua'):
                    return "-- [Bytecode Recovered]\n-- Use a bytecode lifter to read.\n", obf_type, "Raw Bytecode Found"
                if len(cap) > len(source) * 0.4 and "function" in cap:
                    return self._beautify(cap), obf_type, "Payload recovered from VM Memory"

        return self._beautify(current_code), obf_type, "Analysis Complete"

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
