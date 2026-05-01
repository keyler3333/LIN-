from scanner import WeAreDevsScanner
from transformers import WeAreDevsLifter, StaticCleanup
from sandbox import execute_sandbox

class WeAreDevsEngine:
    def __init__(self):
        self.scanner = WeAreDevsScanner()
        self.lifter = WeAreDevsLifter()
        self.cleaner = StaticCleanup()

    def process(self, source):
        if not self.scanner.is_wearedevs(source):
            return self._beautify(source), "not_wearedevs", "Not a WeAreDevs script"

        lifted = self.lifter.lift(source)
        if lifted:
            return self._beautify(lifted), "wearedevs_lift", "Successfully lifted"

        cleaned = self.cleaner.transform(source)
        layers, captures = execute_sandbox(cleaned, use_emulator=False)
        if layers:
            payload = max(layers, key=len)
            return self._beautify(payload), "sandbox_peel", "Sandbox extracted layer"
        if captures:
            for cap in captures:
                if cap.startswith('\x1bLua'):
                    return "-- [Bytecode Recovered]\n-- Use a bytecode lifter to read.\n", "raw_bytecode", "Bytecode found but not liftable"
                if len(cap) > 100 and "function" in cap:
                    return self._beautify(cap), "captured", "Sandbox captured payload"

        return self._beautify(cleaned), "fallback", "Cleanup only"

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
