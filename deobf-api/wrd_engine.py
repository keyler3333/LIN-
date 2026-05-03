import os
import tempfile
import subprocess
import shutil
from deobfuscator_core import Deobfuscator
from pattern_scanner import PatternScanner
from execution_engine import ExecutionEngine


class WRDPipeline:
    def __init__(self):
        self.deobfuscator = Deobfuscator()
        self.scanner = PatternScanner()
        self.executor = ExecutionEngine(max_time=15)
        self.lua_bin = shutil.which('lua5.1') or shutil.which('lua51') or shutil.which('lua') or 'lua'
        self.runtime_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sandbox_runtime.lua')

    def run(self, code):
        result = self._static_extract(code)
        if result:
            return result

        result = self._sandbox_extract(code)
        if result:
            return result

        return code

    def _static_extract(self, source):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as tmp:
            tmp.write(source)
            tmp_path = tmp.name

        try:
            analysis = self.deobfuscator.analyze_script(tmp_path)
            strings = analysis.get('decrypted_strings', [])
            for s in strings:
                if len(s) > 50 and ('function' in s or 'local' in s):
                    return s
            joined = ''.join(strings)
            if len(joined) > 100 and ('function' in joined or 'local' in joined):
                return joined
        except Exception:
            pass
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        return None

    def _sandbox_extract(self, source):
        if not os.path.isfile(self.runtime_path):
            return None

        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, 'input.lua')
            drv = os.path.join(d, 'driver.lua')

            with open(inp, 'w', encoding='utf-8') as f:
                f.write(source)

            with open(self.runtime_path, 'r', encoding='utf-8') as f:
                runtime = f.read()

            driver = runtime.replace('"OUTDIR_PLACEHOLDER"', f'"{d.replace(chr(92), "/")}"')\
                            .replace('"INPATH_PLACEHOLDER"', f'"{inp.replace(chr(92), "/")}"')

            with open(drv, 'w', encoding='utf-8') as f:
                f.write(driver)

            try:
                subprocess.run([self.lua_bin, drv], capture_output=True, text=True,
                               timeout=20, cwd=d, env=os.environ.copy())
            except Exception:
                pass

            captures = self._read_captures(d)
            for tag in ('LOADSTRING_PAYLOAD', 'BASE64', 'CONCAT_RESULT'):
                if tag in captures:
                    payload = captures[tag].strip()
                    if len(payload) > 20 and ('function' in payload or 'local' in payload):
                        return payload

        return None

    def _read_captures(self, d):
        cap_path = os.path.join(d, 'cap.txt')
        if not os.path.exists(cap_path):
            return {}

        captures = {}
        with open(cap_path, encoding='utf-8', errors='replace') as f:
            current_tag = None
            current_data = []
            for line in f:
                line = line.rstrip('\n')
                if line.startswith('--- ') and line.endswith(' ---'):
                    if current_tag and current_data:
                        captures[current_tag] = '\n'.join(current_data)
                    current_tag = line[4:-4].strip()
                    current_data = []
                elif line == '---SEP---':
                    if current_tag and current_data:
                        captures[current_tag] = '\n'.join(current_data)
                    current_tag = None
                    current_data = []
                else:
                    current_data.append(line)
            if current_tag and current_data:
                captures[current_tag] = '\n'.join(current_data)

        return captures
