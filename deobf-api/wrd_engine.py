import os
import tempfile
import subprocess
import shutil

class SandboxExtractor:
    def __init__(self):
        self.lua_bin = shutil.which('lua5.1') or shutil.which('lua51') or shutil.which('lua') or 'lua'
        self.runtime_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sandbox_runtime.lua')

    def extract(self, source, timeout=90):
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
                               timeout=timeout, cwd=d, env=os.environ.copy())
            except:
                pass
            cap_path = os.path.join(d, 'cap.txt')
            if not os.path.exists(cap_path):
                return None
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
            for tag in ('LOADSTRING_PAYLOAD', 'CONCAT_RESULT'):
                if tag in captures:
                    payload = captures[tag].strip()
                    if len(payload) > 20:
                        return payload
            return None


class WRDPipeline:
    def __init__(self):
        self.sandbox = SandboxExtractor()

    def run(self, code):
        result = self.sandbox.extract(code, timeout=90)
        if result:
            return result
        return code
