import os
import shutil
import subprocess
import tempfile
import base64
import urllib.request
import asyncio
from transformers import WeAreDevsLifter
from sandbox import execute_sandbox
from errors import (
    logger, timer, validate_input,
    Stage, StageResult, PipelineResult,
    InputError, StaticLiftError, SandboxError, SandboxTimeoutError,
    CaptureError, DecompileError, LuneNotInstalledError, UnluacNotFoundError
)
from lune_executor import execute_and_capture

UNLUAC_JAR_URL = "https://github.com/HansWessels/unluac/releases/download/v2023.10.24/unluac.jar"
UNLUAC_LOCAL_PATH = os.environ.get('UNLUAC_PATH') or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'unluac.jar'
)

class DeobfEngine:
    def __init__(self):
        self.lifter = WeAreDevsLifter()
        self.unluac_path = UNLUAC_LOCAL_PATH

    async def process(self, raw_source):
        stages = []

        try:
            source = validate_input(raw_source)
        except InputError as e:
            return PipelineResult(success=False, stages=stages, error=e)

        logger.info(f"Pipeline started - input size: {len(source)} chars")

        with timer() as t:
            try:
                lifted = self.lifter.transform(source)
                if lifted and lifted != source and self._looks_decoded(lifted):
                    sr = StageResult(
                        stage=Stage.STATIC_LIFT, success=True,
                        output=lifted, duration_ms=t.ms,
                        note="Pattern matched and reversed"
                    )
                    stages.append(sr)
                    logger.info(f"Static lift succeeded in {t.ms:.0f}ms")
                    return PipelineResult(success=True, output=self._beautify(lifted), stages=stages)
                else:
                    stages.append(StageResult(
                        stage=Stage.STATIC_LIFT, success=False,
                        duration_ms=t.ms, note="No pattern matched"
                    ))
            except Exception as e:
                stages.append(StageResult(
                    stage=Stage.STATIC_LIFT, success=False,
                    error=StaticLiftError(str(e)), duration_ms=t.ms,
                    note=f"Transformer crashed: {type(e).__name__}"
                ))
                logger.warning(f"Static lift crashed: {e!r}")

        decoded_chunks = self._run_decode_pipeline(source)
        extracted_bc = None
        if decoded_chunks:
            extracted_bc = next((c for c in decoded_chunks if self._is_lua51_bytecode(c)), None)
            if not extracted_bc:
                full = b''.join(decoded_chunks)
                idx = full.find(b'\x1bLua')
                if idx != -1 and idx + 5 <= len(full) and full[idx+4] == 0x51:
                    extracted_bc = full[idx:]

        raw_bytes = raw_source if isinstance(raw_source, bytes) else raw_source.encode("latin-1")
        if raw_bytes[:4] == b"\x1bLua" and not extracted_bc:
            extracted_bc = raw_bytes

        if extracted_bc:
            with timer() as t:
                decompiled, decompile_err = self._run_unluac(extracted_bc)
            if decompiled and self._looks_decoded(decompiled):
                stages.append(StageResult(
                    stage=Stage.DECOMPILE, success=True,
                    output=decompiled, duration_ms=t.ms,
                    note="Bytecode decompiled"
                ))
                return PipelineResult(success=True, output=self._beautify(decompiled), stages=stages)
            if decompiled:
                stages.append(StageResult(
                    stage=Stage.DECOMPILE, success=True,
                    output=decompiled, duration_ms=t.ms,
                    note="Decompiled (low confidence)"
                ))
                return PipelineResult(success=True, output=decompiled, stages=stages)
            stages.append(StageResult(
                stage=Stage.DECOMPILE, success=False,
                error=decompile_err, duration_ms=t.ms,
                note="unluac failed"
            ))
            bc_b64 = base64.b64encode(extracted_bc).decode('ascii')
            hint = "Bytecode extracted but decompilation failed."
            return PipelineResult(success=False, raw_bytecode=extracted_bc, stages=stages, error=DecompileError("unluac", "decompilation failed"))

        logger.info("Attempting dynamic execution via Lune")
        async with timer() as t:
            try:
                captured = await execute_and_capture(source)
            except RuntimeError as e:
                stages.append(StageResult(
                    stage=Stage.DYNAMIC_EXEC, success=False,
                    error=LuneNotInstalledError(), duration_ms=t.ms,
                    note="Lune not found"
                ))
                logger.error(f"Lune not installed: {e}")
                return PipelineResult(success=False, stages=stages, error=LuneNotInstalledError())

        if captured:
            stages.append(StageResult(
                stage=Stage.DYNAMIC_EXEC, success=True,
                output=captured, duration_ms=t.ms,
                note=f"Captured {len(captured)} bytes"
            ))
            logger.info(f"Captured {len(captured)} bytes in {t.ms:.0f}ms")

            with timer() as t:
                decompiled, decompile_err = self._run_unluac(captured)
            if decompiled and self._looks_decoded(decompiled):
                stages.append(StageResult(
                    stage=Stage.DECOMPILE, success=True,
                    output=decompiled, duration_ms=t.ms,
                    note="Captured bytecode decompiled"
                ))
                return PipelineResult(success=True, output=self._beautify(decompiled), stages=stages)
            stages.append(StageResult(
                stage=Stage.DECOMPILE, success=False,
                error=decompile_err, duration_ms=t.ms,
                note="unluac failed on captured bytecode"
            ))
            return PipelineResult(success=False, raw_bytecode=captured, stages=stages, error=decompile_err)

        err = CaptureError("loadstring was never called")
        stages.append(StageResult(
            stage=Stage.DYNAMIC_EXEC, success=False,
            error=err, duration_ms=t.ms,
            note="Script ran but hook never fired"
        ))
        logger.warning("Dynamic execution completed but nothing was captured")

        layers, caps, diag = execute_sandbox(source, timeout=30)
        all_text = [t for t in caps if isinstance(t, str) and len(t) > 20]
        all_text += [t for t in layers if isinstance(t, str) and len(t) > 20]
        all_text.sort(key=len, reverse=True)

        best = ''
        for text in all_text:
            if len(text) > len(best) and self._looks_decoded(text):
                best = text
        if best:
            stages.append(StageResult(
                stage=Stage.FALLBACK, success=True,
                output=best, duration_ms=0,
                note="Sandbox string capture"
            ))
            return PipelineResult(success=True, output=self._beautify(best), stages=stages)

        return PipelineResult(success=False, stages=stages, error=err)

    def _run_decode_pipeline(self, source):
        cmap = self.lifter._build_char_map(source)
        if not cmap or len(cmap) < 60:
            return []
        strings = self.lifter._extract_n_strings(source)
        if not strings:
            return []
        pairs = self.lifter._extract_shuffle_pairs(source)
        working = list(strings)
        if pairs and len(pairs) == 3:
            for a, b in pairs:
                lo, hi = a - 1, b - 1
                if 0 <= lo < len(working) and 0 <= hi < len(working) and lo < hi:
                    working[lo:hi+1] = working[lo:hi+1][::-1]
        decoded = []
        for s in working:
            buf = self.lifter._decode_b64(s, cmap)
            if buf:
                decoded.append(buf)
        return decoded

    @staticmethod
    def _is_lua51_bytecode(data):
        return len(data) >= 12 and data[:4] == b'\x1bLua' and data[4] == 0x51

    def _run_unluac(self, bytecode):
        if not os.path.isfile(self.unluac_path):
            self._ensure_unluac_jar()
        if not os.path.isfile(self.unluac_path):
            return None, UnluacNotFoundError()
        java_bin = shutil.which('java')
        if not java_bin:
            return None, DecompileError("unluac", "java not found")
        try:
            with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
                tmp.write(bytecode)
                tmp_path = tmp.name
            result = subprocess.run(
                [java_bin, '-jar', self.unluac_path, tmp_path],
                capture_output=True, text=True, timeout=30
            )
            os.unlink(tmp_path)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout, None
            return None, DecompileError("unluac", result.stderr)
        except subprocess.TimeoutExpired:
            return None, DecompileError("unluac", "timeout after 30s")
        except Exception as e:
            return None, DecompileError("unluac", str(e))

    def _ensure_unluac_jar(self):
        try:
            os.makedirs(os.path.dirname(self.unluac_path), exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, self.unluac_path)
        except:
            pass

    @staticmethod
    def _looks_decoded(code):
        if not code or len(code) < 50:
            return False
        lines = code.split('\n')
        if max((len(l) for l in lines), default=0) > 500:
            return False
        keywords = ['function', 'local', 'end', 'if', 'then', 'else', 'for', 'while', 'do', 'return', 'print']
        kw_count = sum(1 for kw in keywords if kw in code)
        if kw_count < 3:
            return False
        alpha = sum(1 for ch in code if ch.isalpha() or ch in ' \t\n_.,;(){}[]=')
        return (alpha / max(len(code), 1)) > 0.2

    def _beautify(self, code):
        try:
            from luaparser import ast as lua_ast
            return lua_ast.to_lua_source(lua_ast.parse(code))
        except:
            out, ind = [], 0
            for raw in code.split('\n'):
                line = raw.strip()
                if not line:
                    continue
                if any(line.startswith(w) for w in ('end', 'else', 'elseif', 'until', '}', ')')):
                    ind = max(0, ind - 1)
                if any(line.startswith(w) for w in ('repeat', 'do')):
                    ind += 1
                out.append('    ' * ind + line)
                if any(line.startswith(w) for w in ('if ', 'for ', 'while ', 'function ', 'local function ')) and not line.endswith('end'):
                    ind += 1
            return '\n'.join(out)
