import logging
from transformers import MathTransformer, StringTransformer, JunkTransformer, ConstantTableTransformer
from sandbox_runner import run_sandbox

class DeobfEngine:
    def __init__(self):
        self.transformers = [
            MathTransformer(),
            ConstantTableTransformer(),
            StringTransformer(),
            JunkTransformer()
        ]
        self.max_depth = 10

    def process(self, source, depth=0):
        if depth > self.max_depth:
            return source, "max_depth_reached"

        current_code = source
        state_changed = True
        
        while state_changed:
            old_code = current_code
            for transformer in self.transformers:
                current_code = transformer.transform(current_code)
            state_changed = (old_code != current_code)

        if self._is_vm_detected(current_code):
            layers, error = self._run_dynamic_analysis(current_code)
            if layers:
                payload = max(layers, key=len)
                return self.process(payload, depth + 1)

        return current_code, "success"

    def _is_vm_detected(self, code):
        indicators = ["while", "if", "repeat", "getfenv"]
        return all(x in code for x in indicators) and len(code) > 5000

    def _run_dynamic_analysis(self, source):
        return run_sandbox(source)
