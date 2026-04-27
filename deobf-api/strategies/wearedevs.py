from .base import BaseStrategy
import re

class WeAreDevsStrategy(BaseStrategy):
    name = "wearedevs"
    def detect(self, source):
        return bool(re.search(r'show_\w+\s*=\s*function', source))
    def deobfuscate(self, source, pipeline):
        from pipeline import deep_deobfuscate
        return deep_deobfuscate(source, force_trace=True)
