import re

class ObfuscationScanner:
    def __init__(self):
        self.patterns = {
            'luraph': [r'return\s*\(function\s*\(\.\.\.\)', r'loadstring\s*\(\s*\(function', r'Luraph'],
            'ironbrew2': [r'while\s+true\s+do\s+local\s+\w+\s*=\s*\w+\[\w+\]', r'local\s+\w+,\s*\w+,\s*\w+\s*=\s*\w+\s*&'],
            'ironbrew1': [r'bit\.bxor', r'getfenv\s*\(\s*\)\s*\['],
            'moonsec_vm': [r'if\s+\w+\s*<\s*\d+\s*[+\-]\s*\(?-\d+\)?\s*then', r'while\s+\w+\s+do\s*\n\s*if\s+\w+\s*<'],
            'moonsec': [r'local\s+\w+\s*=\s*\{[\d\s,]{20,}\}', r'_moon\s*=\s*function', r'MoonSec'],
            'wearedevs': [r'show_\w+\s*=\s*function', r'https?://wearedevs\.net', r'v1\.\d+\.\d+.*wearedevs'],
            'prometheus': [r'Prometheus', r'number_to_bytes'],
            'psu': [r'PSU_Obfuscator', r'local\s+\w+\s*=\s*\{\s*\["\w+"\]\s*=\s*function'],
        }

    def analyze(self, text):
        scores = {}
        for name, pats in self.patterns.items():
            score = sum(1 for p in pats if re.search(p, text, re.IGNORECASE))
            if score > 0:
                scores[name] = score
        if not scores:
            return 'generic', 'sandbox_peel'
        best_match = max(scores, key=lambda k: scores[k])
        method = 'dynamic' if best_match in ('luraph', 'ironbrew2', 'moonsec_vm', 'psu') else 'static_peel'
        return best_match, method
