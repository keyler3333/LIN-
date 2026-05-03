import re


class WeAreDevsScanner:
    def is_wearedevs(self, text):
        patterns = [
            r'local\s+N\s*=\s*\{',
            r'local\s+b\s*=\s*\{',
            r'getfenv\s*\(\s*\)',
            r'string\.reverse',
            r'https?://wearedevs\.net',
            r'v1\.\d+\.\d+.*wearedevs',
            r'show_\w+\s*=\s*function',
        ]
        score = sum(1 for p in patterns if re.search(p, text, re.IGNORECASE))
        return score >= 2


class ObfuscationScanner:
    STATIC_PATTERNS = {
        'wearedevs': [
            r'local\s+N\s*=\s*\{',
            r'\["\."\]\s*=\s*-?\d+',
            r'string\.reverse\s*\(',
            r'getfenv\s*\(\s*\)',
        ],
        'luaobfuscator': [
            r'local\s+[A-Z]{2,}\s*=\s*\{',
            r'LuaObfuscator',
            r'VM\s*=\s*\{',
        ],
        'luraph': [
            r'Luraph',
            r'local\s+\w+\s*=\s*\{\s*\d{3,}',
            r'0x[0-9a-fA-F]{4,}\s*,\s*0x',
        ],
        'ironbrew': [
            r'IronBrew',
            r'local\s+\w+\s*=\s*"\d{5,}',
        ],
        'generic_vm': [
            r'loadstring\s*\(',
            r'string\.char\s*\(',
            r'table\.concat\s*\(',
        ],
    }

    DYNAMIC_OBFUSCATORS = {'luaobfuscator', 'luraph', 'ironbrew', 'generic_vm'}

    def analyze(self, code):
        scores = {}
        for name, patterns in self.STATIC_PATTERNS.items():
            hit = sum(1 for p in patterns if re.search(p, code, re.IGNORECASE | re.DOTALL))
            if hit:
                scores[name] = hit

        if not scores:
            return 'unknown', 'static'

        best = max(scores, key=scores.get)
        method = 'dynamic' if best in self.DYNAMIC_OBFUSCATORS else 'static'
        return best, method
