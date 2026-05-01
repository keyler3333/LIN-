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
