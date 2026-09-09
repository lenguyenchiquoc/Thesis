import base64
import gzip
import re
import urllib.parse
from collections import deque

from Utility import signatures


class DataNormalizer:
    def __init__(self, value:str, max_depth = 12, max_candidate = 40):
        self.data = value.strip()
        self.max_depth = max_depth
        self.max_candidate = max_candidate

    def normalize(self) -> list[str]:
        seen = set()
        queue = deque([(self.data,0)])
        meaningfull_data = []
        all_layer = []
        while queue:
            current, depth = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            all_layer.append(current)
            if self._is_serialized_payload(current):
                meaningfull_data.append(current)
            if depth >= self.max_depth and len(seen) >= self.max_candidate:
                continue
            for next_value in self._generate_decodes(current):
                if next_value and next_value not in seen:
                    queue.append((next_value, depth+1))
        if meaningfull_data:
            meaningfull_data.sort(key = lambda x: (-self._serialized_score(x),abs(len(x)-120),-x.count(':')))
            return list(dict.fromkeys(meaningfull_data))[:2]

        return [self.data]

    def _is_serialized_payload(self, value: str) -> bool:
        if len(value) < 12:
            return False
        return signatures.looks_like_serialized(value)

    def _generate_decodes(self, value: str) -> list[str]:
        results = []
        try:
            ud = urllib.parse.unquote(value)
            if ud != value and ud.strip():
                results.append(ud.strip())
        except:
            pass
        try:
            val = value.replace('-', '+').replace('_', '/').rstrip('=')
            if len(val) % 4 != 0:
                val += '=' * (4 - len(val) % 4)
            if len(val) >= 16:
                decoded_bytes = base64.b64decode(val, validate=False)
                if decoded_bytes.startswith(b'\x1f\x8b'):
                    try:
                        decompressed = gzip.decompress(decoded_bytes)
                        txt = decompressed.decode('utf-8', errors='ignore').strip()
                        if txt:
                            results.append(txt)
                    except:
                        pass
                else:
                    try:
                        txt = decoded_bytes.decode('utf-8', errors='ignore').strip()
                        if txt and len(txt) >= 10:
                            results.append(txt)
                    except:
                        pass
        except:
            pass
        if re.fullmatch(r'^[0-9a-fA-F]+$', value) and len(value) % 2 == 0 and len(value) >= 16:
            try:
                hex_bytes = bytes.fromhex(value)
                txt = hex_bytes.decode('utf-8', errors='ignore').strip()
                if txt:
                    results.append(txt)
            except:
                pass
        return results

    def _serialized_score(self, value: str) -> float:
        score = 0.0

        if 'java.' in value or 'org.apache' in value:
            score += 10
        if any(kw in value.lower() for kw in
            ['commonscollections', 'templatesimpl', 'gadget',
                'invoketransformer', 'urldns']):
            score += 8

        if re.search(r'O:\d+:"[^"]+":\d+:\{', value):
            score += 6

        if any(re.search(p, value) for p in signatures.DOTNET_VIEWSTATE):
            score += 6
        if any(magic in value.encode('utf-8', errors='ignore') for magic in signatures.RUBY_MAGIC_BYTES):
            score += 6
        if any(re.search(p, value, re.IGNORECASE) for p in signatures.DOTNET_PATTERNS):
            score += 4
        if any(re.search(p, value, re.IGNORECASE) for p in signatures.RUBY_PATTERNS):
            score += 4
        if any(re.search(p, value, re.IGNORECASE) for p in signatures.NODEJS_PATTERNS):
            score += 4
        if any(w in value.lower() for w in signatures.WRAPPER_DANGEROUS):
            score += 4

        indicators = ['O:', 'rO0', 'ACED', '__class__', '!!', 'pickle']
        score += sum(value.count(ind) for ind in indicators)
        score += value.count(':') * 0.5
        score += value.count('"') * 0.3

        if re.fullmatch(r'[A-Za-z0-9+/=\-_]{20,}', value.strip()):
            score -= 3

        return score
