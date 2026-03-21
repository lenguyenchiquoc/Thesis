import base64
import gzip
import re
import urllib.parse
from collections import deque


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

        # Java: chỉ accept raw base64 nếu KHÔNG có decoded version tốt hơn
        # → vẫn mark là serialized để không bỏ sót, nhưng score thấp hơn decoded
        if value.startswith('rO0') or 'ACED' in value.upper():
            return True

        # PHP
        if re.search(r'O:\d+:"[^"]+":\d+:\{', value):
            return True
        if re.search(r'a:\d+:\{', value):
            return True

        # YAML
        if any(ind in value for ind in ['!!', '%YAML', '!<tag:yaml.org']):
            return True

        # Pickle/marshal
        if any(ind in value for ind in ['__class__', '__wakeup', 'pickle', 'marshal']):
            return True

        # Decoded Java binary — class names readable
        if 'java.' in value or 'javax.' in value or 'org.apache' in value:
            return True

        # Generic: nhiều colon + quote → likely serialized structure
        if value.count(':') >= 4 and (value.count('"') + value.count("'")) >= 4:
            return True

        return False
    
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

        # Decoded Java binary score cao hơn raw base64
        if 'java.' in value or 'org.apache' in value:
            score += 10
        if any(kw in value.lower() for kw in
            ['commonscollections', 'templatesimpl', 'gadget',
                'invoketransformer', 'urldns']):
            score += 8

        # PHP object
        if re.search(r'O:\d+:"[^"]+":\d+:\{', value):
            score += 6

        # Generic indicators
        indicators = ['O:', 'rO0', 'ACED', '__class__', '!!', 'pickle']
        score += sum(value.count(ind) for ind in indicators)
        score += value.count(':') * 0.5
        score += value.count('"') * 0.3

        # Penalty: raw base64 không có ý nghĩa readable
        if re.fullmatch(r'[A-Za-z0-9+/=\-_]{20,}', value.strip()):
            score -= 3

        return score