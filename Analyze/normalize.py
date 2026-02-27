import base64
import gzip
import re
import urllib.parse
from collections import deque


class DataNormalizer:
    """
    Multi-layer Encoding Detection & Decoding Engine
    - BFS exploration
    - Heuristic-based decoding
    - Depth bounded
    - Loop safe
    - Deterministic output
    """

    BASE64_REGEX = re.compile(r'^[A-Za-z0-9+/=]+$')
    HEX_REGEX = re.compile(r'^[0-9a-fA-F]+$')

    def __init__(self, value: str, max_depth, max_candidates: int = 50):
        self.original = value.strip()
        self.max_depth = max_depth
        self.max_candidates = max_candidates



    def normalize(self):
        seen = set()
        results = set()

        queue = deque()
        queue.append((self.original, 0))

        while queue:
            current, depth = queue.popleft()

            if current in seen:
                continue

            seen.add(current)
            results.add(current)

            if depth >= self.max_depth:
                continue

            if len(results) >= self.max_candidates:
                break

            for new_value in self._transform(current):
                if new_value and new_value not in seen:
                    queue.append((new_value, depth + 1))

        return sorted(results)

#Decode transform

    def _transform(self, value: str):
        candidates = []

        url_decoded = self._try_url_decode(value)
        if url_decoded:
            candidates.append(url_decoded)

        hex_decoded = self._try_hex_decode(value)
        if hex_decoded:
            candidates.append(hex_decoded)

        b64_decoded = self._try_base64_decode(value)
        if b64_decoded:
            candidates.extend(b64_decoded)

        return candidates

    def _try_url_decode(self, value):
        try:
            decoded = urllib.parse.unquote(value)
            if decoded != value:
                return decoded.strip()
        except:
            pass
        return None

    def _try_hex_decode(self, value):
        if not self._looks_like_hex(value):
            return None

        try:
            decoded_bytes = bytes.fromhex(value)
            decoded = decoded_bytes.decode(errors="ignore")
            if self._is_meaningful(decoded):
                return decoded.strip()
        except:
            pass
        return None

    def _try_base64_decode(self, value):
        if not self._looks_like_base64(value):
            return None

        results = []

        try:
            val = value.strip()
            padding = len(val) % 4
            if padding:
                val += "=" * (4 - padding)

            decoded_bytes = base64.b64decode(val, validate=False)

            if decoded_bytes.startswith(b"\x1f\x8b"):
                try:
                    decompressed = gzip.decompress(decoded_bytes)
                    decoded = decompressed.decode(errors="ignore")
                    if self._is_meaningful(decoded):
                        results.append(decoded.strip())
                except:
                    pass
            else:
                decoded = decoded_bytes.decode(errors="ignore")
                if self._is_meaningful(decoded):
                    results.append(decoded.strip())

        except:
            pass

        return results if results else None

#Filter

    def _looks_like_base64(self, value):
        if len(value) < 12:
            return False
        if not self.BASE64_REGEX.fullmatch(value):
            return False
        return True

    def _looks_like_hex(self, value):
        if len(value) < 8:
            return False
        if len(value) % 2 != 0:
            return False
        if not self.HEX_REGEX.fullmatch(value):
            return False
        return True

    def _is_meaningful(self, value):
        
        if not value:
            return False

        printable = sum(c.isprintable() for c in value)
        ratio = printable / len(value)

        if ratio < 0.7:
            return False

        ascii_char = sum(ord(c) < 128 for c in value)
        ascii_char_ratio  = ascii_char/len(value)
        if ascii_char_ratio < 0.7: return False
        
        if any(x in value for x in ["O:", "rO0", "__VIEWSTATE", "{", ":", ";"]):
            return True

        return ratio > 0.85