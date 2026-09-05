import re

from Utility import signatures

class cleanfilter:

    PREFIX_PATTERNS = [
        r'^(session|PHPSESSID|JSESSIONID|sid|__Host-session|user|auth|token|data|payload)\s*=\s*',
        r'^Bearer\s+',
        r'^[\w-]{1,32}\s*=\s*',
        r'^Cookie:\s*',
        r'^Set-Cookie:\s*',
    ]

    def __init__(self, filter_output):
        self.data = filter_output
    def _clean(self, value:str) -> str:
        if not isinstance(value,str) or not value.strip():
            return value
        cleaned = value.strip()

        # A raw header can bundle several "; "-separated name=value pairs
        # (Cookie per RFC 6265, Content-Disposition per RFC 6266/7578). The
        # interesting one isn't necessarily first — score every segment and
        # keep whichever one actually looks like a serialized payload,
        # instead of blindly assuming position #1. Falls back to the first
        # segment (old behavior) when none of them look suspicious, so a
        # plain single value is unaffected.
        if '; ' in cleaned:
            segments = [s.strip() for s in cleaned.split('; ')]
            suspicious = [s for s in segments if signatures.looks_like_serialized(s)]
            cleaned = suspicious[0] if suspicious else segments[0]

        # Stripping one wrapper can expose another underneath it (e.g.
        # "Cookie: session=<payload>" — stripping "Cookie: " only reveals
        # "session=" *after* that pattern was already checked). Keep
        # re-running the full pattern list until a full pass changes
        # nothing, instead of a single pass, so stacked wrappers are fully
        # unwrapped regardless of order. Guaranteed to terminate: every
        # pattern that matches strictly shortens `cleaned`, and the loop
        # stops as soon as one full pass makes no change.
        changed = True
        while changed:
            changed = False
            for pattern in self.PREFIX_PATTERNS:
                stripped = re.sub(pattern, '', cleaned, flags=re.IGNORECASE).strip()
                if stripped != cleaned:
                    cleaned = stripped
                    changed = True

        cleaned = cleaned.strip('= \t\n\r;,"')
        return cleaned
    
    def _clean_all(self) -> list[dict]:
        cleaned_vector = []
        for vector in self.data:
            original_value = vector.get('value','')
            clean_value = self._clean(original_value)
            
            new_vector = vector.copy()
            new_vector["original_value"] = original_value
            new_vector["cleaned_value"] = clean_value
            
            cleaned_vector.append(new_vector)
            
        return cleaned_vector
    
    def clean_and_output(self):
        cleaned = self._clean_all()
        print(f"Found {len(cleaned)} cleaned vectors:")
        for i, vec in enumerate(cleaned, 1):
            orig = vec.get('original_value', '')
            cln = vec.get('cleaned_value', '')
            print(f"\n[{i}] Location: {vec.get('location')} | Name: {vec.get('name')}")
            print(f"   Original: {orig}")
            print(f"   Cleaned : {cln}")