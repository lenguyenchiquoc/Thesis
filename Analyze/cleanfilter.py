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

        if '; ' in cleaned:
            segments = [s.strip() for s in cleaned.split('; ')]
            suspicious = [s for s in segments if signatures.looks_like_serialized(s)]
            cleaned = suspicious[0] if suspicious else segments[0]

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