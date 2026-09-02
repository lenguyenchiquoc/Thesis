import re
import base64

from Utility import signatures


class Fingerprint:

    PHP_STRONG = signatures.PHP_STRONG
    PHP_MEDIUM = signatures.PHP_MEDIUM
    PHP_WEAK = signatures.PHP_WEAK
    PHP_GADGET_CHAINS = signatures.PHP_GADGET_CHAINS

    JAVA_MAGIC_B64 = signatures.JAVA_MAGIC_B64
    JAVA_MAGIC_BYTES = signatures.JAVA_MAGIC_BYTES
    JAVA_GADGET_CHAINS = signatures.JAVA_GADGET_CHAINS

    PICKLE_MAGIC_BYTES = signatures.PICKLE_MAGIC_BYTES
    PICKLE_TEXT_INDICATORS = signatures.PICKLE_TEXT_INDICATORS
    PICKLE_GADGET = signatures.PICKLE_GADGET

    YAML_STRONG = signatures.YAML_STRONG
    YAML_MEDIUM = signatures.YAML_MEDIUM
    YAML_WEAK = signatures.YAML_WEAK

    DOTNET_PATTERNS = signatures.DOTNET_PATTERNS
    DOTNET_VIEWSTATE = signatures.DOTNET_VIEWSTATE

    NODEJS_PATTERNS = signatures.NODEJS_PATTERNS

    RUBY_PATTERNS = signatures.RUBY_PATTERNS
    RUBY_MAGIC_BYTES = signatures.RUBY_MAGIC_BYTES

    WRAPPER_DANGEROUS = signatures.WRAPPER_DANGEROUS
    WRAPPER_MODERATE = signatures.WRAPPER_MODERATE

    GADGET_KEYWORDS = signatures.GADGET_KEYWORDS

    def __init__(self, data_list: list[str]):
        self.data = [str(item).strip() for item in data_list if str(item).strip()]

    def fingerprint_serial(self) -> dict:
        if not self.data:
            return self._unknown_result()

        raw_text   = " ".join(self.data)
        lower_text = raw_text.lower()
        bin_data   = b" ".join(
            item.encode('utf-8', errors='ignore') for item in self.data
        )
        clean_text = lower_text.replace('\x00', ' ').replace('\x05', ' ').replace('\x04', ' ')

        scores = {
            "PHP":           self._detect_php(raw_text, lower_text),
            "Java":          self._detect_java(raw_text, lower_text, bin_data),
            "Python Pickle": self._detect_pickle(raw_text, lower_text, bin_data),
            "YAML":          self._detect_yaml(raw_text, lower_text),
            "DotNet":        self._detect_dotnet(raw_text, lower_text),
            "NodeJS":        self._detect_nodejs(raw_text, lower_text),
            "Ruby":          self._detect_ruby(raw_text, lower_text, bin_data),
            "Wrapper":       self._detect_wrapper(lower_text),
        }

        matched = {k: v for k, v in scores.items() if v["score"] > 0}

        if not matched:
            return self._unknown_result()

        best_type = max(matched, key=lambda k: matched[k]["score"])
        best      = matched[best_type]

        gadget_hits     = [kw for kw in self.GADGET_KEYWORDS if kw.lower() in clean_text]
        gadget_detected = len(gadget_hits) > 0

        risk_level      = "Critical" if gadget_detected else best["risk_level"]
        effective_count = self._effective_match_count(best_type, matched)
        confidence      = self._calc_confidence(best["score"], effective_count)

        return {
            "value":           raw_text,
            "type":            best_type,
            "confidence":      confidence,
            "risk_level":      risk_level,
            "subtype":         best.get("subtype"),
            "gadget_detected": gadget_detected,
            "gadget_hints":    gadget_hits,
            "all_candidates":  {k: v["score"] for k, v in matched.items()},
        }

    def _detect_php(self, raw: str, lower: str) -> dict:
        if len(raw) < 8:
            return {"score": 0, "risk_level": "Low", "subtype": None}

        score   = 0
        subtype = None

        for p in self.PHP_STRONG:
            if re.search(p, raw):
                score += 4

        for p in self.PHP_MEDIUM:
            if re.search(p, raw):
                score += 2

        weak_hits = sum(1 for p in self.PHP_WEAK if re.search(p, raw))
        score += min(weak_hits, 2)

        for m in re.finditer(r's:(\d+):"([^"]*)"', raw):
            declared = int(m.group(1))
            actual   = len(m.group(2))
            if declared == actual:
                score += 3
                break
            else:
                score -= 1

        gadget_hits = [kw for kw in self.PHP_GADGET_CHAINS if kw in lower]
        if gadget_hits:
            subtype = "PHP Gadget Chain"
            score  += 2

        if 'phar://' in lower:
            score  += 2
            subtype = subtype or "Phar Deserialization"

        return {"score": score, "risk_level": "High", "subtype": subtype}

    def _detect_java(self, raw: str, lower: str, bin_data: bytes) -> dict:
        score   = 0
        subtype = None

        for magic in self.JAVA_MAGIC_BYTES:
            if magic in bin_data:
                score += 6

        for b64 in self.JAVA_MAGIC_B64:
            if b64 in raw:
                score += 5

        if 'jndi:' in lower:
            score  += 4
            subtype = "JNDI Injection"

        if 'ldap://' in lower or 'rmi://' in lower:
            score += 2

        gadget_hits = [kw for kw in self.JAVA_GADGET_CHAINS if kw in lower]
        if gadget_hits:
            subtype = subtype or "Java Gadget Chain"
            score  += len(gadget_hits) * 2

        return {"score": score, "risk_level": "High", "subtype": subtype}

    def _detect_pickle(self, raw: str, lower: str, bin_data: bytes) -> dict:
        score = 0

        for magic in self.PICKLE_MAGIC_BYTES:
            if magic in bin_data:
                score += 6

        for indicator in self.PICKLE_TEXT_INDICATORS:
            if indicator in raw:
                score += 4

        for gadget in self.PICKLE_GADGET:
            if gadget in lower:
                score += 3

        return {"score": score, "risk_level": "Critical", "subtype": None}

    def _detect_yaml(self, raw: str, lower: str) -> dict:
        score   = 0
        subtype = None

        YAML_SUBTYPES = [
            (r'!!python/object/apply\s*:',   "YAML Python RCE — object/apply"),
            (r'!!python/object\s*:',         "YAML Python Object Injection"),
            (r'!!python/module\s*:',         "YAML Python Module Load"),
            (r'!!(java\.|javax\.|com\.sun)', "YAML Java Class Injection"),
            (r'!!javax\.script',             "YAML Java ScriptEngine RCE"),
        ]
        for pattern, label in YAML_SUBTYPES:
            if re.search(pattern, raw, re.IGNORECASE):
                score  += 5
                subtype = subtype or label

        for p in self.YAML_MEDIUM:
            if re.search(p, raw, re.IGNORECASE):
                score += 3

        weak_hits = sum(1 for p in self.YAML_WEAK if re.search(p, raw))
        if weak_hits >= 2:
            score += 1

        return {"score": score, "risk_level": "High", "subtype": subtype}

    def _detect_dotnet(self, raw: str, lower: str) -> dict:
        score   = 0
        subtype = None

        for p in self.DOTNET_PATTERNS:
            if re.search(p, raw, re.IGNORECASE):
                score += 4

        for p in self.DOTNET_VIEWSTATE:
            if re.search(p, raw):
                score  += 5
                subtype = "ASP.NET ViewState"

        if '"$type"' in raw:
            score  += 4
            subtype = subtype or "JSON.NET TypeNameHandling"

        return {"score": score, "risk_level": "High", "subtype": subtype}

    def _detect_nodejs(self, raw: str, lower: str) -> dict:
        score   = 0
        subtype = None

        for p in self.NODEJS_PATTERNS:
            if re.search(p, raw, re.IGNORECASE):
                score += 3

        if '_$$ND_FUNC$$_' in raw:
            score  += 6
            subtype = "node-serialize RCE"

        if signatures.is_nodejs_prototype_pollution(lower):
            score  += 3
            subtype = subtype or "Prototype Pollution"

        return {"score": score, "risk_level": "High", "subtype": subtype}

    def _detect_ruby(self, raw: str, lower: str, bin_data: bytes) -> dict:
        score = 0

        for magic in self.RUBY_MAGIC_BYTES:
            if magic in bin_data:
                score += 5

        for p in self.RUBY_PATTERNS:
            if re.search(p, raw):
                score += 4

        return {"score": score, "risk_level": "High", "subtype": None}

    def _detect_wrapper(self, lower: str) -> dict:
        score   = 0
        subtype = None

        for w in self.WRAPPER_DANGEROUS:
            if w in lower:
                score  += 4
                subtype = "Dangerous Wrapper Protocol"

        for w in self.WRAPPER_MODERATE:
            if w in lower:
                score += 2

        return {"score": score, "risk_level": "High", "subtype": subtype}

    def _effective_match_count(self, best_type: str, matched: dict) -> int:
        KNOWN_COOCCURRENCE = {
            ("Wrapper", "PHP"),
            ("PHP",     "Wrapper"),
        }
        others = [t for t in matched if t != best_type]
        real_conflicts = sum(
            1 for t in others
            if (best_type, t) not in KNOWN_COOCCURRENCE
        )
        return real_conflicts + 1

    def _calc_confidence(self, score: int, num_matched: int) -> str:
        if num_matched >= 3:
            return "Low"
        if num_matched == 2:
            return "Medium" if score >= 5 else "Low"
        if score >= 8:
            return "High"
        if score >= 4:
            return "Medium"
        return "Low"

    def _unknown_result(self) -> dict:
        return {
            "value":           " ".join(self.data),
            "type":            "Unknown",
            "confidence":      "Low",
            "risk_level":      "Low",
            "subtype":         None,
            "gadget_detected": False,
            "gadget_hints":    [],
            "all_candidates":  {},
        }