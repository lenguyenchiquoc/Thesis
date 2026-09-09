import base64
import re


class OracleProbe:
    def __init__(self, replayer):
        self.replayer = replayer

    def probe(self, fingerprint_type: str, vector: dict) -> dict:
        if fingerprint_type == "PHP":
            return self._probe_php(vector)
        return {
            "supported": False,
            "reason": f"No oracle probe implemented for type '{fingerprint_type}' yet",
        }

    def _corrupt_php_length(self, value: str) -> str | None:
        match = re.search(r's:(\d+):"([^"]*)"', value)
        if not match:
            return None
        declared_len = int(match.group(1))
        corrupted_len = declared_len + 97
        return value[:match.start()] + f's:{corrupted_len}:"{match.group(2)}"' + value[match.end():]

    def _probe_php(self, vector: dict) -> dict:
        url = vector.get("url")
        location = vector.get("location")
        name = vector.get("name")
        method = vector.get("method") or "GET"
        original_value = vector.get("value")

        if not (url and location and name and original_value):
            return {"supported": True, "ran": False, "reason": "Missing url/location/name/value on vector"}

        corrupted = self._corrupt_php_length(original_value)
        if corrupted is None:
            return {"supported": True, "ran": False, "reason": "No PHP string field found to corrupt"}

        probe_payload = {
            "url": url,
            "method": method,
            "location": location,
            "name": name,
            "payload": base64.b64encode(corrupted.encode()).decode(),
            "encoding": "base64",
        }

        replay_result = self.replayer.replay(probe_payload)
        if replay_result.get("skipped"):
            return {"supported": True, "ran": False, "reason": replay_result.get("reason")}

        indicators = replay_result.get("indicators", [])
        return {
            "supported": True,
            "ran": True,
            "technique": "php_length_corruption",
            "indicators": indicators,
            "target_parses_payload": len(indicators) > 0,
        }
