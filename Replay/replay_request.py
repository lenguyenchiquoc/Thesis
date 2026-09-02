import base64
import time
import urllib.error
import urllib.parse
import urllib.request


class ReplayRequest:
    """Reconstructs the original HTTP request, injects a mutated payload at the
    correct location (cookie, header, body, query), sends it, and compares the
    response against a baseline (unmodified) request to flag indicators of
    successful deserialization: response time delta, HTTP status change,
    response length delta, and error-disclosure keywords.
    """

    ERROR_KEYWORDS = [
        "exception", "stack trace", "stacktrace", "traceback",
        "fatal error", "unserialize()", "objectinputstream",
        "invalidclassexception", "classnotfoundexception",
        "yaml.constructor", "pickle.unpicklingerror", "syntaxerror",
        "internal server error", "500 internal", "segmentation fault",
    ]

    TIME_DELAY_THRESHOLD_SEC = 4.0

    def __init__(self, timeout: int = 10, verify_tls: bool = True):
        self.timeout = timeout
        self.verify_tls = verify_tls

    def replay(self, payload: dict) -> dict:
        url = payload.get("url")
        location = payload.get("location")
        name = payload.get("name")
        method = (payload.get("method") or "GET").upper()
        if location in ("body", "form_body") and method == "GET":
            method = "POST"

        if not url or not location or not name:
            return self._skip_result(payload, "Missing url/location/name — cannot reconstruct request")

        raw_payload = self._select_payload_value(payload)
        if raw_payload is None:
            return self._skip_result(payload, "No usable payload value found")

        try:
            baseline = self._send(url, method, location, name, value=None)
            mutated = self._send(url, method, location, name, value=raw_payload)
        except (urllib.error.URLError, OSError, ValueError) as e:
            return self._skip_result(payload, f"Request failed: {e}")

        indicators = self._compare(baseline, mutated)

        return {
            "url": url,
            "method": method,
            "location": location,
            "name": name,
            "payload_type": payload.get("type"),
            "baseline": baseline,
            "mutated": mutated,
            "indicators": indicators,
            "likely_vulnerable": len(indicators) > 0,
        }

    def replay_all(self, payloads: list[dict]) -> list[dict]:
        return [self.replay(p) for p in payloads if "error" not in p]

    def _select_payload_value(self, payload: dict) -> str | None:
        encoding = payload.get("encoding")
        if encoding == "base64" and payload.get("payload"):
            try:
                return base64.b64decode(payload["payload"]).decode("utf-8", errors="replace")
            except Exception:
                return payload.get("payload_raw") or payload.get("payload")
        return payload.get("payload_raw") or payload.get("payload")

    def _send(self, url: str, method: str, location: str, name: str, value: str | None) -> dict:
        headers = {"User-Agent": "EthicalQuoc/replay"}
        cookies = {}
        body = None
        target_url = url

        if location == "cookie":
            if value is not None:
                cookies[name] = value
        elif location == "header":
            if value is not None:
                headers[name] = value
        elif location in ("query", "url_param"):
            parsed = urllib.parse.urlsplit(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if value is not None:
                qs[name] = [value]
            new_query = urllib.parse.urlencode(qs, doseq=True)
            target_url = urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment)
            )
        elif location in ("body", "form_body"):
            if value is not None:
                body = urllib.parse.urlencode({name: value}).encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"

        if cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

        req = urllib.request.Request(target_url, data=body, headers=headers, method=method)

        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                elapsed = time.monotonic() - start
                raw = resp.read()
                return {
                    "status": resp.status,
                    "elapsed_sec": round(elapsed, 3),
                    "length": len(raw),
                    "body_sample": raw[:2000].decode("utf-8", errors="replace"),
                }
        except urllib.error.HTTPError as e:
            elapsed = time.monotonic() - start
            raw = e.read()
            return {
                "status": e.code,
                "elapsed_sec": round(elapsed, 3),
                "length": len(raw),
                "body_sample": raw[:2000].decode("utf-8", errors="replace"),
            }

    def _compare(self, baseline: dict, mutated: dict) -> list[str]:
        indicators = []

        delay_delta = mutated["elapsed_sec"] - baseline["elapsed_sec"]
        if delay_delta >= self.TIME_DELAY_THRESHOLD_SEC:
            indicators.append(
                f"Time-based: mutated response {delay_delta:.2f}s slower than baseline"
            )

        if mutated["status"] != baseline["status"]:
            indicators.append(
                f"Status code changed: baseline={baseline['status']} mutated={mutated['status']}"
            )

        length_delta = abs(mutated["length"] - baseline["length"])
        if baseline["length"] > 0 and length_delta / baseline["length"] > 0.5:
            indicators.append(
                f"Response length changed significantly: baseline={baseline['length']} mutated={mutated['length']}"
            )

        mutated_lower = mutated["body_sample"].lower()
        error_hits = [kw for kw in self.ERROR_KEYWORDS if kw in mutated_lower]
        if error_hits:
            indicators.append(f"Error/exception disclosure in response: {error_hits}")

        return indicators

    def _skip_result(self, payload: dict, reason: str) -> dict:
        return {
            "url": payload.get("url"),
            "location": payload.get("location"),
            "name": payload.get("name"),
            "payload_type": payload.get("type"),
            "skipped": True,
            "reason": reason,
            "likely_vulnerable": False,
        }
