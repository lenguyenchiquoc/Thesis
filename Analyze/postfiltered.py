from Utility import signatures

class VectorFiltering:
    
    Suspicious_header = {
        "authorization",
        "x-api-key",
        "x-auth-token",
        "api-key",
        "x-access-token",
        "x-csrf-token",
        "x-xsrf-token",
    }
    
    Ignore_header_name = {
        "accept",
        "accept-language",
        "accept-encoding",
        "accept-charset",
        "cache-control",
        "connection",
        "content-length",
        "date",
        "dnt",
        "host",
        "origin",
        "pragma",
        "referer",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-protocol",
        "sec-websocket-extensions",
        "sec-websocket-accept",
        "upgrade-insecure-requests",
        "user-agent",
        ":method",
        ":scheme",
        ":authority",
        ":path",
        "priority",
        "purpose",
    }
    
    def __init__(self, input):
        self.data = input
        
    def filter(self):
        filtered = []
        for vector in self.data["vectors"]:
            location = vector.get("location")
            name = vector.get("name")
            name = name.lower() if isinstance(name, str) else ""
            value = vector.get("value")
            if not isinstance(value, str) or not value.strip():
                continue
            if location not in ["cookie", "body", "header", "query", "form_body", "url_param"]:
                continue
            if location == "header" and name in self.Ignore_header_name:
                continue
            if location == "header" and name in self.Suspicious_header:
                filtered.append(vector)
                continue
            if self._look_maybe_suspicious(value):
                filtered.append(vector) 
        return filtered
    
    def _look_maybe_suspicious(self, value: str) -> bool:
        return signatures.looks_like_serialized(value)