import os
import json
import re
class VectorFiltering:
    
    Suspicious_header = {
        "cookie",
        "authorization",
        "x-forwarded-for",
        "x-real-ip",
        "client-ip",
        "true-client-ip",
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
        "content-type",
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
        "sec-websocket-*",
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
            name = vector.get("name", "").lower()
            value = vector.get("value")
            if  not isinstance(value,str):
                continue
            if location not in ["cookie", "body", "header", "query"]:
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
        if len(value) < 10:  
            return False

        value_lower = value.lower()

        if value.startswith("rO0") or "rO0AB" in value:
            return True

        if re.search(r'\b[Oaidsb]:\d+:', value):
            return True

        if any(y in value for y in ["!!", "!<!", "%YAML", "!<tag:yaml.org"]):
            return True

        if value.startswith(("{", "[")) and len(value) > 100:
            if any(k in value_lower for k in ["__class__", "__wakeup", "__destruct", "java.lang", "java.util"]):
                return True

        if len(value) > 40 and value.count("=") in (0, 1, 2) and len(value) % 4 == 0:
            if re.match(r'^[A-Za-z0-9+/=]{20,}$', value): 
                return True

        if re.match(r'^[0-9a-fA-F]{30,}$', value):
            return True

        suspicious_chars = r'[\{\}\[\];:\$\|\^&]'
        if len(re.findall(suspicious_chars, value)) >= 6:
            return True

        unique_ratio = len(set(value)) / len(value) if value else 0
        if unique_ratio > 0.65 and len(value) > 60:
            return True


        if any(kw in value_lower for kw in ["ysoserial", "commonscollections", "urlclassloader", "templatesimpl"]):
            return True

        return False