import os
import json
import re
import urllib.parse

class VectorFiltering:
    
    Suspicious_header = {
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
            if not isinstance(value, str):
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
        if len(value) < 10:  
            return False

        value_lower = value.lower()

        try:
            decoded_value = urllib.parse.unquote(value)
            decoded_lower = decoded_value.lower()
        except:
            decoded_value = value
            decoded_lower = value_lower

        if re.search(r'(?i)[Oaidsb]:\d+:', value) or re.search(r'(?i)[Oaidsb]:\d+:', decoded_value):
            return True
        if re.search(r'(?i)Tzo[0-9]+[A-Za-z0-9+/=]*', value) or re.search(r'(?i)Tzo[0-9]+[A-Za-z0-9+/=]*', decoded_value):
            return True

        if value.startswith("rO0") or "rO0AB" in value or value.startswith("ACED") or "ACED" in value.upper():
            return True
        if "ysoserial" in decoded_lower or "commonscollections" in decoded_lower or "urlclassloader" in decoded_lower or "templatesimpl" in decoded_lower:
            return True

        if any(y in value for y in ["!!", "!<!", "%YAML", "!<tag:yaml.org"]):
            return True

        if value.startswith(("{", "[")) and len(value) > 100:
            if any(k in decoded_lower for k in ["__class__", "__wakeup", "__destruct", "java.lang", "java.util", "gadget", "phar"]):
                return True

        value_clean = value.replace('%3d', '=').replace('%3D', '=').replace('-', '+').replace('_', '/').rstrip('=')
        if len(value_clean) > 40 and len(value_clean) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]{20,}$', value_clean):
            return True

        if re.match(r'^[0-9a-fA-F]{30,}$', value):
            return True

        suspicious_chars = r'[\{\}\[\];:\$\|\^&]'
        if len(re.findall(suspicious_chars, decoded_value)) >= 6:
            return True

        unique_ratio = len(set(decoded_value)) / len(decoded_value) if decoded_value else 0
        if unique_ratio > 0.65 and len(decoded_value) > 60:
            return True

        if any(kw in decoded_lower for kw in ["phar://", "gopher://", "expect://", "file://", "data://", "serialize", "unserialize", "pickle", "marshal"]):
            return True

        return False