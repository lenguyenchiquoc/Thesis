import os
import re

class Fingerprint:
    PHP_PATTERNS = [
        r'O:\d+:"[^"]+":\d+:{',
        r'a:\d+:{',
        r's:\d+:',
        r'i:\d+;',
        r'd:\d+\.\d+;',
        r'b:[01];'
    ]
    
    JAVA_PATTERNS = [
        r'rO0AB',
        r'\xac\xed\x00\x05'
    ]
    
    YAML_PATTERNS = [
        r'!!',
        r'!<',
        r'%YAML',
        r'!<tag:yaml.org'
    ]
    
    PICKLE_PATTERNS = [
        r'c__builtin__',
        r'cposix',
        r'csubprocess',
        r'\x80\x04'
    ]
    
    GADGET_KEYWORDS = [
        'TemplatesImpl',
        'InvokerTransformer',
        'CommonsCollections',
        'ysoserial',
        'Monolog',
        'Guzzle',
        'SwiftMailer',
        'os.system',
        'subprocess',
        '__wakeup',
        '__destruct',
        '__class__',
        'AnnotationInvocationHandler',
        'URLDNS'
    ]

    def __init__(self, data_list: list[str]):
        self.data = [str(item).strip() for item in data_list if str(item).strip()]
        
    def fingerprint_serial(self) -> dict:
        if not self.data:
            return {
                "type": "Unknown",
                "confidence": "Low",
                "risk_level": "Low",
                "subtype": None,
                "gadget_detected": False,
            }
        
        text = " ".join(self.data).lower()

        bin_part = [item.encode('utf-8', errors='ignore') for item in self.data]
        bin_data = b" ".join(bin_part)

        confidence = "Low"
        risk_level = "Low"
        detected_type = "Unknown"
        subtype = None
        gadget_detected = False    
        
        if any(re.search(pattern, text) for pattern in self.PHP_PATTERNS):
            detected_type = "PHP"
            confidence = "High"
            risk_level = "High"
            if any(kw in text for kw in ['Monolog', 'Guzzle', 'SwiftMailer']):
                subtype = "PHP Gadget chain"
                gadget_detected = True
        
        elif any(p in text for p in self.JAVA_PATTERNS) or \
             any(p.encode('latin1') in bin_data for p in self.JAVA_PATTERNS):
            detected_type = "Java"
            confidence = "High"
            risk_level = "High"
            if any(kw in text for kw in ["TemplatesImpl", "CommonsCollections", "URLDNS"]):
                subtype = "Java Gadget Chain"
                gadget_detected = True
  
        elif any(re.search(pattern, text) for pattern in self.YAML_PATTERNS):
            detected_type = "YAML"
            confidence = "Medium"
            risk_level = "High"
            gadget_detected = True
        
   
        elif any(re.search(pattern, text) for pattern in self.PICKLE_PATTERNS):
            detected_type = "Python Pickle"
            confidence = "High"
            risk_level = "Critical"
            gadget_detected = True
        

        elif any(kw in text for kw in ["phar://", "gopher://", "expect://", "file://", "data://"]):
            detected_type = "Wrapper Protocol Exploit"
            confidence = "Medium"
            risk_level = "High"


        if any(kw.lower() in text for kw in self.GADGET_KEYWORDS):
            gadget_detected = True
            risk_level = "Critical"

        if len(self.data) > 1:
            confidence = "Very High" if confidence in ["High", "Medium"] else confidence


        return {
            "value": " ".join(self.data),
            "type": detected_type,
            "confidence": confidence,
            "risk_level": risk_level,
            "subtype": subtype,
            "gadget_detected": gadget_detected,

        }