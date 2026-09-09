import re
import urllib.parse

PHP_STRONG = [
    r'O:\d+:"[^"]+":\d+:\{',
    r'C:\d+:"[^"]+":\d+:\{',
]
PHP_MEDIUM = [
    r'a:\d+:\{(?:s:|i:|O:|b:|d:)',
]
PHP_WEAK = [
    r's:\d+:"',
    r'i:\d+;',
    r'd:\d+\.\d+;',
    r'b:[01];',
]
PHP_GADGET_CHAINS = [
    "monolog", "guzzle", "swiftmailer",
    "phpggc", "laravel", "symfony",
    "__wakeup", "__destruct", "__toString",
    "__call", "__get", "__set",
]

JAVA_MAGIC_B64 = [
    'rO0AB',
    'rO0A',
]
JAVA_MAGIC_BYTES = [
    b'\xac\xed\x00\x05',
    b'\xac\xed\x00\x04',
]
JAVA_GADGET_CHAINS = [
    "templatesimpl", "commonscollections", "urldns",
    "invoketransformer", "annotationinvocationhandler",
    "ysoserial", "jdk7u21", "spring", "hibernatevalidator",
    "rome", "beanshell", "clojure", "groovy",
]

PICKLE_MAGIC_BYTES = [
    b'\x80\x02',
    b'\x80\x03',
    b'\x80\x04',
    b'\x80\x05',
]
PICKLE_TEXT_INDICATORS = [
    'c__builtin__', 'cposix', 'csubprocess',
    'cos\nsystem', 'cbuiltins\nexec',
    '__reduce__', '__reduce_ex__',
    'ctypes\nFunctionType',
]
PICKLE_GADGET = [
    'os.system', 'subprocess.check_output',
    'eval', 'exec', '__import__',
]

YAML_STRONG = [
    r'!!python/object/apply',
    r'!!python/object:',
    r'!!python/module:',
    r'!!javax\.script',
    r'!!com\.sun',
    r'!!java\.lang',
    r'!<tag:yaml\.org,2002:python',
]
YAML_MEDIUM = [
    r'%YAML\s+\d+\.\d+',
    r'!<tag:yaml\.org',
]
YAML_WEAK = [
    r'!!',
    r'!<',
]

DOTNET_PATTERNS = [
    r'<SOAP-ENV:Envelope',
    r'<System\.Runtime\.Serialization',
    r'__type.*System\.',
    r'"@class"\s*:\s*"[^"]*"',
    r'TypeObject.*mscorlib',
    r'BinaryFormatter',
    r'ObjectStateFormatter',
    r'LosFormatter',
    r'NetDataContractSerializer',
]
DOTNET_VIEWSTATE = [
    r'^/wEy',
    r'^/wEx',
    r'^/wEP',
]

NODEJS_PATTERNS = [
    r'_proto_\s*:',
    r'"__proto__"\s*:',
    r'"constructor"\s*:\s*\{',
    r'node-serialize',
    r'"rce"\s*:\s*"_\$\$ND_FUNC\$\$_',
    r'_\$\$ND_FUNC\$\$_function',
]

RUBY_PATTERNS = [
    r'\\x04\\x08',
    r'BAhv',
    r'BAh[0-9A-Za-z+/]',
    r'\\u0004\\b',
]
RUBY_MAGIC_BYTES = [
    b'\x04\x08',
]

WRAPPER_DANGEROUS = [
    "phar://", "expect://", "gopher://",
    "glob://", "zlib://", "bzip2://",
]
WRAPPER_MODERATE = [
    "file://", "data://", "php://",
    "compress.zlib://", "compress.bzip2://",
]

GADGET_KEYWORDS = [
    'TemplatesImpl', 'InvokerTransformer', 'CommonsCollections',
    'ysoserial', 'Monolog', 'Guzzle', 'SwiftMailer',
    'os.system', 'subprocess', '__wakeup', '__destruct',
    'AnnotationInvocationHandler', 'URLDNS', 'phpggc',
    'marshalsec', 'jndi:', 'ldap://', 'rmi://',
    'commons.collections',
    'commons-collections',
    'org.apache.commons',
    'com.sun.org.apache',
    'org.apache.xalan',
    'com.sun.org.apache.xalan',
    'transletbytecodes',
    'sun.reflect.annotation',
    'java.lang.reflect.proxy',
    'com.sun.jndi',
    'javax.naming',
    'org.springframework',
    'springframework.core',
    'groovy.lang',
    'org.codehaus.groovy',
    'bsh.interpreter',
    'com.sun.syndication',
    'java.lang.runtime',
    'java.lang.reflect',
    'java.net.urlclassloader',
    'java.rmi.server',
    'gadgets',
]


def is_nodejs_prototype_pollution(text: str) -> bool:
    return '__proto__' in text or ('constructor' in text and 'prototype' in text)


def looks_like_serialized(value: str) -> bool:
    if len(value) < 10:
        return False

    value_lower = value.lower()

    try:
        decoded_value = urllib.parse.unquote(value)
        decoded_lower = decoded_value.lower()
    except Exception:
        decoded_value = value
        decoded_lower = value_lower

    bin_data = value.encode('utf-8', errors='ignore')
    if any(magic in bin_data for magic in JAVA_MAGIC_BYTES + PICKLE_MAGIC_BYTES + RUBY_MAGIC_BYTES):
        return True

    if any(re.search(p, value) or re.search(p, decoded_value) for p in PHP_STRONG + PHP_WEAK):
        return True
    if re.search(r'(?i)Tzo[0-9]+[A-Za-z0-9+/=]*', value) or re.search(r'(?i)Tzo[0-9]+[A-Za-z0-9+/=]*', decoded_value):
        return True

    if value.startswith("rO0") or "rO0AB" in value or value.startswith("ACED") or "ACED" in value.upper():
        return True
    if "ysoserial" in decoded_lower or "commonscollections" in decoded_lower or "urlclassloader" in decoded_lower or "templatesimpl" in decoded_lower:
        return True
    if "application/x-java-serialized-object" in value_lower:
        return True
    if any(y in value for y in ["!!", "!<!", "%YAML", "!<tag:yaml.org"]):
        return True

    if any(p in decoded_value for p in PICKLE_TEXT_INDICATORS):
        return True

    if any(re.search(p, value) or re.search(p, decoded_value) for p in DOTNET_VIEWSTATE):
        return True
    if any(re.search(p, value, re.IGNORECASE) or re.search(p, decoded_value, re.IGNORECASE) for p in DOTNET_PATTERNS):
        return True

    if any(re.search(p, value) or re.search(p, decoded_value) for p in RUBY_PATTERNS):
        return True

    if is_nodejs_prototype_pollution(decoded_lower):
        return True
    if any(re.search(p, value, re.IGNORECASE) or re.search(p, decoded_value, re.IGNORECASE) for p in NODEJS_PATTERNS):
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
