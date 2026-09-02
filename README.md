# EthicalQuoc

CLI decision-support tool for detecting insecure deserialization in black-box web applications, with automated payload mutation and pentest-oriented reporting.

Built as a pre-thesis project at International University — VNU-HCM. Not a production security scanner — intended for lab/CTF/authorized pentest environments only. See [Disclaimer](#disclaimer).

## Table of contents

- [How it works](#how-it-works)
- [Supported serialization formats](#supported-serialization-formats)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Project structure](#project-structure)
- [Known limitations](#known-limitations)
- [Credits](#credits)
- [Disclaimer](#disclaimer)

## How it works

EthicalQuoc runs a black-box analysis pipeline over HTTP traffic captured from a target application. Instead of requiring the tester to manually spot a serialized parameter, identify its format, and hand-craft an exploit (the current state of tools like `ysoserial`/`phpggc`), it automates the pipeline end to end:

```
Stage 1  Input Collection   (scan)      HAR file or live browser capture -> raw HTTP vectors
Stage 2  PostFilter                     drop noise: irrelevant locations/headers, keep suspicious values
Stage 3  CleanFilter                    strip known prefixes (Bearer, session=, Cookie:, ...)
Stage 4  Normalize                      peel URL-encoding / Base64 / gzip / hex layers (BFS, multi-layer)
Stage 5  Fingerprint                    classify against known serialization signatures + confidence score
Stage 6  Exploitability Analysis        map fingerprint -> exploit type, severity, suggested probe
Stage 7  Payload Mutation               generate type-specific exploit payloads for the suggested probe
Stage 8  Replay + Confirmation (assess) inject payload into the real request, compare vs baseline response
Stage 9  Report                         split findings into Confirmed vs Suspected, export JSON
```

Each stage writes structured JSON, so any stage can be re-run or inspected independently without re-running the whole pipeline.

### Oracle probe

Before replaying a potentially large batch of exploit payloads against a live target (e.g. dozens of phpggc gadget-chain variants for a single PHP parameter), `assess` first runs one cheap, non-destructive oracle probe per vector. For PHP, this corrupts the declared length of a string field in the *original* serialized value (`s:4:"role"` → `s:101:"role"`) and compares the response to a clean baseline — a well-formed `unserialize()` call on that value will error or behave differently only if the target actually parses it. The oracle result is attached to every finding as additional evidence; it never gates or skips the full replay, since a negative/inconclusive oracle doesn't prove absence of a vulnerability, only that this particular probe didn't observe one.

### Confirmed vs Suspected

A signature match alone (e.g. "this cookie contains `__wakeup`") is not proof of exploitability in a black-box setting — it only means the *shape* of the data looks dangerous. EthicalQuoc keeps this distinction explicit throughout the pipeline:

- **Suspected** — the exploitability analysis stage detected a signature/pattern and generated a payload for it, but nothing has confirmed the target actually deserializes it.
- **Confirmed** — the `assess` stage replayed the mutated payload against the live target and observed real evidence: a timing delay, a status/response-length change, or an error/exception disclosed in the response.

A failed or skipped replay (timeout, unreachable target) never downgrades a finding to "not vulnerable" — it just means it wasn't verified this run.

## Supported serialization formats

| Format | Fingerprinting | Exploitability analysis | Payload mutation |
|---|---|---|---|
| Java | ✅ | ✅ | ✅ ysoserial subprocess (multi gadget-chain × command) |
| PHP | ✅ | ✅ | ✅ phpggc (gadget chains) + inline mutation (flip_boolean / modify_string / modify_integer / magic_method) |
| Python Pickle | ✅ | ✅ | ✅ inline `pickle`-based payload |
| YAML | ✅ | ✅ | ✅ inline `!!python/object/apply` payload |
| NodeJS | ✅ | ✅ | ✅ node-serialize IIFE + prototype pollution |
| Ruby Marshal | ✅ | ✅ | ✅ `ruby -e` subprocess (requires Ruby installed) |
| .NET (ViewState / BinaryFormatter / JSON.NET) | ✅ | ✅ | ✅ ysoserial.net subprocess + inline JSON.NET `$type` payload |
| Wrapper (`phar://`, `expect://`, `gopher://`, `php://`, `data://`, `glob://`, ...) | ✅ | ✅ | ✅ inline construction + phpggc phar output + optional Gopherus |

All mutation paths that shell out to an external tool (`ysoserial`, `phpggc`, `ysoserial.net`, `Gopherus`) fail gracefully with a clear error/hint when the tool isn't installed, instead of silently returning nothing.

## Installation

Requires Python 3.10+. On Windows, PHP and Java are needed for the PHP/Java mutation paths (see [Configuration](#configuration) for third-party tool setup).

```bash
git clone https://github.com/lenguyenchiquoc/Thesis.git
cd Thesis
pip install playwright   # only needed for `scan --url` (live browser capture)
playwright install chromium
```

No other Python dependencies — the rest of the pipeline uses only the standard library (`json`, `re`, `base64`, `subprocess`, `urllib`).

## Usage

The tool is invoked through `main.py` with one of four subcommands, chained via JSON files:

```bash
# 1. Collect HTTP vectors from a HAR file exported from your browser's DevTools
python main.py scan --har capture.har -o results/scan_output.json

# (alternative) live capture by driving a headless browser against a URL
python main.py scan --url https://target.example.com -o results/scan_output.json

# 2. Run the full analysis pipeline: filter -> normalize -> fingerprint -> exploit analysis -> mutate
python main.py analyze -i results/scan_output.json -o results/analyze_output.json

# 3. Replay generated payloads against the live target and confirm/deny each finding
python main.py assess -i results/analyze_output.json -o results/assess_output.json

# 4. Generate a report split into Confirmed / Suspected findings
python main.py report -i results/assess_output.json -o results/report_output.json
```

Each stage's output is plain JSON and can be inspected manually — see `results/` for examples.

## Configuration

Third-party exploitation tools are **not bundled with a fixed absolute path** — paths are resolved through `config.json` at the project root, via `tool_config.py`:

```json
{
    "tools": {
        "ysoserial": "Analyze/third_tool/java/ysoserial-all.jar",
        "phpggc": "Analyze/third_tool/phpggc/phpggc",
        "ysoserial_net": "Analyze/third_tool/dotnet/ysoserial.exe",
        "gopherus": "Analyze/third_tool/gopherus/gopherus.py"
    },
    "oob_domain": ""
}
```

- Relative paths are resolved against the project root, so the tool works regardless of the drive letter or clone location.
- To point at tools installed elsewhere, either edit `config.json` directly or set the `ETHICALQUOC_CONFIG` environment variable to a different config file path.
- `ysoserial-all.jar` and `phpggc` are vendored under `Analyze/third_tool/`. `ysoserial.net` and `Gopherus` are not bundled — install them separately and update `config.json` if you need the .NET/SSRF mutation paths.
- `oob_domain` — set this to your own Burp Collaborator or Interactsh subdomain (or set `ETHICALQUOC_OOB_DOMAIN`) to have URLDNS and blind-SSRF payloads embed a real canary instead of a placeholder. Interaction logs must still be checked manually — this tool does not poll an OOB provider's API for you.

## Project structure

```
main.py                     CLI entry point (scan / analyze / assess / report)
tool_config.py               third-party tool path resolution
config.json                  tool path configuration

Scanner/
  har_loader.py               parses HAR files into HTTP vectors
  browser_automated_scan.py   live capture via Playwright

Analyze/
  postfiltered.py             Stage 2 — location/header/heuristic filtering
  cleanfilter.py               Stage 3 — prefix/whitespace normalization
  normalize.py                 Stage 4 — multi-layer decode (BFS)
  finderprint.py                Stage 5 — serialization fingerprinting
  ExploitabilityAnalysis.py    Stage 6 — exploit type, severity, suggested probe
  payloadMutation.py           Stage 7 — payload generation per format
  third_tool/                  vendored ysoserial-all.jar, phpggc

Replay/
  replay_request.py            Stage 8 — request replay + Confirmed/Suspected evidence
  oracle_probe.py               cheap pre-check before replaying a full payload batch

Input/, Output/                schema-validated JSON load/save helpers
Utility/
  signatures.py                 shared serialization signatures (single source of
                                 truth for postfiltered.py, cleanfilter.py, finderprint.py)

results/                       example pipeline output at each stage
TestCase/
  test.har                       fixed regression fixture covering all 8 formats
  example_multivalue_header.har  illustrative "; "-separated multi-value header cases
```

## Known limitations

- Static signature matching (e.g. detecting `monolog`/`laravel` keywords, magic method names) infers exploitability from the *shape* of the payload, not from confirmed knowledge of the target's classpath/dependencies — this is an inherent limitation of black-box analysis, not something the tool can fully resolve. The Confirmed/Suspected split exists specifically to keep this honest.
- Attacks requiring a prerequisite step (e.g. forging an HMAC-signed cookie, leaking a signing key such as Django's `SECRET_KEY` or Rails' `secret_key_base`) are out of scope — the tool assumes the observed payload is directly mutable.
- Out-of-band (OOB) confirmation is semi-manual: `assess` will embed a configured canary domain (`oob_domain`) into URLDNS/blind-SSRF payloads, but does not poll an Interactsh/Burp Collaborator API for interactions — checking the interaction log is still a manual step.
- The oracle probe currently only supports PHP (length-corruption technique); Java/Pickle/YAML/.NET/NodeJS/Ruby/Wrapper probes still go straight to full payload replay without a cheap pre-check.
- No automated test suite yet — correctness of fingerprinting/exploitability heuristics has been validated manually against PortSwigger Web Security Academy labs.
- `scan --url` (live browser capture via Playwright) has not been extensively exercised end to end.

## Credits

Payload generation for Java and PHP builds on top of:
- [ysoserial](https://github.com/frohoff/ysoserial) — Java deserialization gadget chains
- [phpggc](https://github.com/ambionics/phpggc) — PHP deserialization gadget chains

## Disclaimer

This tool was built for academic/research purposes as part of a pre-thesis project. It is **not** intended for use against systems you do not own or do not have explicit authorization to test. Use only in controlled lab environments (e.g. PortSwigger Web Security Academy) or authorized penetration testing engagements.
