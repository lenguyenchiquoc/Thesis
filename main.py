import argparse
import asyncio
import io
import sys

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from Scanner.har_loader import HarLoader
from Scanner.browser_automated_scan import BrowserScanner
from Output.save_output import save_output_file_type
from Input.input_loader import InputLoader
from Analyze.postfiltered import VectorFiltering
from Analyze.normalize import DataNormalizer
from Analyze.cleanfilter import cleanfilter
from Analyze.finderprint import Fingerprint
import json
from Analyze.ExploitabilityAnalysis import ExploitAnalyze
from Analyze.payloadMutation import PayloadMutation
from Replay.replay_request import ReplayRequest
VERSION = "2025.1.0.0"

def _apply_replay_confirmation(exploit_analysis: dict, replay_result: dict) -> dict:
    """Upgrades a static (Suspected) exploit_analysis to Confirmed when the
    replay stage observed real evidence (time-delay, status/length change, or
    error disclosure). Never downgrades on a failed/skipped replay — a
    timeout or unreachable target does not prove the vulnerability is absent,
    it only means it was not verified this run.
    """
    result = dict(exploit_analysis)
    severity = result.get("severity", "Low")

    if replay_result.get("skipped"):
        result["confirmation_status"] = "Suspected"
        result["display_severity"] = f"Suspected-{severity}"
        result["confidence_source"] = "static_signature"
        result["replay_note"] = replay_result.get("reason")
        return result

    if replay_result.get("likely_vulnerable"):
        result["confirmation_status"] = "Confirmed"
        result["display_severity"] = f"Confirmed-{severity}"
        result["confidence_source"] = "replay_confirmed"
        result["confirmed_indicators"] = replay_result.get("indicators", [])
    else:
        result["confirmation_status"] = "Suspected"
        result["display_severity"] = f"Suspected-{severity}"
        result["confidence_source"] = "static_signature"
        result["replay_note"] = "Replay completed but no confirming indicator observed"

    return result


def main():
    parser = argparse.ArgumentParser(
        prog="ethicalQuoc",
        description="Insecure deserialization detection tool"
    )

    parser.add_argument("--setup", action="store_true", help="Set up tool")
    parser.add_argument("--version", action="store_true", help="Show version")
    parser.add_argument("--update", action="store_true", help="Update tool")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_cmd = subparsers.add_parser("scan", help="Scan target")
    scan_cmd.add_argument("--url", type=str, help="Scan website")
    scan_cmd.add_argument("--har", type=str, help="Input HAR file")
    scan_cmd.add_argument("-o", "--output", type=str, help="Export scan result file")

    analyze_cmd = subparsers.add_parser("analyze", help="Analyze input vectors")
    analyze_cmd.add_argument("-i", "--input", type=str, required=True, help="Input scan file")
    analyze_cmd.add_argument("-o", "--output", type=str, help="Export analyze result")

    assess_cmd = subparsers.add_parser("assess", help="Risk assessment")
    assess_cmd.add_argument("-i", "--input", type=str, required=True, help="Input analyze file")
    assess_cmd.add_argument("-o", "--output", type=str, help="Export assessment result")

    report_cmd = subparsers.add_parser("report", help="Generate report")
    report_cmd.add_argument("-i", "--input", type=str, required=True, help="Input assessment file")
    report_cmd.add_argument("--format", choices=["json", "pdf", "html"], default="json")
    report_cmd.add_argument("-o", "--output", type=str, help="Output report file")

    args = parser.parse_args()
    handle_arg(args)


def handle_arg(args):

    if args.setup:
        print("[*] Initializing environment...")
        return

    if args.version:
        print(f"EthicalQuoc version {VERSION}")
        return

    if args.update:
        print("[*] Updating EthicalQuoc...")
        return

    if args.command == "scan":

        if not args.url and not args.har:
            print("[!] Error: scan requires --url or --har")
            return

        total_vectors = []

        if args.har:
            loader = HarLoader(args.har)
            har_vectors = loader.parse()
            total_vectors.extend(har_vectors)
            print(f"[+] HAR collected: {len(har_vectors)} vectors")

        if args.url:
            scanner = BrowserScanner(args.url)
            browser_vectors = asyncio.run(scanner.start())
            total_vectors.extend(browser_vectors)
            print(f"[+] Browser collected: {len(browser_vectors)} vectors")

        print(f"[+] Total collected: {len(total_vectors)} vectors")

        if args.output:
            save_output_file_type(
                vectors=total_vectors,
                target_output_name=args.output,
                phase="scan",
                version=VERSION
            )

    elif args.command == "analyze":

        print(f"[*] Analyzing: {args.input}")

        results = []

        if args.input:
            reader = InputLoader(args.input)
            file_read = reader.load()
            vector_filtered = VectorFiltering(file_read)
            vector_filtered_list = vector_filtered.filter()
            print(f"[+] Vectors after filter: {len(vector_filtered_list)}")
            clean_filter = cleanfilter(vector_filtered_list)
            clean_filter.clean_and_output()

            for i in clean_filter._clean_all():
                value = i["cleaned_value"]
                value_normalize = DataNormalizer(value).normalize()
                print(f"Normalize is: {value_normalize}")
                fingerprint = Fingerprint(value_normalize).fingerprint_serial()
                print(json.dumps(fingerprint, indent=4, ensure_ascii=False))
                ExploitAnalyze_rs = ExploitAnalyze(fingerprint).analyze()
                print(json.dumps(ExploitAnalyze_rs, indent=4, ensure_ascii=False))

                mutation_vector = dict(i)
                mutation_vector["value"] = value_normalize[0] if value_normalize else value
                mutations = PayloadMutation(ExploitAnalyze_rs, mutation_vector).mutate()
                print(mutations)

                results.append({
                    "vector": {
                        "url": i.get("url"),
                        "method": i.get("method"),
                        "location": i.get("location"),
                        "name": i.get("name"),
                        "original_value": i.get("original_value"),
                    },
                    "normalized": value_normalize,
                    "fingerprint": fingerprint,
                    "exploit_analysis": ExploitAnalyze_rs,
                    "mutations": mutations,
                })

        if args.output:
            save_output_file_type(
                vectors=results,
                target_output_name=args.output,
                phase="analyze",
                version=VERSION
            )

    elif args.command == "assess":

        print(f"[*] Assessing risk for: {args.input}")

        results = []

        if args.input:
            with open(args.input, "r", encoding="utf-8") as f:
                analyze_data = json.load(f)

            replayer = ReplayRequest()

            for entry in analyze_data.get("vectors", []):
                mutations = entry.get("mutations", [])
                for mutation in mutations:
                    replay_result = replayer.replay(mutation)
                    print(json.dumps(replay_result, indent=4, ensure_ascii=False, default=str))

                    exploit_analysis = _apply_replay_confirmation(
                        entry.get("exploit_analysis") or {}, replay_result
                    )

                    results.append({
                        "exploit_analysis": exploit_analysis,
                        "mutation": mutation,
                        "replay": replay_result,
                    })

        if args.output:
            save_output_file_type(
                vectors=results,
                target_output_name=args.output,
                phase="assess",
                version=VERSION
            )
            
    elif args.command == "report":

        print(f"[*] Generating {args.format.upper()} report from {args.input}")

        if args.format != "json":
            print(f"[!] Format '{args.format}' not implemented yet — falling back to json")

        confirmed = []
        suspected = []

        if args.input:
            with open(args.input, "r", encoding="utf-8") as f:
                assess_data = json.load(f)

            for entry in assess_data.get("vectors", []):
                exploit_analysis = entry.get("exploit_analysis") or {}
                finding = {
                    "exploit_type": exploit_analysis.get("exploit_type"),
                    "severity": exploit_analysis.get("display_severity"),
                    "score": exploit_analysis.get("score"),
                    "suggested_probe": exploit_analysis.get("suggested_probe"),
                    "notes": exploit_analysis.get("notes"),
                    "mutation": entry.get("mutation"),
                }

                if exploit_analysis.get("confirmation_status") == "Confirmed":
                    finding["confirmed_indicators"] = exploit_analysis.get("confirmed_indicators", [])
                    confirmed.append(finding)
                else:
                    finding["replay_note"] = exploit_analysis.get("replay_note")
                    suspected.append(finding)

        results = {
            "summary": {
                "confirmed_count": len(confirmed),
                "suspected_count": len(suspected),
            },
            "confirmed_findings": confirmed,
            "suspected_findings": suspected,
        }

        print(f"[+] Confirmed: {len(confirmed)} | Suspected (requires manual verification): {len(suspected)}")

        if args.output:
            save_output_file_type(
                vectors=results,
                target_output_name=args.output,
                phase="report",
                version=VERSION
            )


if __name__ == "__main__":
    main()