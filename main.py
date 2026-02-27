import argparse
import asyncio

from Scanner.har_loader import HarLoader
from Scanner.browser_automated_scan import BrowserScanner
from Output.save_output import save_output_file_type
from Input.input import InputLoader
VERSION = "2025.1.0.0"

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

        results = {"status": "analyze placeholder"}

        if args.input:
            reader = InputLoader(args.input)
            file_read = reader.load()
        if args.output:
            save_output_file_type(
                vectors=results,
                target_output_name=args.output,
                phase="scan",
                version=VERSION
            )

    elif args.command == "assess":

        print(f"[*] Assessing risk for: {args.input}")

        results = {"status": "assess placeholder"}

        if args.output:
            save_output_file_type(
                vectors=results,
                target_output_name=args.output,
                phase="scan",
                version=VERSION
            )
            
    elif args.command == "report":

        print(f"[*] Generating {args.format.upper()} report from {args.input}")

        results = {"status": "report placeholder"}

        if args.output:
            save_output_file_type(
                vectors=results,
                target_output_name=args.output,
                phase="scan",
                version=VERSION
            )


if __name__ == "__main__":
    main()