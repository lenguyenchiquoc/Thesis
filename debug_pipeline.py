"""Pipeline step inspector — runs the analyze pipeline up to a specific
stage and prints/saves exactly what that stage produced, instead of running
the whole chain to the end like `main.py analyze` does.

Reuses the exact same classes main.py calls (no separate/duplicated logic),
so what you see here is guaranteed to match what the real pipeline does at
that point — this exists specifically to catch input/output mismatches
between adjacent stages without re-deriving the whole chain by hand.

Usage:
    python debug_pipeline.py -i results/scan_output.json --step 2   # PostFilter
    python debug_pipeline.py -i results/scan_output.json --step 3   # + CleanFilter
    python debug_pipeline.py -i results/scan_output.json --step 4   # + Normalize
    python debug_pipeline.py -i results/scan_output.json --step 5   # + Fingerprint
    python debug_pipeline.py -i results/scan_output.json --step 6   # + ExploitabilityAnalysis
    python debug_pipeline.py -i results/scan_output.json --step 7   # + PayloadMutation
"""

import argparse
import io
import json
import sys

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from Input.input_loader import InputLoader
from Analyze.postfiltered import VectorFiltering
from Analyze.cleanfilter import cleanfilter
from Analyze.normalize import DataNormalizer
from Analyze.finderprint import Fingerprint
from Analyze.ExploitabilityAnalysis import ExploitAnalyze
from Analyze.payloadMutation import PayloadMutation

STEP_NAMES = {
    2: "PostFilter (VectorFiltering)",
    3: "CleanFilter",
    4: "Normalize",
    5: "Fingerprint",
    6: "ExploitabilityAnalysis",
    7: "PayloadMutation",
}


def main():
    parser = argparse.ArgumentParser(
        prog="debug_pipeline",
        description="Run the analyze pipeline up to a chosen stage and show that stage's output.",
    )
    parser.add_argument("-i", "--input", required=True, help="Input scan_output.json (Stage 1 output)")
    parser.add_argument(
        "--step", type=int, required=True, choices=sorted(STEP_NAMES),
        help="Which stage's output to inspect: " + ", ".join(f"{k}={v}" for k, v in STEP_NAMES.items()),
    )
    parser.add_argument("-o", "--output", help="Optional: save this stage's output to a JSON file")
    args = parser.parse_args()

    print(f"[*] Running pipeline up to Stage {args.step}: {STEP_NAMES[args.step]}")

    reader = InputLoader(args.input)
    file_read = reader.load()

    # Stage 2: PostFilter
    vector_filtered_list = VectorFiltering(file_read).filter()
    print(f"[+] Stage 2 (PostFilter): {len(vector_filtered_list)} vectors kept")
    if args.step == 2:
        _emit(vector_filtered_list, args.output)
        return

    # Stage 3: CleanFilter
    cleaned_vectors = cleanfilter(vector_filtered_list)._clean_all()
    print(f"[+] Stage 3 (CleanFilter): {len(cleaned_vectors)} vectors")
    if args.step == 3:
        _emit(cleaned_vectors, args.output)
        return

    # Stages 4-7: same per-vector chain as main.py's analyze command
    results = []
    for vector in cleaned_vectors:
        value = vector["cleaned_value"]
        value_normalize = DataNormalizer(value).normalize()

        entry = {
            "vector": {
                "url": vector.get("url"),
                "method": vector.get("method"),
                "location": vector.get("location"),
                "name": vector.get("name"),
                "original_value": vector.get("original_value"),
                "cleaned_value": vector.get("cleaned_value"),
            },
            "normalized": value_normalize,
        }

        if args.step >= 5:
            fingerprint = Fingerprint(value_normalize).fingerprint_serial()
            entry["fingerprint"] = fingerprint

        if args.step >= 6:
            exploit_result = ExploitAnalyze(fingerprint).analyze()
            entry["exploit_analysis"] = exploit_result

        if args.step >= 7:
            mutation_vector = dict(vector)
            mutation_vector["value"] = value_normalize[0] if value_normalize else value
            entry["mutations"] = PayloadMutation(exploit_result, mutation_vector).mutate()

        results.append(entry)

    print(f"[+] Stage {args.step} ({STEP_NAMES[args.step]}): {len(results)} vectors")
    _emit(results, args.output)


def _emit(data, output_path):
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        print(f"[+] Saved to {output_path}")


if __name__ == "__main__":
    main()
