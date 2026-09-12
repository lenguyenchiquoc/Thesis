import json
import os
from datetime import datetime


def default_output_path(phase: str, base_dir: str = "results") -> str:
    now = datetime.now()
    date_folder = now.strftime("%d%m%Y")
    dir_path = os.path.join(base_dir, date_folder)
    os.makedirs(dir_path, exist_ok=True)
    timestamp = now.strftime("%H%M%S")
    filename = f"{phase}_{timestamp}.json"
    return os.path.join(dir_path, filename)


def save_output_file_type(vectors, target_output_name,phase ,scantype = "Hybrid", version = None):
    parent_dir = os.path.dirname(target_output_name)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    result = {
        "metadata": {
            "tool": "ethicalQuoc",
            "version": version,
            "scan_type": scantype,
            "phase": phase,
            "target": target_output_name,
            "timestamp": datetime.utcnow().isoformat()
        },
        "summary": {
            "total_vectors": len(vectors)
        },
        "vectors": vectors
    }

    with open(target_output_name , "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)

    print(f"[+] Output saved to {target_output_name}")