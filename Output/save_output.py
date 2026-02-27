import json
from datetime import datetime
def save_output_file_type(vectors, target_output_name,phase ,scantype = "Hybrid", version = None):
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