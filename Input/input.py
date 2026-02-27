import json
import os

class InputLoader:
    REQUIRED_TOP = {"metadata", "summary", "vectors"}
    REQUIRED_VECTOR = {"source", "url", "method", "location", "name", "value"}
    
    def __init__(self, file_path:str):
        self.file_path = file_path
    
    def load(self):
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File is not found at {self.file_path}!")
        if not self.file_path.endswith('json'):
            raise ValueError("Wrong file type!")
        with open(self.file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self._is_valid_schema(data)
        return data
        
    def _is_valid_schema(self, data):
        missing_part = self.REQUIRED_TOP - data.keys()
        if missing_part:
            raise ValueError("Missing top-level json")
        
        if not isinstance(data["vectors"], list):
            raise ValueError("Missing vectors")
        
        for i, vector in enumerate(data["vectors"]):
            if not isinstance(vector, dict):
                raise ValueError("Is not valid")
            missing_fields = self.REQUIRED_VECTOR - vector.keys()
            if missing_fields:
                raise ValueError(f"[!] Vector at index {i} missing fields: {missing_fields}")
        