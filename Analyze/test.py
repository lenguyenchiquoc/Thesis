from normalize import DataNormalizer
import base64
value = "rO0ABXNyABdqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHABwAAAAAEwAHhwdAAIZ2FkZ2V0cw=="
ecoded_bytes = base64.b64decode(value)
print(ecoded_bytes)
decode = DataNormalizer(value, max_depth = 12)
candidate = decode.normalize()
print(candidate)





