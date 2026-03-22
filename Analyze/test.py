import re

text = 'o:4:"User"'

print(re.search(r"\D+", text))   
print(re.search(r"o:\d+:", text))




