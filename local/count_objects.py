import json

with open("local/vision-evidence-batch-03.json", "r") as f:
    data = json.load(f)
    print(len(data))
