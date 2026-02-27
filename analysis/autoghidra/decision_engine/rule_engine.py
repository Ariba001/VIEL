import json

def evaluate(report_path):
    with open(report_path) as f:
        data = json.load(f)

    unsafe_score = sum(data["unsafe_calls"].values())

    if unsafe_score > 2:
        return "High Risk"
    elif unsafe_score > 0:
        return "Medium Risk"
    else:
        return "Low Risk"