import csv


def evaluate(report_path):
    """
    Score a binary from the Ghidra feature CSV.
    Returns 'High Risk', 'Medium Risk', or 'Low Risk'.
    """
    DANGEROUS = {"strcpy", "gets", "printf", "sprintf", "scanf", "strcat", "system"}

    dangerous_calls = 0
    total_functions = 0

    with open(report_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_functions += 1
            func_name = row.get("function", "").lower()
            if any(d in func_name for d in DANGEROUS):
                dangerous_calls += 1

            # indirect_calls is a strong signal
            try:
                dangerous_calls += int(row.get("indirect_calls", 0))
            except ValueError:
                pass

    if dangerous_calls > 5:
        return "High Risk"
    elif dangerous_calls > 1:
        return "Medium Risk"
    else:
        return "Low Risk"
