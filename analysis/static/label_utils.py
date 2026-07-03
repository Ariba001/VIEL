"""
Shared per-function label resolution, used by both vuln_labels.py
(synthetic ai_sec_lab dataset) and juliet_labels.py (ingested Juliet Test
Suite dataset).
"""


def resolve_node_labels(binary_label, function_names, target):
    """
    Per-function 0/1 labels given a single named function that carries
    the vulnerability. If target isn't found among function_names (e.g.
    the optimizer inlined it away), falls back to labelling "main" --
    the vulnerable code then physically lives inside main's compiled
    body. Returns all-zero when binary_label == 0 or target is None.
    """
    n = len(function_names)
    if binary_label == 0 or target is None:
        return [0] * n

    if target in function_names:
        return [1 if name == target else 0 for name in function_names]

    if target != "main" and "main" in function_names:
        return [1 if name == "main" else 0 for name in function_names]

    return [0] * n
