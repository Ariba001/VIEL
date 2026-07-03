"""
Per-function ground truth for the synthetic ai_sec_lab dataset.

Every template in scripts/generate_dataset.py injects its vulnerable (or
safe-equivalent) code into exactly one function — either a dedicated
helper ("vuln", "vulnerable", "safe", "inc") or directly inside "main".
Binary filenames encode the exact template key
(f"{template}_{variation}_{arch}_{opt}"), so the vulnerable function name
can be recovered without re-parsing C sources.

This lets us go from "this binary is vulnerable" (weak, binary-level
supervision) to "this specific function is vulnerable" (node-level
supervision) for training/evaluating function-level GNN localization.
"""

import re
from pathlib import Path

from analysis.static.label_utils import resolve_node_labels

# template key -> name of the function that carries the vuln/safe pattern
VULN_FUNCTION_BY_TEMPLATE = {
    "stack_overflow_vuln": "vuln",
    "stack_safe": "safe",
    "heap_overflow_vuln": "vuln",
    "heap_safe": "safe",
    "format_vuln": "main",
    "format_safe": "main",
    "double_free_vuln": "main",
    "double_free_safe": "main",
    "use_after_free_vuln": "main",
    "use_after_free_safe": "main",
    "int_overflow_vuln": "main",
    "int_safe": "main",
    "null_deref_vuln": "main",
    "null_deref_safe": "main",
    "oob_vuln": "main",
    "oob_safe": "main",
    "race_vuln": "inc",
    "race_safe": "inc",
    "cmd_injection_vuln": "main",
    "cmd_injection_safe": "main",
    "arm_stack_vuln": "vulnerable",
    "arm_stack_safe": "safe",
    "inline_asm_vuln": "vulnerable",
    "inline_asm_safe": "safe",
    "opaque_predicate_vuln": "vulnerable",
    "opaque_predicate_safe": "safe",
    "dead_code_vuln": "vulnerable",
    "dead_code_safe": "safe",
    "control_flow_flatten_vuln": "vulnerable",
    "control_flow_flatten_safe": "safe",
}

_FULL_NAME_RE = re.compile(r"^(.*)_(\d+)_x86_O(\d)$")


def parse_binary_name(binary_filename):
    """Split a binary filename into (template_key, variation_index, opt_level).
    Returns None if the filename doesn't match the generate_dataset.py scheme."""
    m = _FULL_NAME_RE.match(Path(binary_filename).name)
    if not m:
        return None
    return m.group(1), int(m.group(2)), int(m.group(3))


def template_key(binary_filename):
    """Recover the generate_dataset.py template key from a binary filename."""
    parsed = parse_binary_name(binary_filename)
    return parsed[0] if parsed else None


def vulnerable_function_name(binary_filename):
    """Name of the function that carries this template's vuln/safe pattern,
    or None if the template key can't be resolved."""
    key = template_key(binary_filename)
    return VULN_FUNCTION_BY_TEMPLATE.get(key)


def node_labels(binary_filename, binary_label, function_names):
    """
    Per-function 0/1 vulnerability labels for one binary's call graph.

    Only meaningful when binary_label == 1: the function matching this
    template's known vulnerable-function name is labelled 1, every other
    function is 0. If the optimizer inlined that function into main (so
    it no longer exists as a separate symbol), the vulnerable code now
    physically lives inside main's compiled body, so main is labelled
    instead. Returns all zeros if neither can be resolved.
    """
    target = vulnerable_function_name(binary_filename) if binary_label == 1 else None
    return resolve_node_labels(binary_label, function_names, target)
