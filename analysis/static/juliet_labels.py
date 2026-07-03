"""
Per-function ground truth for Juliet Test Suite binaries ingested by
scripts/ingest_juliet.py.

Each Juliet test case is compiled into two SEPARATE binaries:
    <testcase>__<opt>__bad    -DINCLUDEMAIN -DOMITGOOD
    <testcase>__<opt>__good   -DINCLUDEMAIN -DOMITBAD

OMITGOOD/OMITBAD strip the sibling function entirely at compile time, so
unlike the synthetic ai_sec_lab dataset (analysis.static.vuln_labels),
ground truth needs no per-template lookup table: a bad binary's
vulnerable function is simply whichever function name ends in "_bad" --
guaranteed unique and unambiguous since the good variants never made it
into that binary at all.
"""

from analysis.static.label_utils import resolve_node_labels


def parse_binary_name(binary_filename):
    """Split an ingest_juliet.py filename into (cwe_category, testcase_id,
    opt_level, variant). Filenames are "{cwe_dir}__{testcase_id}__{opt}__{bad|good}"."""
    cwe_category, testcase_id, opt, variant = binary_filename.split("__")
    return cwe_category, testcase_id, opt, variant


def cwe_category(binary_filename):
    """The CWE directory name (e.g. 'CWE121_Stack_Based_Buffer_Overflow')
    this binary's test case belongs to."""
    return parse_binary_name(binary_filename)[0]


def vulnerable_function_name(binary_filename):
    """The '<testcase>_bad' function name a bad-variant binary should
    contain, or None if this isn't one (e.g. it's a good-variant binary,
    or wasn't produced by ingest_juliet.py's naming scheme)."""
    if not binary_filename.endswith("__bad"):
        return None
    testcase = binary_filename[: -len("__bad")].rsplit("__", 1)[0]
    return f"{testcase}_bad"


def node_labels(binary_filename, binary_label, function_names):
    target = vulnerable_function_name(binary_filename) if binary_label == 1 else None
    return resolve_node_labels(binary_label, function_names, target)
