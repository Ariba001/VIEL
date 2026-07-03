"""
Regression smoke test for predict.py's GNN-backed modes.

Not a correctness benchmark -- just a tripwire so that future changes to
graph_builder.py / gstrain.py / gstrain_node.py / predict.py can't
silently break the CLI's exit codes or JSON schema without a test
failing. Requires the trained models under models/ (run
scripts/build_graphs.py + ml/vuln_detection/gstrain.py + gstrain_node.py
first if they're missing).
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT   = Path(__file__).resolve().parent.parent
PREDICT_PY  = REPO_ROOT / "predict.py"
BINARIES    = REPO_ROOT / "ai_sec_lab" / "binaries"
MODELS_DIR  = REPO_ROOT / "models"

requires_graphsage      = pytest.mark.skipif(
    not (MODELS_DIR / "graphsage.pt").exists(), reason="models/graphsage.pt not built")
requires_graphsage_node = pytest.mark.skipif(
    not (MODELS_DIR / "graphsage_node.pt").exists(), reason="models/graphsage_node.pt not built")


def run_predict(binary_name, model, extra_args=()):
    binary = BINARIES / binary_name
    assert binary.exists(), f"fixture binary missing: {binary}"
    result = subprocess.run(
        [sys.executable, str(PREDICT_PY), str(binary), "--model", model, "--json", *extra_args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )
    return result


@requires_graphsage
def test_graphsage_flags_known_vulnerable_binary():
    result = run_predict("heap_overflow_vuln_2_x86_O2", "graphsage")
    payload = json.loads(result.stdout)
    assert payload["verdict"] == "VULNERABLE"
    assert result.returncode == 1


@requires_graphsage
def test_graphsage_json_schema():
    result = run_predict("heap_overflow_vuln_2_x86_O2", "graphsage")
    payload = json.loads(result.stdout)
    assert set(payload) == {"binary", "model", "verdict", "confidence", "num_nodes", "num_edges"}
    assert 0.0 <= payload["confidence"] <= 1.0


@requires_graphsage_node
def test_localize_points_to_known_vulnerable_function():
    result = run_predict("race_vuln_9_x86_O2", "localize")
    payload = json.loads(result.stdout)
    assert payload["top_suspect"] == "inc"
    assert result.returncode == 1


@requires_graphsage_node
def test_localize_functions_are_ranked_descending():
    result = run_predict("race_vuln_9_x86_O2", "localize")
    payload = json.loads(result.stdout)
    scores = [f["score"] for f in payload["functions"]]
    assert scores == sorted(scores, reverse=True)
