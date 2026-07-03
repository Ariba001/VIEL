"""
Predict vulnerability in an ELF binary using trained models.

Usage:
    python predict.py <binary_path>
    python predict.py <binary_path> --model ghidra

Requirements:
    - TF-IDF model : run ml/vuln_detection/logisticregression.py first
    - Ghidra model : run ml/vuln_detection/ghidra_classifier.py first
"""

import argparse
import json
import sys
import os
from pathlib import Path

# Ensure project root is on the path when running as a script
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import joblib
from rich.console import Console
from rich.table import Table
from rich import box

MODELS_DIR = Path(__file__).resolve().parent / "models"
console = Console()


# ── TF-IDF + Logistic Regression ─────────────────────────────────────────────

def predict_tfidf(binary_path: str):
    model_path = MODELS_DIR / "lr_tfidf.pkl"
    vec_path   = MODELS_DIR / "vectorizer.pkl"

    if not model_path.exists() or not vec_path.exists():
        console.print("[red]TF-IDF model not found.[/red]")
        console.print("Run: [bold]python ml/vuln_detection/logisticregression.py[/bold]")
        sys.exit(1)

    from scripts.opcode_utils import extract_functions_from_binary

    model      = joblib.load(model_path)
    vectorizer = joblib.load(vec_path)

    console.print(f"\nAnalysing [cyan]{Path(binary_path).name}[/cyan] (TF-IDF model)...")
    functions = extract_functions_from_binary(binary_path)

    if not functions:
        console.print("[yellow]No functions found — binary may be stripped or not ELF.[/yellow]")
        return

    tokens = [f["tokens"] for f in functions]
    X      = vectorizer.transform(tokens)
    preds  = model.predict(X)
    probs  = model.predict_proba(X)

    table = Table(title=f"Results: {Path(binary_path).name}", box=box.ROUNDED)
    table.add_column("Function",    style="cyan",  no_wrap=True)
    table.add_column("Verdict",     style="bold")
    table.add_column("Confidence",  justify="right")

    for func, pred, prob in zip(functions, preds, probs):
        if pred == 1:
            verdict = "[red]VULNERABLE[/red]"
        else:
            verdict = "[green]SAFE[/green]"
        table.add_row(func["function"], verdict, f"{max(prob):.1%}")

    console.print(table)

    vuln_count = int(preds.sum())
    total      = len(preds)
    color      = "red" if vuln_count else "green"
    console.print(f"\n[{color}]{vuln_count}/{total} function(s) flagged as vulnerable.[/{color}]")


# ── Random Forest on Ghidra CFG features ─────────────────────────────────────

def predict_ghidra(binary_path: str):
    model_path    = MODELS_DIR / "ghidra_rf.pkl"
    features_path = MODELS_DIR / "ghidra_features.pkl"

    if not model_path.exists():
        console.print("[red]Ghidra model not found.[/red]")
        console.print("Run: [bold]python ml/vuln_detection/ghidra_classifier.py[/bold]")
        console.print("(Also requires Ghidra analysis to have been run on this binary.)")
        sys.exit(1)

    # Ghidra model predicts from the report.csv produced by execute.py.
    # For inline inference on a new binary you'd need to run Ghidra headless first.
    report_csv = Path("analysis/autoghidra/analysed_output/report.csv")
    if not report_csv.exists():
        console.print("[red]Ghidra report.csv not found.[/red]")
        console.print("Run: [bold]python -m analysis.autoghidra.execute[/bold]")
        sys.exit(1)

    import pandas as pd
    model    = joblib.load(model_path)
    features = joblib.load(features_path)

    df = pd.read_csv(report_csv)
    binary_name = Path(binary_path).name
    rows = df[df["binary"] == binary_name]

    if rows.empty:
        console.print(f"[yellow]Binary '{binary_name}' not found in Ghidra report.[/yellow]")
        console.print("Re-run Ghidra analysis to include this binary.")
        sys.exit(1)

    X      = rows[features].apply(pd.to_numeric, errors="coerce").fillna(0).values
    preds  = model.predict(X)
    probs  = model.predict_proba(X)

    table = Table(title=f"Results: {binary_name} (Ghidra RF)", box=box.ROUNDED)
    table.add_column("Function",   style="cyan", no_wrap=True)
    table.add_column("Verdict",    style="bold")
    table.add_column("Confidence", justify="right")

    for (_, row), pred, prob in zip(rows.iterrows(), preds, probs):
        verdict = "[red]VULNERABLE[/red]" if pred == 1 else "[green]SAFE[/green]"
        table.add_row(row["function"], verdict, f"{max(prob):.1%}")

    console.print(table)

    vuln_count = int(preds.sum())
    total      = len(preds)
    color      = "red" if vuln_count else "green"
    console.print(f"\n[{color}]{vuln_count}/{total} function(s) flagged as vulnerable.[/{color}]")


# ── angr Random Forest ───────────────────────────────────────────────────────

def predict_angr(binary_path: str):
    model_path    = MODELS_DIR / "angr_rf.pkl"
    features_path = MODELS_DIR / "angr_features.pkl"

    if not model_path.exists():
        console.print("[red]angr model not found.[/red]")
        console.print("Run: [bold]python scripts/extract_angr_features.py[/bold]")
        console.print("Then: [bold]python ml/vuln_detection/angr_classifier.py[/bold]")
        sys.exit(1)

    try:
        from analysis.static.angr_engine import extract_binary_features
    except ImportError:
        console.print("[red]angr is not installed. Run: pip install angr[/red]")
        sys.exit(1)

    import pandas as pd
    model    = joblib.load(model_path)
    features = joblib.load(features_path)

    console.print(f"\nAnalysing [cyan]{Path(binary_path).name}[/cyan] (angr RF model)...")
    console.print("[dim]Running CFG analysis — may take a few seconds...[/dim]")

    functions = extract_binary_features(binary_path)

    if not functions:
        console.print("[yellow]No functions extracted — binary may not be ELF or unsupported.[/yellow]")
        return

    df = pd.DataFrame(functions)
    X  = df[features].apply(pd.to_numeric, errors="coerce").fillna(0).values
    preds = model.predict(X)
    probs = model.predict_proba(X)

    table = Table(title=f"Results: {Path(binary_path).name} (angr RF)", box=box.ROUNDED)
    table.add_column("Function",   style="cyan", no_wrap=True)
    table.add_column("Verdict",    style="bold")
    table.add_column("Confidence", justify="right")

    for func, pred, prob in zip(functions, preds, probs):
        verdict = "[red]VULNERABLE[/red]" if pred == 1 else "[green]SAFE[/green]"
        table.add_row(func["function"], verdict, f"{max(prob):.1%}")

    console.print(table)

    vuln_count = int(preds.sum())
    total      = len(preds)
    color      = "red" if vuln_count else "green"
    console.print(f"\n[{color}]{vuln_count}/{total} function(s) flagged as vulnerable.[/{color}]")


# ── GraphSAGE GNN ─────────────────────────────────────────────────────────────

def predict_graphsage(binary_path: str, json_output: bool = False):
    model_path  = MODELS_DIR / "graphsage.pt"
    scaler_path = MODELS_DIR / "graphsage_scaler.pt"

    for p, name in [(model_path, "graphsage.pt"), (scaler_path, "graphsage_scaler.pt")]:
        if not p.exists():
            console.print(f"[red]{name} not found.[/red]")
            console.print("Run: [bold]python scripts/build_graphs.py[/bold]")
            console.print("Then: [bold]python ml/vuln_detection/gstrain.py[/bold]")
            sys.exit(1)

    try:
        import torch
        import torch.nn.functional as F
        from torch_geometric.data import Batch
        from analysis.static.graph_builder import build_binary_graph, GRAPH_NODE_FEATURES
        from ml.vuln_detection.graphsage import GraphSAGEClassifier
    except ImportError as e:
        console.print(f"[red]Import error: {e}[/red]")
        console.print("Run: [bold]pip install angr torch torch_geometric[/bold]")
        sys.exit(1)

    if not json_output:
        console.print(f"\nAnalysing [cyan]{Path(binary_path).name}[/cyan] (GraphSAGE GNN)...")
        console.print("[dim]Building function call graph — may take a few seconds...[/dim]")

    g = build_binary_graph(binary_path, label=0)
    if g is None:
        if json_output:
            print(json.dumps({"binary": Path(binary_path).name, "model": "graphsage", "error": "could not build graph"}))
            sys.exit(2)
        console.print("[yellow]Could not build graph — binary may not be ELF or is unsupported.[/yellow]")
        return

    scaler = torch.load(scaler_path, weights_only=True)
    g.x = (g.x - scaler["mean"]) / scaler["std"]

    model = GraphSAGEClassifier(in_channels=GRAPH_NODE_FEATURES)
    model.load_state_dict(torch.load(model_path, weights_only=True))
    model.eval()

    batch = Batch.from_data_list([g])
    with torch.no_grad():
        out  = model(batch.x, batch.edge_index, batch.batch)
        prob = F.softmax(out, dim=1)
        pred = out.argmax(dim=1).item()
        conf = prob[0, pred].item()

    if json_output:
        print(json.dumps({
            "binary": Path(binary_path).name,
            "model": "graphsage",
            "verdict": "VULNERABLE" if pred == 1 else "SAFE",
            "confidence": round(conf, 4),
            "num_nodes": g.num_nodes,
            "num_edges": g.num_edges,
        }))
        sys.exit(1 if pred == 1 else 0)

    color   = "red" if pred == 1 else "green"
    verdict = f"[{color}]{'VULNERABLE' if pred == 1 else 'SAFE'}[/{color}]"

    table = Table(title=f"Results: {Path(binary_path).name} (GraphSAGE GNN)", box=box.ROUNDED)
    table.add_column("Binary",     style="cyan", no_wrap=True)
    table.add_column("Verdict",    style="bold")
    table.add_column("Confidence", justify="right")
    table.add_column("Nodes",      justify="right")
    table.add_column("Edges",      justify="right")
    table.add_row(
        Path(binary_path).name, verdict, f"{conf:.1%}",
        str(g.num_nodes), str(g.num_edges),
    )
    console.print(table)
    console.print(
        f"\n[{color}]Binary classified as {'VULNERABLE' if pred==1 else 'SAFE'} "
        f"({conf:.1%} confidence).[/{color}]"
    )


# ── GraphSAGE node classifier — function-level localization ──────────────────

def predict_localize(binary_path: str, json_output: bool = False):
    model_path  = MODELS_DIR / "graphsage_node.pt"
    scaler_path = MODELS_DIR / "graphsage_node_scaler.pt"

    for p, name in [(model_path, "graphsage_node.pt"), (scaler_path, "graphsage_node_scaler.pt")]:
        if not p.exists():
            console.print(f"[red]{name} not found.[/red]")
            console.print("Run: [bold]python scripts/build_graphs.py[/bold]")
            console.print("Then: [bold]python ml/vuln_detection/gstrain_node.py[/bold]")
            sys.exit(1)

    try:
        import torch
        import torch.nn.functional as F
        from analysis.static.graph_builder import build_binary_graph, GRAPH_NODE_FEATURES
        from ml.vuln_detection.graphsage_node import GraphSAGENodeClassifier
    except ImportError as e:
        console.print(f"[red]Import error: {e}[/red]")
        console.print("Run: [bold]pip install angr torch torch_geometric[/bold]")
        sys.exit(1)

    if not json_output:
        console.print(f"\nAnalysing [cyan]{Path(binary_path).name}[/cyan] (GraphSAGE function-level localization)...")
        console.print("[dim]Building function call graph — may take a few seconds...[/dim]")

    g = build_binary_graph(binary_path, label=0)
    if g is None:
        if json_output:
            print(json.dumps({"binary": Path(binary_path).name, "model": "localize", "error": "could not build graph"}))
            sys.exit(2)
        console.print("[yellow]Could not build graph — binary may not be ELF or is unsupported.[/yellow]")
        return

    scaler = torch.load(scaler_path, weights_only=True)
    g.x = (g.x - scaler["mean"]) / scaler["std"]

    model = GraphSAGENodeClassifier(in_channels=GRAPH_NODE_FEATURES)
    model.load_state_dict(torch.load(model_path, weights_only=True))
    model.eval()

    with torch.no_grad():
        out  = model(g.x, g.edge_index)
        prob = F.softmax(out, dim=1)[:, 1]

    user_idx = [i for i in range(g.num_nodes) if g.is_user_mask[i]]
    rows = sorted(
        ((g.func_names[i], prob[i].item()) for i in user_idx),
        key=lambda r: r[1], reverse=True,
    )

    if json_output:
        print(json.dumps({
            "binary": Path(binary_path).name,
            "model": "localize",
            "functions": [{"name": name, "score": round(score, 4)} for name, score in rows],
            "top_suspect": rows[0][0] if rows and rows[0][1] > 0.5 else None,
        }))
        sys.exit(1 if rows and rows[0][1] > 0.5 else 0)

    table = Table(title=f"Function-level localization: {Path(binary_path).name}", box=box.ROUNDED)
    table.add_column("Function",   style="cyan", no_wrap=True)
    table.add_column("Vuln score", justify="right")
    table.add_column("Verdict",    style="bold")

    for name, score in rows:
        verdict = "[red]SUSPECT[/red]" if score > 0.5 else ""
        table.add_row(name, f"{score:.1%}", verdict)

    console.print(table)

    if rows and rows[0][1] > 0.5:
        console.print(
            f"\n[red]Most likely vulnerable function: {rows[0][0]} "
            f"({rows[0][1]:.1%} confidence).[/red]"
        )
    else:
        console.print("\n[green]No function scored above 50% — binary looks safe.[/green]")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Predict vulnerabilities in a compiled ELF binary.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python predict.py ai_sec_lab/binaries/arm_stack_vuln_0_x86_O0
  python predict.py path/to/binary --model ghidra
  python predict.py path/to/binary --model angr
  python predict.py path/to/binary --model graphsage
  python predict.py path/to/binary --model localize
        """,
    )
    parser.add_argument("binary", help="Path to the ELF binary to analyse")
    parser.add_argument(
        "--model",
        choices=["tfidf", "ghidra", "angr", "graphsage", "localize"],
        default="tfidf",
        help="Which model to use (default: tfidf). 'localize' points to the "
             "specific function most likely to be vulnerable.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Machine-readable JSON on stdout instead of a table (graphsage/localize "
             "only). Exit code 1 if vulnerable/a suspect function was found, 0 otherwise "
             "-- suitable for CI gating.",
    )
    args = parser.parse_args()

    if not Path(args.binary).exists():
        console.print(f"[red]File not found: {args.binary}[/red]")
        sys.exit(1)

    if args.model == "tfidf":
        predict_tfidf(args.binary)
    elif args.model == "ghidra":
        predict_ghidra(args.binary)
    elif args.model == "angr":
        predict_angr(args.binary)
    elif args.model == "localize":
        predict_localize(args.binary, json_output=args.json)
    else:
        predict_graphsage(args.binary, json_output=args.json)


if __name__ == "__main__":
    main()
