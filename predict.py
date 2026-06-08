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
        """,
    )
    parser.add_argument("binary", help="Path to the ELF binary to analyse")
    parser.add_argument(
        "--model",
        choices=["tfidf", "ghidra", "angr"],
        default="tfidf",
        help="Which model to use (default: tfidf)",
    )
    args = parser.parse_args()

    if not Path(args.binary).exists():
        console.print(f"[red]File not found: {args.binary}[/red]")
        sys.exit(1)

    if args.model == "tfidf":
        predict_tfidf(args.binary)
    elif args.model == "ghidra":
        predict_ghidra(args.binary)
    else:
        predict_angr(args.binary)


if __name__ == "__main__":
    main()
