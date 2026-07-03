# VIEL — Vulnerability Intelligence and Exploit Learning

VIEL is a binary vulnerability detection research project. It automatically
identifies vulnerable functions in compiled Linux ELF binaries **without
source code**, using a combination of static analysis and machine learning.

---

## What it does

| Stage | Tool | Output |
|---|---|---|
| Dataset generation | `gcc` (C templates → ELF binaries) | `ai_sec_lab/binaries/` + `labels.csv` |
| Opcode extraction | `pyelftools` + `capstone` | `opcode_dataset_semantic.csv` |
| ML training (opcodes) | `scikit-learn` (TF-IDF + Logistic Regression) | classification report |
| CFG feature extraction | Ghidra headless + Java script | `report.csv` (17 features per function) |
| CFG feature extraction | `angr` (per-function) | `angr_dataset.csv` (15 features per function) |
| ML training (angr features) | `scikit-learn` (Random Forest) | function-level classification report |
| Call-graph construction | `angr` (whole-binary function call graph) | `graphs.pt` (PyTorch Geometric `Data` per binary) |
| Binary-level GNN | GraphSAGE (graph classification) | "is this binary vulnerable?" |
| Function-level GNN | GraphSAGE (node classification) | "which function is vulnerable?" (localization) |
| Cross-model comparison | — | ROC/confusion/F1 plots across all models |

**Vulnerability types covered:** buffer overflow, heap overflow, format string,
integer overflow, use-after-free, double free, null dereference, out-of-bounds,
race condition, command injection.

---

## Prerequisites

| Tool | Required for | Notes |
|---|---|---|
| Python 3.10–3.11 | everything | 3.12 not yet supported by angr |
| `gcc` | `generate_dataset.py` | Linux/WSL2/Docker only |
| [Ghidra](https://ghidra-sre.org/) | `execute.py` | free, runs on Windows too |
| Java 17+ | Ghidra | `openjdk-17-jre-headless` |

---

## Setup

### Option A — Linux / macOS (native, recommended)

```bash
# 1. Clone
git clone <repo-url>
cd VIEL

# 2. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure Ghidra path
cp .env.example .env
# Edit .env and set GHIDRA_HEADLESS to your Ghidra installation path
```

### Option B — Windows (WSL2)

Binary compilation (`generate_dataset.py`) requires Linux tooling.
WSL2 gives you a full Linux environment on Windows.

```powershell
# In PowerShell — install WSL2 if not already present
wsl --install

# Then open WSL and follow Option A steps inside WSL
```

The ML and opcode-extraction stages (`extract_opcodes.py`,
`logisticregression.py`) work natively on Windows without WSL.

### Option C — Docker (most reproducible)

```bash
# 1. Build the image
docker compose build

# 2. Edit docker-compose.yml — set the Ghidra volume to your local install path

# 3. Start a shell inside the container
docker compose run viel bash
```

---

## Usage

### Step 1 — Generate the binary dataset

> Requires `gcc` (Linux / WSL2 / Docker)

```bash
python scripts/generate_dataset.py
```

Compiles ~20 C vulnerability templates x 10 variations x 4 optimisation levels
into `ai_sec_lab/binaries/`. Writes labels to `ai_sec_lab/labels.csv`.

### Step 2 — Extract opcode sequences

```bash
python scripts/extract_opcodes.py
```

Disassembles each binary with Capstone and writes normalised opcode token
sequences (with PLT symbol resolution) to `ai_sec_lab/opcode_dataset_semantic.csv`.

### Step 3 — Train the classifier

```bash
python ml/vuln_detection/logisticregression.py
```

Trains a TF-IDF + Logistic Regression model. Prints accuracy, precision, recall,
F1, per-template breakdown, and the top vulnerability-indicative opcodes.

### Step 4 — Ghidra CFG feature extraction (optional)

> Requires Ghidra. Set `GHIDRA_HEADLESS` in `.env` first.

```bash
python -m analysis.autoghidra.execute
```

Runs Ghidra headless analysis on all binaries in `ai_sec_lab/binaries/` and
writes per-function CFG features to
`analysis/autoghidra/analysed_output/report.csv`.

Features extracted: `instructions`, `basic_blocks`, `edges`, `calls`,
`indirect_calls`, `jumps`, `loops`, `mem_reads`, `mem_writes`, `stack_size`,
`avg_bb_size`, `max_bb_size`, `call_density`, `mem_write_ratio`, `jump_density`.

### Step 5 — Run the rule-based risk scorer (optional)

```python
from analysis.autoghidra.decision_engine.rule_engine import evaluate
print(evaluate("analysis/autoghidra/analysed_output/report.csv"))
# -> 'High Risk' / 'Medium Risk' / 'Low Risk'
```

### Step 6 — angr per-function features + Random Forest

```bash
python scripts/extract_angr_features.py     # -> ai_sec_lab/angr_dataset.csv
python ml/vuln_detection/angr_classifier.py # -> models/angr_rf.pkl
```

### Step 7 — Build function call graphs and train the GNNs

```bash
python scripts/build_graphs.py              # -> ai_sec_lab/graphs.pt
python ml/vuln_detection/gstrain.py         # binary-level GraphSAGE -> models/graphsage.pt
python ml/vuln_detection/gstrain_node.py    # function-level GraphSAGE -> models/graphsage_node.pt
```

Each binary becomes one graph: user-defined functions are nodes (15 angr CFG
features + 2 type flags), edges are call relationships, and imported library
functions (`strcpy`, `malloc`, ...) are added as extra nodes so patterns like
`main -> vulnerable -> strcpy` show up as graph topology.

- **`gstrain.py`** trains a graph-classification model: one verdict per binary.
- **`gstrain_node.py`** trains a node-classification model: one verdict per
  *function*, enabling localization ("which function is vulnerable?") instead
  of just detection. Ground truth comes from
  `analysis/static/vuln_labels.py`, which maps each of the 30 synthetic
  templates to the function that actually carries its injected vuln/safe
  pattern (falling back to `main` if the optimizer inlined that function
  away). It uses a stratified 80/20 split by (template, variation) rather
  than the sorted split used elsewhere, so every vulnerability type is
  represented in both train and test — necessary for a meaningful
  localization score, since the sorted split holds out entire vulnerability
  families. On held-out variations it reaches **100% top-1 localization
  accuracy** across all 15 vulnerable template types, at the cost of low
  node-level precision (~0.23) — it never misses the real vulnerable
  function (recall 1.0), but flags some structurally-similar safe functions
  as candidates too. Treat it as a triage ranking, not a definitive verdict.

### Step 8 — Compare all models

```bash
python ml/compare_models.py
```

Evaluates TF-IDF+LR, angr RF, Ghidra RF, and binary-level GraphSAGE on the
same held-out set of binaries and writes `models/comparison_metrics.csv`
plus ROC/confusion/F1 plots to `models/`.

### Step 9 — Predict on a new binary

```bash
python predict.py path/to/binary --model tfidf       # opcode TF-IDF + LR
python predict.py path/to/binary --model angr         # angr RF, per function
python predict.py path/to/binary --model ghidra        # Ghidra RF, per function
python predict.py path/to/binary --model graphsage      # binary-level GNN verdict
python predict.py path/to/binary --model localize        # function-level GNN localization
```

`--model localize` is the function-level GNN: it ranks every user-defined
function in the binary by predicted vulnerability probability, so instead of
"this binary is vulnerable" it answers "this specific function looks
vulnerable."

---

## Directory structure

```
VIEL/
├── ai_sec_lab/
│   ├── binaries/          # compiled ELF binaries (generated)
│   ├── c_src/             # generated C source files
│   ├── labels.csv         # binary name -> label (0=safe, 1=vuln)
│   ├── opcode_dataset_semantic.csv   # opcode token sequences
│   ├── angr_dataset.csv   # per-function angr CFG features (generated)
│   └── graphs.pt          # per-binary function call graphs (generated)
│
├── analysis/
│   ├── autoghidra/
│   │   ├── config.py              # reads GHIDRA_HEADLESS from .env
│   │   ├── execute.py             # launches Ghidra headless
│   │   ├── scripts/
│   │   │   └── feature_extractor.java   # Ghidra post-analysis script
│   │   ├── decision_engine/
│   │   │   └── rule_engine.py     # rule-based risk scorer
│   │   └── analysed_output/
│   │       └── report.csv         # Ghidra output (generated)
│   └── static/
│       ├── angr_engine.py         # angr per-function feature extraction
│       ├── graph_builder.py       # angr function call graph -> PyG Data
│       ├── vuln_labels.py         # per-function ground truth for the synthetic dataset
│       ├── extract_cfg.py         # angr CFG -> JSON
│       ├── extract_functions.py   # angr function list -> JSON
│       └── symbolic/
│           └── symbolic_features.py   # angr symbolic execution
│
├── ml/
│   ├── compare_models.py          # cross-model comparison report
│   └── vuln_detection/
│       ├── logisticregression.py  # TF-IDF + LR classifier
│       ├── angr_classifier.py     # Random Forest on angr CFG features
│       ├── ghidra_classifier.py   # Random Forest on Ghidra CFG features
│       ├── graphsage.py           # binary-level GraphSAGE model
│       ├── gstrain.py             # trains graphsage.py (graph classification)
│       ├── graphsage_node.py      # function-level GraphSAGE model
│       └── gstrain_node.py        # trains graphsage_node.py (node classification)
│
├── scripts/
│   ├── generate_dataset.py        # compile C templates -> ELF binaries
│   ├── extract_opcodes.py         # ELF -> opcode token sequences
│   ├── extract_angr_features.py   # ELF -> ai_sec_lab/angr_dataset.csv
│   ├── build_graphs.py            # ELF -> ai_sec_lab/graphs.pt
│   └── feature_extractor.py      # basic capstone disassembly helper
│
├── predict.py              # CLI: run any trained model on a new binary
├── .env.example           # copy to .env and fill in GHIDRA_HEADLESS
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
└── requirements.txt
```

---

## Troubleshooting

**`gcc: command not found`**
You are on Windows outside WSL. Run `generate_dataset.py` inside WSL2 or Docker.

**`analyzeHeadless: command not found`**
Copy `.env.example` to `.env` and set `GHIDRA_HEADLESS` to the full path of
the `analyzeHeadless` (Linux) or `analyzeHeadless.bat` (Windows) script inside
your Ghidra installation.

**`angr` install fails on Windows**
Install Visual C++ Build Tools first, or use WSL2/Docker.

**`ModuleNotFoundError` when running `execute.py`**
Run it as a module from the project root so Python resolves the package:
```bash
python -m analysis.autoghidra.execute
```

---

## Contributing

1. Fork the repo and create a feature branch.
2. Run `pip install -r requirements.txt` in a fresh virtual environment.
3. Open a pull request describing your change.
