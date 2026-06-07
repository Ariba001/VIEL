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
| ML training | `scikit-learn` (TF-IDF + Logistic Regression) | classification report |
| CFG feature extraction | Ghidra headless + Java script | `report.csv` (17 features per function) |
| Static analysis utilities | `angr` | CFG JSON, function list, symbolic paths |

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

---

## Directory structure

```
VIEL/
├── ai_sec_lab/
│   ├── binaries/          # compiled ELF binaries (generated)
│   ├── c_src/             # generated C source files
│   ├── labels.csv         # binary name -> label (0=safe, 1=vuln)
│   └── opcode_dataset_semantic.csv   # opcode token sequences
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
│       ├── extract_cfg.py         # angr CFG -> JSON
│       ├── extract_functions.py   # angr function list -> JSON
│       └── symbolic/
│           └── symbolic_features.py   # angr symbolic execution
│
├── ml/
│   └── vuln_detection/
│       └── logisticregression.py  # TF-IDF + LR classifier
│
├── scripts/
│   ├── generate_dataset.py        # compile C templates -> ELF binaries
│   ├── extract_opcodes.py         # ELF -> opcode token sequences
│   └── feature_extractor.py      # basic capstone disassembly helper
│
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
