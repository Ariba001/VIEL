from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

GHIDRA_HEADLESS = "/home/giyu20/tools/ghidra/support/analyzeHeadless"

GHIDRA_PROJECT_DIR = BASE_DIR / "ghidra_projects"
GHIDRA_SCRIPT_DIR = BASE_DIR / "ghidra_scripts"
OUTPUT_JSON = BASE_DIR / "analysis_output" / "report.json"