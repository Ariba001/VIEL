import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Set GHIDRA_HEADLESS in your .env file or as an environment variable.
# Linux/macOS : /path/to/ghidra/support/analyzeHeadless
# Windows     : C:\path\to\ghidra\support\analyzeHeadless.bat
GHIDRA_HEADLESS = os.getenv("GHIDRA_HEADLESS", "analyzeHeadless")

GHIDRA_PROJECT_DIR = PROJECT_ROOT / "ghidra_projects"
GHIDRA_SCRIPT_DIR  = PROJECT_ROOT / "analysis" / "autoghidra" / "scripts"
OUTPUT_CSV         = PROJECT_ROOT / "analysis" / "autoghidra" / "analysed_output" / "report.csv"
BINARY_PATH        = PROJECT_ROOT / "ai_sec_lab" / "binaries"