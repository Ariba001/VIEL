from pathlib import Path
import subprocess
# ---- PROJECT ROOT ----
PROJECT_ROOT = Path(__file__).resolve().parents[2]

GHIDRA_HEADLESS = Path("/home/giyu20/tools/ghidra/support/analyzeHeadless")

GHIDRA_PROJECT_DIR = PROJECT_ROOT / "ghidra_projects"
SCRIPT_PATH = PROJECT_ROOT / "analysis" / "autoghidra" / "scripts"

OUTPUT_CSV = PROJECT_ROOT / "analysis" / "autoghidra" / "analysed_output" / "report.csv"

BINARY_PATH = PROJECT_ROOT / "ai_sec_lab" / "binaries"


def run_analysis():

    if not BINARY_PATH.exists():
        raise FileNotFoundError(f"Binary path not found: {BINARY_PATH}")

    GHIDRA_PROJECT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    label = 1

    cmd = [
        str(GHIDRA_HEADLESS),
        str(GHIDRA_PROJECT_DIR),
        "analysis_project",
        "-overwrite",
        "-import", str(BINARY_PATH.resolve()),
        "-scriptPath", str(SCRIPT_PATH.resolve()),
        "-postScript", "feature_extractor.java",
        str(OUTPUT_CSV.resolve()),
        label
    ]

    print("Running Ghidra Headless...")
    subprocess.run(cmd, check=True)
    print("Done.")


if __name__ == "__main__":
    run_analysis()