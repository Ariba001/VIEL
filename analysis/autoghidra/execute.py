import subprocess
from analysis.autoghidra.config import (
    GHIDRA_HEADLESS,
    GHIDRA_PROJECT_DIR,
    GHIDRA_SCRIPT_DIR,
    OUTPUT_CSV,
    BINARY_PATH,
)


def run_analysis():
    if not BINARY_PATH.exists():
        raise FileNotFoundError(f"Binary path not found: {BINARY_PATH}")

    GHIDRA_PROJECT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(GHIDRA_HEADLESS),
        str(GHIDRA_PROJECT_DIR),
        "analysis_project",
        "-overwrite",
        "-import", str(BINARY_PATH.resolve()),
        "-scriptPath", str(GHIDRA_SCRIPT_DIR.resolve()),
        "-postScript", "feature_extractor.java",
        str(OUTPUT_CSV.resolve()),
        "1",  # label arg passed to the Java script (must be a string)
    ]

    print("Running Ghidra headless analysis...")
    subprocess.run(cmd, check=True)
    print(f"Done. Output written to: {OUTPUT_CSV}")


if __name__ == "__main__":
    run_analysis()
