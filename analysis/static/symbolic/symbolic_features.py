import angr
import os

UNSAFE_FUNCS = ["gets", "strcpy", "sprintf", "scanf"]

def extract_symbolic_features(binary_path):
    proj = angr.Project(binary_path, auto_load_libs=False)

    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state)

    features = {
        "symbolic_paths": 0,
        "reaches_unsafe": 0
    }

    try:
        simgr.explore(n=50)
        features["symbolic_paths"] = len(simgr.active)

        for f in proj.kb.functions.values():
            if f.name in UNSAFE_FUNCS:
                features["reaches_unsafe"] = 1

    except Exception:
        pass

    return features
