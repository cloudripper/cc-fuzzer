#!/usr/bin/env python3
"""toolbox_eval.py — re-export shim for cc_fuzzer_core.state.toolbox (the deterministic lever board).

The module moved into the core package (UPDATE_ROADMAP.md §2 row 3). `import
toolbox_eval` binds the core module itself; the testing CLI is unchanged:
  python3 toolbox_eval.py <current.json>   (prints the block as JSON)
"""
import sys

from cc_fuzzer_core.state import toolbox as _core

if __name__ == "__main__":
    import json

    print(json.dumps(_core.compute_from_current(sys.argv[1]), indent=2))
else:
    sys.modules[__name__] = _core
