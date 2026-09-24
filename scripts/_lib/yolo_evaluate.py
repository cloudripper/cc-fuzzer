#!/usr/bin/env python3
"""yolo_evaluate.py — re-export shim for cc_fuzzer_core.state.yolo_evaluate (the advisory dynamic-YOLO evaluation block).

The module moved into the core package (UPDATE_ROADMAP.md §2 row 3). `import
yolo_evaluate` binds the core module itself; the testing CLI is unchanged:
  python3 yolo_evaluate.py <current.json>   (prints the block as JSON)
"""
import sys

from cc_fuzzer_core.state import yolo_evaluate as _core

if __name__ == "__main__":
    import json

    print(json.dumps(_core.evaluate_from_current(sys.argv[1]), indent=2))
else:
    sys.modules[__name__] = _core
