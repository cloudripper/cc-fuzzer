#!/usr/bin/env python3
"""enums.py — re-export shim for cc_fuzzer_core.enums (the state-enum SSOT).

The enum definitions moved into the core package (UPDATE_ROADMAP.md §2 row 1);
this file keeps both old interfaces working unchanged:

  Python:  `import enums` from a sibling _lib module binds the core module
           itself (same objects, so there is still exactly one definition).
  CLI:     python3 enums.py print <name> [--sep <s>] | check <name> <value>
           | doc-drift [STATE_SCHEMA.md]      (== `cc-fuzzer enums ...`)

cc_fuzzer_core is importable because scripts/_lib/root.sh puts the checkout's
src/ on PYTHONPATH (or the package is installed).
"""
import sys

from cc_fuzzer_core import enums as _core

if __name__ == "__main__":
    sys.exit(_core.main(sys.argv[1:]))
else:
    sys.modules[__name__] = _core
