#!/usr/bin/env python3
"""ceiling_probe.py — re-export shim for cc_fuzzer_core.state.ceiling (the deterministic plateau / structural-ceiling probe).

The module moved into the core package (UPDATE_ROADMAP.md §2 row 3). `import
ceiling_probe` binds the core module itself; the testing CLI is unchanged:
  python3 ceiling_probe.py <current.json>   (writes a ceiling-probe snapshot, prints the block)
"""
import sys

from cc_fuzzer_core.state import ceiling as _core

if __name__ == "__main__":
    # python3 ceiling_probe.py <current.json>: write a ceiling-probe/v1 snapshot
    # next to it and print the block (== `cc-fuzzer state ceiling-probe`).
    import json
    from cc_fuzzer_core.paths import Campaign
    from pathlib import Path

    state = Path(sys.argv[1]).resolve().parent
    r = _core.probe(Campaign(state.parent.parent, state.parent, state), sys.argv[1])
    print(json.dumps(r.block, indent=2))
    print(f"\nceiling-probe: stage {r.block['ladder_stage']} | {r.block['summary']}\n  → {r.path}",
          file=sys.stderr)
else:
    sys.modules[__name__] = _core
