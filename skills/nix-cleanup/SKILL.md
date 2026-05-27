---
name: nix-cleanup
description: "Remove nix GC roots left by this campaign's harness builds, freeing store paths for collection. Safe to run after a campaign is complete. — usage: [--gc] [--dry-run]"
argument-hint: "[--gc] [--dry-run]"
---

Runs `scripts/nix-cleanup.sh` to remove the `result-*` symlinks (GC roots) that `nix-build.sh` created under `fuzz/harnesses/*/harness/`. Once removed, nix can reclaim the store paths on the next garbage-collection run.

Flags:
- `--gc` — run `nix-store --gc` immediately after removing roots
- `--dry-run` — show what would be removed without making changes

Run this after a campaign is complete and you no longer need to rebuild the harnesses. The harness source, manifests, corpus, and findings are untouched — only the compiled nix store outputs are freed.

```bash
bash ${CLAUDE_PLUGIN_ROOT}/scripts/nix-cleanup.sh $ARGUMENTS
```
