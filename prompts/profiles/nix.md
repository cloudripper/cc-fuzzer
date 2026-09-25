# Profile: nix — the Claude Code plugin inside its reproducible Nix dev shell.
#
# This file is the plugin's ADAPTER, so it is the one place allowed to name
# Claude Code's ${CLAUDE_PLUGIN_ROOT}. A prompt source never does: it writes
# {{cc}} / {{scripts}} / {{root}} and asks for <!-- profile:environment -->.

<!-- slot:vars -->
# Who performs the directives this engine emits, named the way THIS host
# names it. The prompts say {{driver}}; only the profile knows the word.
driver        = main thread
driver_hyphen = main-thread
schedule_api  = ScheduleWakeup
dispatch_api  = `Agent`/`Task` tool
# The core CLI. On PATH where the package is pip-installed; inside the plugin
# it is the checkout's wrapper, because an agent's Bash call inherits
# CLAUDE_PLUGIN_ROOT but not CC_FUZZER_ROOT.
cc      = ${CLAUDE_PLUGIN_ROOT}/bin/cc-fuzzer
# Scripts that have not been ported to a core verb yet. Each port turns one
# `{{scripts}}/x.sh` call site into `{{cc}} <verb>`.
scripts = ${CLAUDE_PLUGIN_ROOT}/scripts
root    = ${CLAUDE_PLUGIN_ROOT}

<!-- slot:symcc_runtime -->
   `source {{scripts}}/_lib/nix-tools.sh && nix_tool symcc`. This consults
   `fuzz/state/nix-env.json` before falling back to PATH — `which symcc` alone is
   unreliable when the session inherited a stripped environment. Fix path:
   `nix develop {{root}} && claude`, or `{{scripts}}/install-symcc.sh` outside Nix.

<!-- slot:environment_gate -->
**NIX ENVIRONMENT CHECK**: read `fuzz/state/nix-environment-issues.json` (written by `nix-env-reconcile.sh` at session start); if it contains any `severity=error` issues affecting harnesses committed to `build_backend=nix`, **stop and print each issue's `remediation.human_message`**. Warnings are surfaced but don't block; skip if the file is absent.

<!-- slot:driver_bash_note -->
Under the recommended ctxctl configuration (see README), the main thread cannot run Bash directly; only you and your sibling specialists can.

<!-- slot:build_backend -->
### Step 0: Read committed build backend

Before writing any files, check whether this campaign has committed to a nix build backend:

```bash
python3 -c "
import json, sys
try:
    import os
    hs = os.environ.get('FUZZ_STATE_DIR', 'fuzz/state') + '/harnesses.json'
    doc = json.load(open(hs))
    name = sys.argv[1] if len(sys.argv) > 1 else ''
    for h in doc.get('harnesses', []):
        if not name or h.get('name') == name:
            print(h.get('build_backend', 'legacy'))
            sys.exit(0)
    print('legacy')
except Exception:
    print('legacy')
" "$HARNESS_NAME" 2>/dev/null || echo legacy
```

**If the result is `nix` (campaign already promoted to nix backend):** skip Mode A/B entirely and proceed directly to the **Nix build path** below. `build_backend=nix` is sticky — once set by `harness-set.sh promote-to-nix`, it stays nix until an explicit `harness-set.sh fallback-backend` call.

**If the result is `legacy` (the default for all non-FHS campaigns):** proceed with the standard Mode A/B workflow below.

### Nix build path (CC_FUZZER_FHS=1 + build_backend=nix)

> **Whole-library targets:** the per-harness nix path below compiles a handful
> of source files (`clang src/*`). If the target is a whole **instrumented
> library** that only the project's own build system can produce (e.g. a large
> shared library produced by the project's own meson/cmake/autotools build),
> use **monolithic mode** instead: write a
> `build_mode: "monolithic"` manifest that points at the project's own
> derivation (built with cc-fuzzer's pinned toolchain — `ccfuzzer.lib.${system}.clangStdenv`
> — or coverage breaks). Full recipe + the toolchain-pin contract:
> `{{root}}/references/nix-monolithic.md`.

This path applies when:
1. `$CC_FUZZER_FHS=1` (inside the cc-fuzzer nix FHS shell), AND
2. The harness's `build_backend` is `nix` (explicitly promoted), OR this is a COLD start and the user is in FHS (auto-nix for new campaigns)

**Auto-nix on COLD start:** When `CC_FUZZER_FHS=1` and the harness has no committed backend yet (brand-new campaign), automatically use the nix path — write the manifest and drive `nix-build.sh`. Record `build_backend=nix` via `write-harness-built.sh --build-backend nix`.

**Steps:**

1. Write the harness source to `fuzz/harnesses/<name>/harness/<name>_fuzzer.cc` (same logic as Mode A).
2. Write `fuzz/harnesses/<name>/harness/cov_main.c` (same as Mode A).
3. Write `fuzz/harnesses/<name>/nix/manifest.json` — the nix-build manifest:

   ```json
   {
     "schema": "nix-build-manifest/v1",
     "harness": "<name>",
     "target_source": "<absolute-or-project-root-relative path to target .c/.cc>",
     "target_extra_sources": [],
     "harness_source": "fuzz/harnesses/<name>/harness/<name>_fuzzer.cc",
     "cov_main": "fuzz/harnesses/<name>/harness/cov_main.c",
     "extra_compile_flags": [],
     "extra_link_flags": [],
     "extra_pkgconfig_modules": [],
     "mocks": [],
     "variants": {
       "fuzzer":   {"enabled": true,  "sanitizers": ["address","undefined","fuzzer"]},
       "coverage": {"enabled": true},
       "verify":   {"enabled": true},
       "cmplog":   {"enabled": false},
       "symcc":    {"enabled": false}
     }
   }
   ```

   Populate `extra_pkgconfig_modules` from any `-l<lib>` flags the legacy build would have needed. Set `cmplog.enabled=true` if AFL++ is the campaign engine. Set `symcc.enabled=true` only when concolic execution is explicitly requested.

4. Run `nix-build.sh`:
   ```bash
   bash {{scripts}}/nix-build.sh <name>
   ```
   Iteratively repair nix build failures (up to 5 passes):
   - `unfree_license_blocked`: call `harness-set.sh fallback-backend <name> --reason unfree_license_blocked --evidence "..."` and fall back to Mode A
   - Missing pkg: add to `fuzz/nix-deps.nix`, tell user to re-enter FHS shell
   - Compiler flag unknown to clang in nix sandbox: remove from manifest, retry
   - Other unclassifiable failures (3+): call `harness-set.sh fallback-backend <name> --reason no_nix_expr_for_target --evidence "<last build error>"` and fall back to Mode A

5. Call the wrapper:
   ```bash
   bash {{scripts}}/write-harness-built.sh \
     --harness <name> \
     --target-source <path> \
     --harness-source fuzz/harnesses/<name>/harness/<name>_fuzzer.cc \
     --harness-binary fuzz/harnesses/<name>/harness/<name>_fuzzer \
     --build-script fuzz/harnesses/<name>/harness/build.sh \
     --entry-function <fn> \
     --fuzzing-mode in_process \
     --coverage-binary fuzz/harnesses/<name>/harness/<name>_fuzzer_cov \
     --verify-binary fuzz/harnesses/<name>/harness/<name>_fuzzer_verify \
     --build-backend nix
   ```

   The binary paths in the wrapper call should be the symlink paths under `fuzz/harnesses/<name>/harness/` — `nix-build.sh` creates those symlinks pointing into `/nix/store/`.

<!-- slot:missing_dep -->
**Missing system library / header (`fatal error: foo.h: No such file`, `cannot find -lfoo`, `Package foo was not found` from pkg-config):** the campaign's nix dev shell is missing a build dep. **Do NOT hack include/lib paths into `build.sh`.** Instead, if `fuzz/nix-deps.nix` exists (a v0.19.2+/multi campaign launched via `nix run #init`), append the needed nixpkgs attr to it (it's a `pkgs: with pkgs; [ ... ]` list, in your writable `fuzz/` scope — headers usually live in the `.dev` output, e.g. `expat.dev`), then **stop and tell the orchestrator the dep was added and the shell must be rebuilt**: the user re-enters with `nix run {{root}}#init` (idempotent) or `nix develop -c claude`, then re-runs the campaign. You cannot pick up a new nix dep inside the running shell. If `fuzz/nix-deps.nix` is absent (legacy/host-tools campaign), report the missing lib to the user instead.
