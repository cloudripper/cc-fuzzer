"""cc_fuzzer_core — the host-independent core of cc-fuzzer.

Importable by anything (the Claude Code plugin is only the first consumer).
Hard rule, enforced by tests/test_isolation.py: nothing in this package reads
host-specific environment variables, emits host hook JSON, or refers to the
plugin-only trees (agents, skills, hooks). The plugin's shim layer
(scripts/_lib/root.sh) is the only place that maps the plugin host's
environment onto CC_FUZZER_ROOT.

Subsystems are ported from scripts/ one at a time (see UPDATE_ROADMAP.md §2);
each registers its own `cc-fuzzer <subsystem> <verb>` subcommands through
cc_fuzzer_core.cli.
"""

__version__ = "0.31.0"
