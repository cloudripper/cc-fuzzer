"""Optional integrations: code that connects the core to one outside tool.

The core never imports anything under here (tests/test_integrations.py holds
it to that). An integration reads the tool's output and hands the core what
it already understands -- a code-review/v1 snapshot, a sast-signal/v1 file,
a query engine command, a candidate matcher -- and is gated by feature flags
that are off by default. Delete this package and the core runs unchanged.
"""
