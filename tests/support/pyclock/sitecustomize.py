"""Test-only frozen clock for every Python process a golden test spawns.

The golden harness puts this directory first on PYTHONPATH and exports
CC_FUZZER_TEST_NOW=<epoch seconds>. Every python3 child (the _lib modules, the
heredoc snippets inside the bash scripts, and the cc_fuzzer_core ports) then
sees the same wall clock, so outputs that embed "now" or compute ages from it
are byte-stable. Unset CC_FUZZER_TEST_NOW => this module does nothing.
Monotonic clocks (time.monotonic / perf_counter) are left alone.
"""
import os

_NOW = os.environ.get("CC_FUZZER_TEST_NOW")

if _NOW:
    import datetime as _dt
    import time as _time

    _FROZEN = float(_NOW)
    _real_gmtime = _time.gmtime
    _real_localtime = _time.localtime
    _real_strftime = _time.strftime
    _real_ctime = _time.ctime

    _time.time = lambda: _FROZEN
    _time.time_ns = lambda: int(_FROZEN * 1_000_000_000)
    _time.gmtime = lambda secs=None: _real_gmtime(_FROZEN if secs is None else secs)
    _time.localtime = lambda secs=None: _real_localtime(_FROZEN if secs is None else secs)
    _time.ctime = lambda secs=None: _real_ctime(_FROZEN if secs is None else secs)
    _time.strftime = (lambda fmt, t=None:
                      _real_strftime(fmt, _real_localtime(_FROZEN) if t is None else t))

    class _FrozenDateTime(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls.fromtimestamp(_FROZEN, tz)

        @classmethod
        def utcnow(cls):
            return cls.fromtimestamp(_FROZEN, _dt.timezone.utc).replace(tzinfo=None)

        @classmethod
        def today(cls):
            return cls.fromtimestamp(_FROZEN)

    class _FrozenDate(_dt.date):
        @classmethod
        def today(cls):
            return cls.fromtimestamp(_FROZEN)

    _dt.datetime = _FrozenDateTime
    _dt.date = _FrozenDate
