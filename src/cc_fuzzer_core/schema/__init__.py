"""State schema: version constant, per-file field lists and the validator.

    from cc_fuzzer_core.schema import validate, render, SCHEMA_VERSION
    problems = validate(campaign)          # [Problem(severity, message)]
    text, exit_code = render(problems)     # validate-state.sh's report

fields.py   SCHEMA_VERSION + every required/allowed field list (lifted from
            validate-state.sh)
checks.py   content checks (lifted from scripts/_lib/state_checks.py)
validate.py the validator driver and `cc-fuzzer schema validate|version|field`
"""
from cc_fuzzer_core.schema.fields import SCHEMA_VERSION  # noqa: F401
from cc_fuzzer_core.schema.validate import (ERROR, INFO, WARNING, Problem,  # noqa: F401
                                            register_cli, render, validate)
