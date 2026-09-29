"""Budget errors: the one failure an embedding CRS must not retry.

Frameworks increasingly enforce spend at the model gateway (OSS-CRS issues a
LiteLLM key with a hard max_budget), so the first sign that the money is gone
is an API error in the middle of a run, not a local counter. A CRS that treats
it as transient retries into a wall and burns the rest of its wall-clock.

    BudgetError          catch this to fall through to deterministic work
      BudgetExhausted    the PROVIDER refused: the gateway budget is spent
      CapReached         the LOCAL guard tripped (ledger.guard): advisory,
                         set to trip before the provider does

Neither is ever retried. The right response to either is to stop calling
models and keep doing what needs no model -- fuzzing, replay, minimization,
patch validation -- rather than exiting.
"""
from __future__ import annotations

import re
import time


class BudgetError(RuntimeError):
    """Spend is over. Not transient; do not retry."""


class BudgetExhausted(BudgetError):
    """The provider (or its gateway) refused the call: the budget is spent."""

    def __init__(self, message: str = "", *, provider: str = "", cause: str = ""):
        super().__init__(message or "provider budget exhausted")
        self.provider = provider
        self.cause = cause


class CapReached(BudgetError):
    """ledger.guard: local spend reached cap minus reserve."""

    def __init__(self, message: str = "", *, scope: str = "", spent: float = 0.0,
                 limit: float = 0.0):
        super().__init__(message or f"spend cap reached ({spent:.4f} >= {limit:.4f})")
        self.scope, self.spent, self.limit = scope, spent, limit


# What gateways and providers say when the money is gone. Matched against the
# exception text and any body/type/code attribute; case-insensitive.
_BUDGET_RE = re.compile(
    r"budget\s*(?:has\s+been\s+)?exceeded|exceeded\s*budget|budget_exceeded|"
    r"budgetexceeded|max_budget|credit balance is too low|insufficient_quota|"
    r"spend limit|billing hard limit", re.I)


def _texts(exc: BaseException):
    yield str(exc)
    yield type(exc).__name__
    for attr in ("body", "type", "code", "message", "error"):
        v = getattr(exc, attr, None)
        if v:
            yield repr(v)


def is_budget_error(exc: BaseException) -> bool:
    if isinstance(exc, BudgetError):
        return True
    return any(_BUDGET_RE.search(t) for t in _texts(exc))


def as_budget_exhausted(exc: BaseException):
    """The BudgetExhausted `exc` means, or None if it is some other failure."""
    if isinstance(exc, BudgetExhausted):
        return exc
    if isinstance(exc, BudgetError):
        return None          # a local cap is not a provider refusal
    if not is_budget_error(exc):
        return None
    return BudgetExhausted(f"provider budget exhausted: {exc}",
                           provider=type(exc).__module__.split(".")[0],
                           cause=str(exc))


def call(fn, *args, attempts: int = 3, backoff_s: float = 2.0, sleep=time.sleep,
         **kwargs):
    """Call a model-backed `fn`, retrying transient failures but never a budget
    error: that raises BudgetExhausted (or the BudgetError it was) at once."""
    last = None
    for i in range(max(1, attempts)):
        try:
            return fn(*args, **kwargs)
        except BudgetError:
            raise
        except Exception as e:  # noqa: BLE001 - classify, then decide
            be = as_budget_exhausted(e)
            if be is not None:
                raise be from e
            last = e
            if i + 1 < attempts:
                sleep(backoff_s * (2 ** i))
    raise last
