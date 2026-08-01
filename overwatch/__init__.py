"""Overwatch — passive web-app assessment by riding a real authenticated session.

A human drives a real logged-in browser (Chrome/Edge with --remote-debugging-port);
Overwatch attaches to the DevTools (CDP) endpoint, captures the traffic the app
already generates, and runs a finding taxonomy over it. It emits **zero** requests
of its own — it is indistinguishable from a user.

Restraint ethic (enforced in code, not just docs):
  - passive only: no crafted requests are ever sent.
  - truncate live credentials in all output (see overwatch.redact).
  - findings are metadata: names, shapes, tells — not exfiltrated data.
  - scope is the operator's responsibility: ride only authorized sessions.
"""

__version__ = "0.1.0"

from .detectors import Exchange, Finding, run_detectors, ALL_DETECTORS
from .ledger import Ledger
from .redact import redact

__all__ = [
    "Exchange",
    "Finding",
    "run_detectors",
    "ALL_DETECTORS",
    "Ledger",
    "redact",
    "__version__",
]
