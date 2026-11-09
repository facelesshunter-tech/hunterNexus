from __future__ import annotations

import logging
import sys


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    root = logging.getLogger("hunternexus")
    root.setLevel(level)
    root.handlers = [handler]
    root.propagate = False
