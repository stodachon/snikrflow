"""
SnikrFlow package init.

This MUST configure angr's logging before any submodule imports angr.
Python always executes a package's __init__.py before any of its
submodules run -- so this is the one place guaranteed to win, no matter
which snikrflow.* submodule a caller happens to import first (unlike a
per-file fix, which breaks again the next time a new module adds its own
`import angr`/`from angr import ...`).
"""

import logging

logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)
logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)