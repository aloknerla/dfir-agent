"""Keep the test suite hermetic with respect to a developer's local ``.env``.

``forensic_agent.core.config`` calls ``load_dotenv()`` at import time so an
interactive run picks up credentials and tool locations without ceremony. That
is right for a console session and wrong for the suite: a machine that has a
tool path or credential exported would silently change what the tests exercise,
and the result would depend on who ran it. python-dotenv honours
``PYTHON_DOTENV_DISABLED``, and setting it here, before any project import,
makes the offline suite read only what each test sets itself.
"""

from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("PYTHON_DOTENV_DISABLED", "1")

# Some tests spawn ``python -m ...`` subprocesses (CLI entry points, import
# boundary probes). A freshly spawned interpreter does not inherit the
# in-process ``sys.path``; mirror the ``src`` root into ``PYTHONPATH`` so
# subprocess children resolve the package exactly as the in-process suite does.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SUITE_IMPORT_ROOTS = [str(_REPO_ROOT / "src"), str(_REPO_ROOT)]
_pythonpath_parts = [
    part for part in os.environ.get("PYTHONPATH", "").split(os.pathsep) if part
]
for _root in reversed(_SUITE_IMPORT_ROOTS):
    if _root not in _pythonpath_parts:
        _pythonpath_parts.insert(0, _root)
os.environ["PYTHONPATH"] = os.pathsep.join(_pythonpath_parts)
