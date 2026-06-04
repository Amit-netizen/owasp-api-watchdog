# conftest.py — project-level pytest configuration
# All fixtures shared across test modules are defined in test_owasp_security.py.
# This file ensures pytest picks up the app package from the project root.

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
