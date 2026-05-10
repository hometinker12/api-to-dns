"""Ensure tests use an isolated SQLite file before application modules import ``src.db``."""

import os
import tempfile

_db = tempfile.NamedTemporaryFile(prefix="api-to-dns-test-", suffix=".db", delete=False)
_db.close()
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.abspath(_db.name).replace("\\", "/")
