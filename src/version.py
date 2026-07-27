"""Single source of truth for the application version string."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def get_app_version() -> str:
    """Return the package version from the repository ``VERSION`` file.

    Looks next to the project root (parent of ``src/``) and at ``/app/VERSION``
    for container images that copy the file into the image root.
    """
    candidates = (
        Path(__file__).resolve().parents[1] / "VERSION",
        Path("/app/VERSION"),
    )
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text:
            return text
    return "0.0.0"
