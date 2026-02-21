from pathlib import Path as _Path


def _read_version() -> str:
    # Walk up 3 directories from this file (app/ → backend/ → app/ → mxtac/)
    # to reach the repo root where VERSION lives. Works for editable installs
    # and `uv run`. Falls back to importlib.metadata for installed packages.
    candidate = _Path(__file__).parents[3] / "VERSION"
    if candidate.exists():
        return candidate.read_text().strip()
    try:
        from importlib.metadata import version

        return version("mxtac-backend")
    except Exception:
        return "0.0.0"


__version__: str = _read_version()
