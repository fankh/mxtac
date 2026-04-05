from pathlib import Path as _Path


def _read_version() -> str:
    # Try multiple paths to find VERSION file (works in both local and Docker)
    for depth in range(5):
        try:
            candidate = _Path(__file__).parents[depth] / "VERSION"
            if candidate.exists():
                return candidate.read_text().strip()
        except (IndexError, OSError):
            continue
    try:
        from importlib.metadata import version

        return version("mxtac-backend")
    except Exception:
        return "2.0.0"


__version__: str = _read_version()
