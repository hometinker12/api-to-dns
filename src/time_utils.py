from datetime import datetime, timezone


def utc_now() -> datetime:
    """Naive UTC timestamp for database storage and comparisons."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
