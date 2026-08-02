from datetime import UTC, datetime


def utc_now() -> datetime:
    """Naive UTC timestamp for database storage and comparisons."""
    return datetime.now(UTC).replace(tzinfo=None)
