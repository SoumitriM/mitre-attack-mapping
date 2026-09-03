"""Neo4j temporal type serialization utilities."""

from typing import Any

try:
    from neo4j.time import Date, DateTime, Duration, Time
except ImportError:
    # Fallback if neo4j is not installed
    Date = DateTime = Time = Duration = type(None)  # type: ignore


def serialize_neo4j_value(value: Any) -> Any:
    """
    Recursively serialize Neo4j temporal types to JSON-compatible formats.

    Converts:
    - DateTime, Date, Time to ISO-8601 strings
    - Duration to string representation
    - dict values recursively
    - list/tuple items recursively
    - other values unchanged

    Args:
        value: Any value that may contain Neo4j temporal types

    Returns:
        A JSON-serializable version of the value
    """
    if isinstance(value, (DateTime, Date, Time)):
        return value.iso_format()
    if isinstance(value, Duration):
        return str(value)
    if isinstance(value, dict):
        return {k: serialize_neo4j_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [serialize_neo4j_value(v) for v in value]
    return value
