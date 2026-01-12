import asyncio
from collections.abc import AsyncGenerator, Awaitable, Sequence
from typing import Any, TypeVar

T = TypeVar("T")


def get_missing_keys(data: dict[str, Any], keys: Sequence[str]) -> list[str]:
    """Return a list of required keys missing from a dictionary.

    Args:
        data: Dictionary to check for missing keys.
        keys: Sequence of keys that should be present.

    Returns:
        List of keys that are missing from the dictionary. Empty list if
        all keys are present.
    """
    return [key for key in keys if key not in data]


async def execute_tasks(
    awaitables: Sequence[Awaitable[T]],
) -> AsyncGenerator[T, None]:
    """Execute awaitables concurrently and yield results as they complete.

    Args:
        awaitables: Sequence of awaitables to execute.

    Yields:
        Results from completed awaitables.
    """
    if not awaitables:
        return

    scheduled_futures: list[asyncio.Future[T]] = [
        asyncio.ensure_future(awaitable) for awaitable in awaitables
    ]

    try:
        for completed_future in asyncio.as_completed(scheduled_futures):
            yield await completed_future
    finally:
        for scheduled_future in scheduled_futures:
            if not scheduled_future.done():
                scheduled_future.cancel()
        await asyncio.gather(*scheduled_futures, return_exceptions=True)
