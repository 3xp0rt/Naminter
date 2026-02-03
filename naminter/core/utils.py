import asyncio
from collections.abc import AsyncGenerator, Awaitable, Sequence
from typing import TypeVar

T = TypeVar("T")


async def execute_tasks(
    awaitables: Sequence[Awaitable[T]],
) -> AsyncGenerator[T, None]:
    """Execute awaitables concurrently and yield results as they complete.

    Args:
        awaitables: Sequence of awaitables to execute.

    Yields:
        T: Results from completed awaitables as they finish.
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
