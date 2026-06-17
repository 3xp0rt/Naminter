"""Tests for naminter.core.utils."""

from __future__ import annotations

import asyncio

import pytest

from naminter.core.utils import execute_tasks


@pytest.mark.asyncio
async def test_execute_tasks_empty_yields_nothing() -> None:
    results = [item async for item in execute_tasks([])]
    assert results == []


@pytest.mark.asyncio
async def test_execute_tasks_yields_all_results() -> None:
    async def one(x: int) -> int:
        await asyncio.sleep(0)
        return x

    awaitables = [one(1), one(2), one(3)]
    results = [x async for x in execute_tasks(awaitables)]
    assert sorted(results) == [1, 2, 3]


@pytest.mark.asyncio
async def test_execute_tasks_cancels_pending_on_close() -> None:
    started = asyncio.Event()

    async def slow() -> str:
        started.set()
        await asyncio.sleep(60)
        return "slow"

    async def fast() -> str:
        await asyncio.sleep(0)
        return "fast"

    gen = execute_tasks([slow(), fast()])
    first = await anext(gen)
    await started.wait()
    assert first == "fast"
    await gen.aclose()
