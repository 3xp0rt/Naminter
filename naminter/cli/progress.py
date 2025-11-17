import time
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from naminter.cli.console import THEME
from naminter.cli.constants import PROGRESS_ADVANCE_INCREMENT
from naminter.core.models import WMNResult, WMNStatus


class ResultsTracker:
    """Tracks results for the username enumeration operations."""

    def __init__(self, total_sites: int) -> None:
        """Initialize the results tracker."""
        self.total_sites = max(total_sites, 0)
        self.results_count = 0
        self.start_time = time.time()
        self.status_counts: dict[WMNStatus, int] = dict.fromkeys(WMNStatus, 0)

    def add_result(self, result: WMNResult) -> None:
        """Update counters with a new result."""
        self.results_count += 1
        self.status_counts[result.status] += 1

    def get_progress_text(self) -> str:
        """Get formatted progress text with request speed and statistics."""
        elapsed = time.time() - self.start_time if self.start_time else 0.0

        found = self.status_counts[WMNStatus.FOUND]
        ambiguous = self.status_counts[WMNStatus.AMBIGUOUS]
        unknown = self.status_counts[WMNStatus.UNKNOWN]
        not_found = self.status_counts[WMNStatus.NOT_FOUND]
        not_valid = self.status_counts[WMNStatus.NOT_VALID]
        errors = self.status_counts[WMNStatus.ERROR]

        valid_count = self.results_count - errors - not_valid
        valid_count = max(valid_count, 0)
        rate = valid_count / elapsed if elapsed > 0 else 0.0

        sections = [
            f"[{THEME['primary']}]{rate:.1f} req/s[/]",
            f"[{THEME['success']}]+ {found}[/]",
            f"[{THEME['error']}]- {not_found}[/]",
        ]

        if unknown > 0:
            sections.append(f"[{THEME['warning']}]? {unknown}[/]")
        if ambiguous > 0:
            sections.append(f"[{THEME['warning']}]* {ambiguous}[/]")
        if errors > 0:
            sections.append(f"[{THEME['error']}]! {errors}[/]")
        if not_valid > 0:
            sections.append(f"[{THEME['warning']}]x {not_valid}[/]")

        total = max(self.total_sites, self.results_count)
        sections.append(
            f"[{THEME['primary']}]{self.results_count}/{total}[/]"
        )
        return " │ ".join(sections)


class ProgressManager:
    """Manages progress bar and tracking for CLI applications."""

    def __init__(self, console: Console, disabled: bool = False) -> None:
        """Initialize the progress manager."""
        self.console: Console = console
        self.disabled: bool = disabled
        self.progress: Progress | None = None
        self.task_id: TaskID | None = None

    def create_progress_bar(self) -> Progress:
        """Create a new progress bar."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(
                complete_style=THEME["primary"],
                finished_style=THEME["success"],
            ),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=self.console,
        )

    def start(self, total: int, description: str) -> None:
        """Start the progress bar."""
        if not self.disabled:
            self.progress = self.create_progress_bar()
            self.progress.start()
            self.task_id = self.progress.add_task(description, total=total)

    def update(
        self, advance: int = PROGRESS_ADVANCE_INCREMENT, description: str | None = None
    ) -> None:
        """Update the progress bar."""
        if self.progress and self.task_id is not None:
            update_kwargs: dict[str, Any] = {"advance": advance}
            if description is not None:
                update_kwargs["description"] = description
            self.progress.update(self.task_id, **update_kwargs)

    def stop(self) -> None:
        """Stop and close the progress bar."""
        if self.progress:
            self.progress.stop()
            self.progress = None
            self.task_id = None

    def __enter__(self) -> "ProgressManager":
        """Enter context manager."""
        return self

    def __exit__(
        self, exc_type: type | None, exc_val: BaseException | None, exc_tb: Any | None
    ) -> None:
        """Exit context manager and stop progress bar."""
        self.stop()
