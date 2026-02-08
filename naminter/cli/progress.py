from collections import defaultdict
import time

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
from naminter.cli.constants import PROGRESS_ADVANCE_INCREMENT, STATUS_SYMBOLS
from naminter.core.models import WMNResult, WMNStatus


class ProgressBar:
    """Manages progress bar and result tracking for CLI applications."""

    def __init__(self, console: Console, *, disabled: bool = False) -> None:
        """Initialize the progress bar.

        Args:
            console: Rich Console instance for output.
            disabled: Whether to disable progress bar display.
        """
        self.console: Console = console
        self.disabled: bool = disabled
        self.progress: Progress | None = None
        self.task_id: TaskID | None = None

        self.total_sites: int = 0
        self.results_count: int = 0
        self.start_time: float | None = None
        self.status_counts: dict[WMNStatus, int] = defaultdict(int)

    def add_result(self, result: WMNResult) -> None:
        """Update counters with a new result and refresh progress display."""
        self.results_count += 1
        self.status_counts[result.status] += 1
        self.update(
            advance=PROGRESS_ADVANCE_INCREMENT,
            description=self._get_progress_text(),
        )

    def _get_progress_text(self) -> str:
        """Get formatted progress text with request speed and statistics."""
        elapsed = time.time() - self.start_time if self.start_time else 0.0

        exists = self.status_counts[WMNStatus.EXISTS]
        partial_exists = self.status_counts[WMNStatus.PARTIAL_EXISTS]
        partial_missing = self.status_counts[WMNStatus.PARTIAL_MISSING]
        conflicting = self.status_counts[WMNStatus.CONFLICTING]
        unknown = self.status_counts[WMNStatus.UNKNOWN]
        missing = self.status_counts[WMNStatus.MISSING]
        not_valid = self.status_counts[WMNStatus.NOT_VALID]
        errors = self.status_counts[WMNStatus.ERROR]

        valid_count = max(self.results_count - errors - not_valid, 0)
        rate = valid_count / elapsed if elapsed > 0.0 else 0.0

        sections = [
            f"[{THEME.primary}]{rate:.1f} req/s[/]",
            f"[{THEME.success}]{STATUS_SYMBOLS[WMNStatus.EXISTS]} {exists}[/]",
            f"[{THEME.error}]{STATUS_SYMBOLS[WMNStatus.MISSING]} {missing}[/]",
        ]

        if unknown > 0:
            sections.append(
                f"[{THEME.warning}]{STATUS_SYMBOLS[WMNStatus.UNKNOWN]} {unknown}[/]",
            )
        if partial_exists > 0:
            sections.append(
                f"[{THEME.warning}]{STATUS_SYMBOLS[WMNStatus.PARTIAL_EXISTS]} ~E {partial_exists}[/]",
            )
        if partial_missing > 0:
            sections.append(
                f"[{THEME.warning}]{STATUS_SYMBOLS[WMNStatus.PARTIAL_MISSING]} ~M {partial_missing}[/]",
            )
        if conflicting > 0:
            sections.append(
                f"[{THEME.warning}]{STATUS_SYMBOLS[WMNStatus.CONFLICTING]} {conflicting}[/]",
            )
        if errors > 0:
            sections.append(
                f"[{THEME.error}]{STATUS_SYMBOLS[WMNStatus.ERROR]} {errors}[/]",
            )
        if not_valid > 0:
            sections.append(
                f"[{THEME.warning}]{STATUS_SYMBOLS[WMNStatus.NOT_VALID]} {not_valid}[/]",
            )

        sections.append(f"[{THEME.primary}]{self.results_count}/{self.total_sites}[/]")
        return " │ ".join(sections)

    def _create_progress_bar(self) -> Progress:
        """Create a new progress bar with configured styling.

        Returns:
            Configured Progress instance ready for display.
        """
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(
                complete_style=THEME.primary,
                finished_style=THEME.success,
            ),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=self.console,
        )

    def start(self, total: int, description: str) -> None:
        """Start the progress bar and result tracking.

        Args:
            total: Total number of tasks to track.
            description: Initial description text for the progress bar.
        """
        self.total_sites = max(total, 0)
        self.start_time = time.time()
        if not self.disabled:
            self.progress = self._create_progress_bar()
            self.progress.start()
            self.task_id = self.progress.add_task(description, total=total)

    def update(
        self,
        advance: int = PROGRESS_ADVANCE_INCREMENT,
        description: str | None = None,
    ) -> None:
        """Update the progress bar.

        Args:
            advance: Number of steps to advance the progress.
            description: Optional new description to display.
        """
        if self.progress and self.task_id is not None:
            self.progress.update(self.task_id, advance=advance, description=description)

    def stop(self) -> None:
        """Stop and close the progress bar."""
        if self.progress:
            self.progress.stop()
            self.progress = None
            self.task_id = None
