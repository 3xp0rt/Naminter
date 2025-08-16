import time
from typing import Any, Dict, Optional, Union

from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TaskID,
)

from ..cli.console import THEME
from ..core.models import ResultStatus, SiteResult

class ResultsTracker:
    """Tracks results for the username enumeration operations."""
    
    def __init__(self, total_sites: int) -> None:
        """Initialize the results tracker."""
        self.total_sites = total_sites
        self.results_count = 0
        self.start_time = time.time()
        self.status_counts: Dict[ResultStatus, int] = {status: 0 for status in ResultStatus}

    def add_result(self, result: SiteResult) -> None:
        """Update counters with a new result."""
        self.results_count += 1
        self.status_counts[result.status] += 1

    def get_progress_text(self) -> str:
        """Get formatted progress text with request speed and statistics."""
        elapsed = time.time() - self.start_time
        rate = self.results_count / elapsed if elapsed > 0 else 0.0
        
        found = self.status_counts[ResultStatus.FOUND]
        ambiguous = self.status_counts[ResultStatus.AMBIGUOUS]
        unknown = self.status_counts[ResultStatus.UNKNOWN]
        not_found = self.status_counts[ResultStatus.NOT_FOUND]
        not_valid = self.status_counts[ResultStatus.NOT_VALID]
        errors = self.status_counts[ResultStatus.ERROR]

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
            sections.append(f"[{THEME['warning']}]× {not_valid}[/]")
            
        sections.append(f"[{THEME['primary']}]{self.results_count}/{self.total_sites}[/]")
        return " │ ".join(sections)
    
    @property
    def completion_percentage(self) -> float:
        """Get the completion percentage as a float between 0 and 100."""
        return (self.results_count / self.total_sites) * 100 if self.total_sites > 0 else 0.0


class ProgressManager:
    """Manages progress bar and tracking for CLI applications."""
    
    def __init__(self, console: Console, disabled: bool = False) -> None:
        """Initialize the progress manager."""
        self.console: Console = console
        self.disabled: bool = disabled
        self.progress: Optional[Progress] = None
        self.task_id: Optional[TaskID] = None
        
    def create_progress_bar(self) -> Progress:
        """Create a new progress bar."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(
                complete_style=THEME['primary'],
                finished_style=THEME['success'],
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
        
    def update(self, advance: int = 1, description: Optional[str] = None) -> None:
        """Update the progress bar."""
        if self.progress and self.task_id is not None:
            update_kwargs: Dict[str, Any] = {"advance": advance}
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
        
    def __exit__(self, exc_type: Optional[type], exc_val: Optional[BaseException], exc_tb: Optional[Any]) -> None:
        """Exit context manager and stop progress bar."""
        self.stop()
