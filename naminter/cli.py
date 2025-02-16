import asyncio
import time
import webbrowser
from enum import Enum
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

import typer
import rich.box
from rich.console import Console
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, 
    TaskProgressColumn, TimeElapsedColumn, TimeRemainingColumn
)
from rich.panel import Panel
from rich.table import Table
from rich.style import Style
from rich.text import Text
from rich.tree import Tree

from .naminter import Naminter
from .models import CheckStatus, TestResult, SelfTestResult
from .settings import SITES_LIST_REMOTE_URL

__version__ = "1.0.2"
__author__ = "3xp0rt"
__description__ = "The most powerful and fast username availability checker that searches across hundreds of websites using WhatsMyName dataset."

app = typer.Typer(
    help="Username availability checker",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True
)
console = Console()

THEME = {
    'primary': 'bright_blue',
    'success': 'bright_green',
    'error': 'bright_red',
    'warning': 'bright_yellow',
    'info': 'bright_cyan',
    'muted': 'bright_black'
}

class BrowserImpersonation(str, Enum):
    """Browser impersonation options."""
    NONE = "none"
    CHROME = "chrome"
    CHROME_ANDROID = "chrome_android"
    SAFARI = "safari"
    SAFARI_IOS = "safari_ios" 
    EDGE = "edge"

from dataclasses import dataclass
from typing import Optional, List

@dataclass(frozen=True)
class CheckerConfig:
    """Configuration for the UsernameChecker."""
    username: str 

    # Input sources
    local_list_path: Optional[str]
    remote_list_url: Optional[str]

    # Category filters 
    include_categories: Optional[List[str]]
    exclude_categories: Optional[List[str]]

    # HTTP settings
    max_tasks: int
    timeout: int
    proxy: Optional[str]
    allow_redirects: bool
    verify_ssl: bool

    # Browser settings
    impersonate: Optional[str]
    browse: bool

    # Validation settings
    fuzzy_mode: bool

    # Self check setting
    self_check: bool

    # Debug options
    debug: bool
    version: str = __version__

class ResultsTracker:
    """Tracks results for the username availability checks."""
    def __init__(self, total_sites: int, max_tasks: int):
        self.total_sites = total_sites
        self.max_tasks = max_tasks
        self.results_count = 0
        self.start_time = time.time()
        self.status_counts = {status: 0 for status in CheckStatus}

    def add_result(self, result: TestResult) -> None:
        """Updates counters with a new result."""
        self.results_count += 1
        self.status_counts[result.check_status] += 1

    def get_progress_text(self) -> str:
        """Returns formatted progress text with enhanced speed indicators."""
        elapsed = time.time() - self.start_time
        req_per_sec = self.results_count / elapsed if elapsed > 0 else 0
        found = self.status_counts.get(CheckStatus.FOUND, 0)
        not_found = self.status_counts.get(CheckStatus.NOT_FOUND, 0)
        unknown = self.status_counts.get(CheckStatus.UNKNOWN, 0)
        errors = self.status_counts.get(CheckStatus.ERROR, 0)

        speed_indicators = [
            (15.0, f"[{THEME['success']}]LIGHTNING[/]", "⚡️⚡️"),
            (10.0, f"[{THEME['success']}]BLAZING[/]", "⚡️"),
            (7.0, f"[{THEME['success']}]FAST[/]", "🚀"),
            (5.0, f"[{THEME['primary']}]GOOD[/]", "✨"),
            (3.0, f"[{THEME['warning']}]MODERATE[/]", "⚙️"),
            (1.0, f"[{THEME['warning']}]STEADY[/]", "🔄"),
            (0.0, f"[{THEME['error']}]SLOW[/]", "🐌")
        ]

        speed_text = next(
            (f"{indicator} {emoji}" for threshold, indicator, emoji in speed_indicators 
            if req_per_sec >= threshold),
            f"[{THEME['error']}]INITIALIZING[/] ⏳"
        )

        sections = [
            f"{speed_text} ({req_per_sec:.1f} req/s)",
            f"[{THEME['success']}]✓ {found}[/]",
            f"[{THEME['error']}]× {not_found}[/]",
            f"[{THEME['warning']}]? {unknown}[/]" if unknown > 0 else "",
            f"[{THEME['error']}]! {errors}[/]" if errors > 0 else "",
            f"[{THEME['primary']}]{self.results_count}/{self.total_sites}[/]"
        ]
        return " │ ".join(filter(None, sections))

class UsernameChecker:
    """Handles username availability checks."""
    def __init__(self, config: CheckerConfig):
        self.config = config
        self._found_results: List[TestResult] = []
        self._status_styles = {
            CheckStatus.FOUND: Style(color=THEME['success'], bold=True),
            CheckStatus.NOT_FOUND: Style(color=THEME['error']),
            CheckStatus.UNKNOWN: Style(color=THEME['warning']),
            CheckStatus.ERROR: Style(color=THEME['error'], bold=True),
        }
    
    def _format_result(self, result: TestResult) -> Optional[Text]:
        """Formats a single result for console printing."""
        if not self.config.debug and result.check_status != CheckStatus.FOUND:
            return None

        status_symbols = {
            CheckStatus.FOUND: "✓",
            CheckStatus.NOT_FOUND: "✗",
            CheckStatus.UNKNOWN: "?",
            CheckStatus.ERROR: "!"
        }

        text = Text()
        text.append(" ", style=THEME['muted'])
        text.append(status_symbols[result.check_status], style=self._status_styles[result.check_status])
        text.append(" [", style=THEME['muted'])
        text.append(result.site_name or "Unknown", style=THEME['info'])
        """
        text.append("/", style=THEME['muted'])
        text.append(result.category or "Unknown", style=THEME['warning'])
        """
        text.append("] ", style=THEME['muted'])
        text.append(result.site_url, style=THEME['primary'])

        if self.config.debug and result.error:
            text.append(f" ({result.error})", style=THEME['error'])

        return text

    def _format_test_result(self, self_check: SelfTestResult) -> Tree:
        """Formats self-check results into a tree structure."""
        status_symbols = {
            CheckStatus.FOUND: "✓",
            CheckStatus.NOT_FOUND: "✗",
            CheckStatus.UNKNOWN: "?",
            CheckStatus.ERROR: "!",
            CheckStatus.NOT_VALID: "x",
        }

        overall_status = next((
            status for status in [
                CheckStatus.ERROR,
                CheckStatus.FOUND,
                CheckStatus.NOT_FOUND
            ] if any(test.check_status == status for test in self_check.results)
        ), CheckStatus.UNKNOWN)

        root_label = Text()
        root_label.append(status_symbols.get(overall_status, "?"), 
            style=self._status_styles.get(overall_status)
        )
        root_label.append(" [", style=THEME["muted"])
        root_label.append(self_check.site_name, style=THEME["info"]) 
        root_label.append("]", style=THEME["muted"])

        tree = Tree(root_label, guide_style=THEME["muted"], expanded=True)

        for test in self_check.results:
            url_text = Text()
            url_text.append(status_symbols.get(test.check_status, "?"),
                style=self._status_styles.get(test.check_status)
            )
            url_text.append(" ", style=THEME["muted"])
            url_text.append(test.site_url, style=THEME["primary"])

            url_branch = tree.add(url_text)

            details_text = Text()
            if test.status_code is not None:
                details_text.append(f"Status: {test.status_code}", style=THEME["info"])
            if test.elapsed is not None:
                details_text.append(f" Time: {test.elapsed:.2f}s", style=THEME["info"])
            if test.error:
                details_text.append(f" (Error: {test.error})", style=THEME["error"])

            if details_text:
                url_branch.add(details_text)

        return tree

    def _get_impersonation_value(self) -> Optional[str]:
        """Returns browser impersonation value."""
        if self.config.impersonate == "none":
            return None
        return self.config.impersonate

    def _open_profile(self, url: str) -> None:
        """Opens a single profile URL in the browser."""
        try:
            webbrowser.open(url)
        except Exception as e:
            console.print(f"[{THEME['error']}]Failed to open {url}: {str(e)}[/]")

    async def run(self) -> None:
        """Main execution method with progress tracking."""
        async with Naminter(
            max_tasks=self.config.max_tasks,
            impersonate=self._get_impersonation_value(),
            verify_ssl=self.config.verify_ssl,
            timeout=self.config.timeout,
            allow_redirects=self.config.allow_redirects,
            proxy=self.config.proxy,
        ) as naminter:
            if self.config.local_list_path:
                await naminter.load_local_list(self.config.local_list_path)
            else:
                await naminter.fetch_remote_list(self.config.remote_list_url)

            wmn_info = await naminter.get_wmn_info()

            if self.config.self_check:
                sites_data = naminter._wmn_data.get("sites", [])
                total_known = sum(len(site.get("known", [])) for site in sites_data if site.get("known"))
                tracker = ResultsTracker(total_known, self.config.max_tasks)

                with self._create_progress_bar() as progress:
                    task_id = progress.add_task(
                        f"[{THEME['info']}]Running self-check...[/]",
                        total=tracker.total_sites
                    )
                    try:
                        results = await naminter.self_check(fuzzy_mode=self.config.fuzzy_mode, as_generator=True)
                        async for site_result in results:
                            num_tests = len(site_result.results)
                            for test in site_result.results:
                                tracker.add_result(test)
                            if formatted := self._format_test_result(site_result):
                                console.print(formatted)
                            progress.update(task_id, advance=num_tests, description=tracker.get_progress_text())
                    except Exception as e:
                        self._handle_error(e)
            else:
                tracker = ResultsTracker(wmn_info["sites_count"], self.config.max_tasks)
                with self._create_progress_bar() as progress:
                    task_id = progress.add_task(
                        f"[{THEME['info']}]Running enumerating...[/]",
                        total=tracker.total_sites
                    )
                    try:
                        results = await naminter.check_username(self.config.username, self.config.fuzzy_mode, as_generator=True)
                        async for result in results:
                            tracker.add_result(result)
                            if result.check_status == CheckStatus.FOUND:
                                self._found_results.append(result)
                                self._open_profile(result.site_url)
                            if formatted := self._format_result(result):
                                console.print(formatted)
                            progress.update(task_id, advance=1, description=tracker.get_progress_text())
                    except Exception as e:
                        self._handle_error(e)

    def _create_progress_bar(self) -> Progress:
        """Creates a configured Progress instance."""
        return Progress(
            TextColumn(""),
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
            TextColumn(""),
            console=console,
        )

    def _handle_error(self, error: Exception) -> None:
        """Handles error reporting consistently."""
        console.print(f"\n[{THEME['error']}]Error:[/] {str(error)}")
        if self.config.debug:
            console.print_exception()
        raise typer.Exit(1)

def display_version():
    """Display version and metadata of the application."""
    version_table = Table.grid(padding=(0, 2))
    version_table.add_column(style=THEME['info'])
    version_table.add_column(style="bold")

    version_table.add_row("Version:", __version__)
    version_table.add_row("Author:", __author__)
    version_table.add_row("Description:", __description__)

    panel = Panel(
        version_table,
        title="[bold]:mag: Naminter[/]",
        border_style=THEME['muted'],
        box=rich.box.ROUNDED
    )

    console.print(panel)

@app.callback(invoke_without_command=True)
def main(
    username: Optional[str] = typer.Argument(None, help="Username to search"),
    version: bool = typer.Option(False, "--version", "-v", help="Show version information"),
    local_list: Optional[Path] = typer.Option(None, "--local-list", "-l", show_default=False, help="Path to a local file containing list of sites to check"),
    remote_list_url: Optional[str] = typer.Option(SITES_LIST_REMOTE_URL, "--remote-url", "-r", help="URL to fetch remote list of sites to check"),
    self_check: bool = typer.Option(False, "--self-check", help="Perform self-check of the application"),
    include_categories: Optional[List[str]] = typer.Option(None, "--include-categories", "-ic", show_default=False, help="Categories of sites to include in the search"),
    exclude_categories: Optional[List[str]] = typer.Option(None, "--exclude-categories", "-ec", show_default=False, help="Categories of sites to exclude from the search"),
    proxy: Optional[str] = typer.Option(None, "--proxy", "-p", show_default=False, help="Proxy server to use for requests"),
    timeout: int = typer.Option(30, "--timeout", "-t", help="Maximum time in seconds to wait for each request"),
    allow_redirects: bool = typer.Option(False, "--allow-redirects", help="Whether to follow URL redirects"),
    verify_ssl: bool = typer.Option(False, "--verify-ssl", help="Whether to verify SSL certificates"),
    impersonate: BrowserImpersonation = typer.Option(BrowserImpersonation.CHROME, "--impersonate", "-i", help="Browser to impersonate in requests"),
    max_tasks: int = typer.Option(50, "--max-tasks", "-m", help="Maximum number of concurrent tasks"),
    fuzzy_mode: bool = typer.Option(False, "--fuzzy", "-f", help="Enable fuzzy validation mode"),
    debug: bool = typer.Option(False, "--debug", "-d"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
    browse: bool = typer.Option(False, "--browse", "-b", help="Open found profiles in web browser"),
    ctx: typer.Context = None,
):
    """Main CLI entry point."""
    if version:
        display_version()
        raise typer.Exit()

    if ctx and ctx.invoked_subcommand:
        return

    if no_color:
        global console
        console = Console(no_color=True)

    if not self_check and not username:
        console.print(f"[{THEME['error']}]Error:[/] Username is required")
        raise typer.Exit(1)

    if proxy and not proxy.startswith(("http://", "https://", "socks://")):
        console.print(f"[{THEME['error']}]Error:[/] Proxy must start with http://, https://, or socks://")
        raise typer.Exit(1)

    """if local_list and remote_list_url:
        console.print(f"[{THEME['error']}]Error:[/] Cannot specify both --local-list and --remote-url")
        raise typer.Exit(1)
    """

    try:
        config = CheckerConfig(
            username=username or "",
            local_list_path=str(local_list) if local_list else None,
            remote_list_url=remote_list_url,
            include_categories=include_categories,
            exclude_categories=exclude_categories,
            max_tasks=max_tasks,
            timeout=timeout,
            proxy=proxy,
            allow_redirects=allow_redirects,
            verify_ssl=verify_ssl,
            impersonate=impersonate,
            fuzzy_mode=fuzzy_mode,
            self_check=self_check,
            debug=debug,
            browse=browse
        )
        checker = UsernameChecker(config)
        asyncio.run(checker.run())
    except KeyboardInterrupt:
        console.print(f"\n[{THEME['warning']}]Operation interrupted[/]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[{THEME['error']}]Error:[/] {e}")
        if debug:
            console.print_exception()
        raise typer.Exit(1)

def entry_point() -> None:
    typer.run(main)

if __name__ == "__main__":
    app()