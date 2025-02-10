import asyncio
import time
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

__version__ = "1.0.0"
__author__ = "3xp0rt"
__description__ = "Username availability checker across multiple websites"

app = typer.Typer(help="Username availability checker", add_completion=False, rich_markup_mode="rich")
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

@dataclass
class CheckerConfig:
    """Configuration for the UsernameChecker."""
    # Core settings
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

    # Validation settings
    weak_mode: bool
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

    def _create_header_panel(self, wmn_info: Dict[str, Any]) -> Panel:
        """Creates an enhanced configuration panel."""
        main_grid = Table.grid(padding=0)
        main_grid.add_column(ratio=1)
        main_grid.add_column(ratio=1)

        main_grid.add_row(
            self._create_essential_table(wmn_info),
            self._create_technical_table()
        )

        subtitle_text = (
            f"[{THEME['muted']}]Running self check across {wmn_info['sites_count']} sites[/]"
            if self.config.self_check
            else f"[{THEME['muted']}]Checking {self.config.username} across {wmn_info['sites_count']} sites[/]"
        )

        return Panel(
            main_grid,
            title=f"[bold {THEME['primary']}]:mag: Naminter[/]",
            subtitle=subtitle_text,
            border_style=THEME['primary'],
            box=rich.box.ROUNDED,
            padding=(1, 2)
        )

    def _create_essential_table(self, wmn_info: Dict) -> Table:
        """Creates table with essential configuration items."""
        table = Table.grid(padding=0)

        def truncate_text(text: str, max_length: int = 50) -> str:
            return text if len(text) <= max_length else text[:max_length-3] + "..."

        categories = wmn_info.get("categories", [])
        if categories:
            if len(categories) > 3:
                categories_text = f"{', '.join(categories[:3])} +{len(categories)-3}"
            else:
                categories_text = ", ".join(categories)
        else:
            categories_text = "None"

        essential_items = [
            ("📦 Version", self.config.version),
            ("🌐 Total Sites", str(wmn_info["sites_count"])),
            ("📑 Categories", categories_text)
        ]
        
        if not self.config.self_check:
            essential_items.insert(1, ("👤 Username", self.config.username))
        else:
            essential_items.insert(1, ("👤 Self check", "✓" if self.config.self_check else "✗"))

        if self.config.include_categories:
            essential_items.append(("✅ Include", ", ".join(self.config.include_categories)))
        if self.config.exclude_categories:
            essential_items.append(("❌ Exclude", ", ".join(self.config.exclude_categories)))
        if self.config.proxy:
            essential_items.append(("🔄 Proxy", truncate_text(self.config.proxy)))
        if self.config.local_list_path:
            essential_items.append(("📁 Local List", truncate_text(self.config.local_list_path)))
        if self.config.remote_list_url:
            essential_items.append(("🌍 Remote URL", truncate_text(self.config.remote_list_url)))

        for label, value in essential_items:
            table.add_row(f"[{THEME['muted']}]{label}:[/] [{THEME['primary']}]{value}[/]")
        return table

    def _create_technical_table(self) -> Table:
        """Creates table with technical settings and minimal spacing."""
        table = Table.grid(padding=0)
        
        technical_settings = [
            ("⚡ Max Tasks", str(self.config.max_tasks)),
            (":clock1: Timeout", f"{self.config.timeout}s"),
            ("🔍 Mode", "Weak" if self.config.weak_mode else "Strict"),
            ("🔒 SSL Verify", "✓" if self.config.verify_ssl else "✗"),
            (":arrows_counterclockwise: Redirects", "✓" if self.config.allow_redirects else "✗"),
            ("🌍 Browser", self.config.impersonate.upper() if self.config.impersonate else "✗"),
        ]
        
        for label, value in technical_settings:
            table.add_row(f"[{THEME['muted']}]{label}:[/] [{THEME['primary']}]{value}[/]")
        return table
    
    def _get_optional_settings(self) -> List[tuple]:
        """Returns list of optional settings."""
        optional = []
        if self.config.include_categories:
            optional.append(("✅ Include", ", ".join(self.config.include_categories)))
        if self.config.exclude_categories:
            optional.append(("❌ Exclude", ", ".join(self.config.exclude_categories)))
        if self.config.proxy:
            optional.append(("🔄 Proxy", self.config.proxy))
        if self.config.local_list_path:
            optional.append(("📁 Local List", self.config.local_list_path))
        if self.config.remote_list_url:
            optional.append(("🌍 Remote URL", self.config.remote_list_url))
        return optional
    
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

        # Determine overall status
        overall_status = next((
            status for status in [
                CheckStatus.ERROR,
                CheckStatus.FOUND,
                CheckStatus.NOT_FOUND
            ] if any(test.check_status == status for test in self_check.results)
        ), CheckStatus.UNKNOWN)

        # Create root label
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
                await naminter.fetch_remote_list()

            wmn_info = await naminter.get_wmn_info()
            console.print(self._create_header_panel(wmn_info))

            if self.config.self_check:
                sites_data = naminter._wmn_data.get("sites", [])
                total_known = sum(len(site.get("known", [])) for site in sites_data if site.get("known"))
                tracker = ResultsTracker(total_known, self.config.max_tasks)

                with self._create_progress_bar() as progress:
                    task_id = progress.add_task(
                        f"[{THEME['info']}]Running self-check...[/]",  # Added color
                        total=tracker.total_sites
                    )
                    try:
                        results = await naminter.self_check(weak_mode=self.config.weak_mode, as_generator=True)
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
                        f"[{THEME['info']}]Running enumerating...[/]",  # Added color
                        total=tracker.total_sites
                    )
                    try:
                        results = await naminter.check_username(self.config.username, self.config.weak_mode, as_generator=True)
                        async for result in results:
                            tracker.add_result(result)
                            if result.check_status == CheckStatus.FOUND:
                                self._found_results.append(result)
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
            BarColumn(complete_style=THEME['primary'], finished_style=THEME['success']),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console,
        )

    def _handle_error(self, error: Exception) -> None:
        """Handles error reporting consistently."""
        console.print(f"\n[{THEME['error']}]Error:[/] {str(error)}")
        if self.config.debug:
            console.print_exception()
        raise typer.Exit(1)

@app.callback(invoke_without_command=True)
def main(
    username: Optional[str] = typer.Argument(None, help="Username to check"),
    local_list: Optional[Path] = typer.Option(None, "--local-list", "-l", show_default=False),
    remote_list_url: Optional[str] = typer.Option(SITES_LIST_REMOTE_URL, "--remote-url", "-r"),
    include_categories: Optional[List[str]] = typer.Option(None, "--include-categories", "-ic", show_default=False),
    exclude_categories: Optional[List[str]] = typer.Option(None, "--exclude-categories", "-ec", show_default=False),
    max_tasks: int = typer.Option(50, "--max-tasks", "-m"),
    timeout: int = typer.Option(30, "--timeout", "-t"),
    proxy: Optional[str] = typer.Option(None, "--proxy", "-p", show_default=False),
    allow_redirects: bool = typer.Option(False, "--allow-redirects"),
    verify_ssl: bool = typer.Option(False, "--verify-ssl"),
    impersonate: BrowserImpersonation = typer.Option(BrowserImpersonation.CHROME, "--impersonate", "-i"),
    weak_mode: bool = typer.Option(False, "--weak", "-w"),
    self_check: bool = typer.Option(False, "--self-check"),
    debug: bool = typer.Option(False, "--debug", "-d"),
    ctx: typer.Context = None
):
    """Main CLI entry point."""
    if ctx and ctx.invoked_subcommand:
        return

    if not self_check and not username:
        console.print(f"[{THEME['error']}]Error:[/] Username is required")
        raise typer.Exit(1)

    """
    if local_list and remote_list_url:
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
            max_tasks=int(max_tasks),
            timeout=int(timeout),
            proxy=proxy,
            allow_redirects=allow_redirects,
            verify_ssl=verify_ssl,
            impersonate=impersonate,
            weak_mode=weak_mode,
            self_check=self_check,
            debug=debug
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

@app.command()
def version():    
    """Display version and metadata of the application."""
    version_table = Table.grid(padding=(0, 2))
    version_table.add_column(style=THEME['info'])
    version_table.add_column(style="bold")
    
    version_table.add_row("Version:", __version__)
    version_table.add_row("Author:", __author__)
    version_table.add_row("Description:", __description__)
    
    panel = Panel(
        version_table,
        title="[bold]🔍  WMNPY Version Information[/]",
        border_style=THEME['muted'],
        box=rich.box.ROUNDED
    )
    
    console.print(panel)

def entry_point() -> None:
    typer.run(main)
    
if __name__ == "__main__":
    app()