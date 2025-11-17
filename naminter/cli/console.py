from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from naminter import (
    __author__,
    __description__,
    __email__,
    __license__,
    __url__,
    __version__,
)
from naminter.core.models import WMNResult, WMNStatus, WMNValidationResult

console: Console = Console()

THEME: dict[str, str] = {
    "primary": "bright_blue",
    "success": "bright_green",
    "error": "bright_red",
    "warning": "bright_yellow",
    "info": "bright_cyan",
    "muted": "bright_black",
}

_STATUS_SYMBOLS: dict[WMNStatus, str] = {
    WMNStatus.FOUND: "+",
    WMNStatus.AMBIGUOUS: "*",
    WMNStatus.UNKNOWN: "?",
    WMNStatus.NOT_FOUND: "-",
    WMNStatus.NOT_VALID: "X",
    WMNStatus.ERROR: "!",
}

_STATUS_STYLES: dict[WMNStatus, Style] = {
    WMNStatus.FOUND: Style(color=THEME["success"], bold=True),
    WMNStatus.AMBIGUOUS: Style(color=THEME["warning"], bold=True),
    WMNStatus.UNKNOWN: Style(color=THEME["warning"]),
    WMNStatus.NOT_FOUND: Style(color=THEME["error"]),
    WMNStatus.NOT_VALID: Style(color=THEME["error"]),
    WMNStatus.ERROR: Style(color=THEME["error"], bold=True),
}


class ResultFormatter:
    """Formats test results for console output."""

    def __init__(self, show_details: bool = False) -> None:
        """Initialize the result formatter."""
        self.show_details = show_details

    def format_result(
        self, site_result: WMNResult, response_file_path: Path | None = None
    ) -> Tree:
        """Format a single result as a tree-style output."""

        root_label = Text()
        status_symbol = _STATUS_SYMBOLS.get(site_result.status, "?")
        status_style = _STATUS_STYLES.get(site_result.status, Style())

        root_label.append(status_symbol, style=status_style)
        root_label.append(" [", style=THEME["muted"])
        root_label.append(site_result.name or "Unknown", style=THEME["info"])
        root_label.append("] ", style=THEME["muted"])
        root_label.append(site_result.url or "No URL", style=THEME["primary"])

        tree = Tree(root_label, guide_style=THEME["muted"])

        if self.show_details:
            self._add_debug_info(
                tree,
                site_result.response_code,
                site_result.elapsed,
                site_result.error,
                response_file_path,
            )

        return tree

    def format_validation(
        self,
        validation_result: WMNValidationResult,
        response_files: list[Path | None] | None = None,
    ) -> Tree:
        """Format validation results into a tree structure."""

        root_label = Text()
        root_label.append(
            _STATUS_SYMBOLS.get(validation_result.status, "?"),
            style=_STATUS_STYLES.get(validation_result.status, Style()),
        )
        root_label.append(" [", style=THEME["muted"])
        root_label.append(validation_result.name, style=THEME["info"])
        root_label.append("]", style=THEME["muted"])

        tree = Tree(root_label, guide_style=THEME["muted"], expanded=True)

        if validation_result.results:
            for i, result in enumerate(validation_result.results):
                url_text = Text()
                url_text.append(
                    _STATUS_SYMBOLS.get(result.status, "?"),
                    style=_STATUS_STYLES.get(result.status, Style()),
                )
                url_text.append(" ", style=THEME["muted"])
                url_text.append(f"{result.username}: ", style=THEME["info"])
                url_text.append(result.url or "No URL", style=THEME["primary"])

                result_node = tree.add(url_text)

                if self.show_details:
                    response_file = (
                        response_files[i]
                        if response_files and i < len(response_files)
                        else None
                    )
                    self._add_debug_info(
                        result_node,
                        result.response_code,
                        result.elapsed,
                        result.error,
                        response_file,
                    )

        return tree

    @staticmethod
    def _add_debug_info(
        node: Tree,
        response_code: int | None = None,
        elapsed: float | None = None,
        error: str | None = None,
        response_file: Path | None = None,
    ) -> None:
        """Add debug information to a tree node."""

        if response_code is not None:
            node.add(Text(f"Response Code: {response_code}", style=THEME["info"]))
        if response_file is not None:
            node.add(Text(f"Response File: {response_file}", style=THEME["info"]))
        if elapsed is not None:
            node.add(Text(f"Elapsed: {elapsed:.2f}s", style=THEME["info"]))
        if error is not None:
            node.add(Text(f"Error: {error}", style=THEME["error"]))


def display_version() -> None:
    """Display version and metadata of the application."""

    version_table = Table.grid(padding=(0, 2))
    version_table.add_column(style=THEME["info"])
    version_table.add_column(style="bold")

    version_table.add_row("Version:", __version__)
    version_table.add_row("Author:", __author__)
    version_table.add_row("Description:", __description__)
    version_table.add_row("License:", __license__)
    version_table.add_row("Email:", __email__)
    version_table.add_row("GitHub:", __url__)

    panel = Panel(
        version_table,
        title="[bold]:mag: Naminter[/]",
        border_style=THEME["muted"],
        box=box.ROUNDED,
    )

    console.print(panel)


def _display_message(message: str, style: str, symbol: str, label: str) -> None:
    """Display a styled message with symbol and label."""

    formatted_message = Text()
    formatted_message.append(symbol, style=style)
    formatted_message.append(f" [{label}] ", style=style)
    formatted_message.append(message)

    console.print(formatted_message)
    console.file.flush()


def display_error(message: str, show_traceback: bool = False) -> None:
    """Display an error message."""

    _display_message(message, THEME["error"], "!", "ERROR")
    if show_traceback:
        console.print_exception()


def display_warning(message: str) -> None:
    """Display a warning message."""

    _display_message(message, THEME["warning"], "?", "WARNING")


def display_info(message: str) -> None:
    """Display an info message."""

    _display_message(message, THEME["info"], "*", "INFO")


def display_success(message: str) -> None:
    """Display a success message."""

    _display_message(message, THEME["success"], "+", "SUCCESS")


def display_validation_errors(errors: list[Any]) -> None:
    """Display validation errors in a formatted table."""
    if not errors:
        return

    table = Table(
        title="[bold bright_red]Validation Errors[/bold bright_red]",
        border_style=THEME["error"],
        box=box.ROUNDED,
        show_lines=True,
    )

    table.add_column("Path", style=THEME["info"], no_wrap=False)
    table.add_column("Message", style=THEME["warning"])
    table.add_column("Data Preview", style=THEME["muted"], overflow="fold")

    for error in errors:
        path = getattr(error, "path", "N/A") or "N/A"
        message = getattr(error, "message", "Unknown error")
        data = getattr(error, "data", None)

        data_preview = (
            data[:200] + "..." if data and len(data) > 200 else (data or "N/A")
        )

        table.add_row(path, message, data_preview)

    console.print(table)
    console.file.flush()
