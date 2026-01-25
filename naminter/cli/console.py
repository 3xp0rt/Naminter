from dataclasses import dataclass
from datetime import timedelta
import difflib
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
from naminter.cli.constants import (
    STATUS_STYLES,
    STATUS_SYMBOLS,
)
from naminter.core.models import WMNResult, WMNStatus, WMNTestResult

console: Console = Console()


@dataclass(frozen=True)
class Theme:
    """Application color theme configuration."""

    primary: str = "bright_blue"
    success: str = "bright_green"
    error: str = "bright_red"
    warning: str = "bright_yellow"
    info: str = "bright_cyan"
    muted: str = "bright_black"


THEME = Theme()


def _get_status_symbol(status: WMNStatus) -> str:
    """Get display symbol for a status using constants.

    Args:
        status: The WMNStatus to get symbol for.

    Returns:
        Symbol character for the status.
    """
    return STATUS_SYMBOLS.get(status, "?")


def _get_status_style(status: WMNStatus) -> Style:
    """Get Rich Style for a status using constants.

    Args:
        status: The WMNStatus to get styling for.

    Returns:
        Rich Style object with appropriate color and formatting.
    """
    style_str = STATUS_STYLES.get(status, "white")
    return Style.parse(style_str)


class ResultFormatter:
    """Formats test results for console output."""

    def __init__(self, *, show_details: bool = False) -> None:
        """Initialize the result formatter.

        Args:
            show_details: Whether to include detailed debug information in output.
        """
        self.show_details = show_details

    def format_result(
        self,
        site_result: WMNResult,
        response_file_path: Path | None = None,
    ) -> Tree:
        """Format a single result as a tree-style output.

        Args:
            site_result: The result to format.
            response_file_path: Optional path to the response file for debugging.

        Returns:
            A Rich Tree object containing the formatted result.
        """
        root_label = Text()
        status_symbol = _get_status_symbol(site_result.status)
        status_style = _get_status_style(site_result.status)

        root_label.append(status_symbol, style=status_style)
        root_label.append(" [", style=THEME.muted)
        root_label.append(site_result.name or "Unknown", style=THEME.info)
        root_label.append("] ", style=THEME.muted)
        root_label.append(site_result.url or "No URL", style=THEME.primary)

        tree = Tree(root_label, guide_style=THEME.muted)

        if self.show_details:
            self._add_debug_info(
                tree,
                site_result.status_code,
                site_result.elapsed,
                site_result.error,
                response_file_path,
            )

        return tree

    def format_validation(
        self,
        validation_result: WMNTestResult,
        response_files: list[Path | None] | None = None,
    ) -> Tree:
        """Format validation results into a tree structure.

        Args:
            validation_result: The validation result to format.
            response_files: Optional list of response file paths for debugging.

        Returns:
            A Rich Tree object containing the formatted validation results.
        """
        root_label = Text()
        root_label.append(
            _get_status_symbol(validation_result.status),
            style=_get_status_style(validation_result.status),
        )
        root_label.append(" [", style=THEME.muted)
        root_label.append(validation_result.name, style=THEME.info)
        root_label.append("]", style=THEME.muted)

        tree = Tree(root_label, guide_style=THEME.muted, expanded=True)

        if validation_result.results:
            for i, result in enumerate(validation_result.results):
                url_text = Text()
                url_text.append(
                    _get_status_symbol(result.status),
                    style=_get_status_style(result.status),
                )
                url_text.append(" ", style=THEME.muted)
                url_text.append(f"{result.username}: ", style=THEME.info)
                url_text.append(result.url or "No URL", style=THEME.primary)

                result_node = tree.add(url_text)

                if self.show_details:
                    response_file = (
                        response_files[i]
                        if response_files and i < len(response_files)
                        else None
                    )
                    self._add_debug_info(
                        result_node,
                        result.status_code,
                        result.elapsed,
                        result.error,
                        response_file,
                    )

        return tree

    @staticmethod
    def _add_debug_info(
        node: Tree,
        status_code: int | None = None,
        elapsed: timedelta | None = None,
        error: str | None = None,
        response_file: Path | None = None,
    ) -> None:
        """Add debug information to a tree node.

        Args:
            node: The tree node to add information to.
            status_code: Optional HTTP status code.
            elapsed: Optional elapsed time in seconds.
            error: Optional error message.
            response_file: Optional path to response file.
        """
        if status_code is not None:
            node.add(Text(f"Status Code: {status_code}", style=THEME.info))
        if response_file is not None:
            node.add(Text(f"Response File: {response_file}", style=THEME.info))
        if elapsed is not None:
            elapsed_seconds = elapsed.total_seconds()
            node.add(Text(f"Elapsed: {elapsed_seconds:.2f}s", style=THEME.info))
        if error is not None:
            node.add(Text(f"Error: {error}", style=THEME.error))


def display_version() -> None:
    """Display version and metadata of the application."""

    version_table = Table.grid(padding=(0, 2))
    version_table.add_column(style=THEME.info)
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
        border_style=THEME.muted,
        box=box.ROUNDED,
    )

    console.print(panel)


def _display_message(
    message: str,
    style: str,
    symbol: str,
    label: str,
    end: str = "\n",
) -> None:
    """Display a styled message with symbol and label."""

    formatted_message = Text()
    formatted_message.append(symbol, style=style)
    formatted_message.append(f" [{label}] ", style=style)
    formatted_message.append(message)

    console.print(formatted_message, end=end)
    console.file.flush()


def display_error(
    message: str,
    *,
    show_traceback: bool = False,
    end: str = "\n",
) -> None:
    """Display an error message.

    Args:
        message: The error message to display.
        show_traceback: Whether to print the full traceback.
        end: String to append after the message (default: newline).
    """
    _display_message(message, THEME.error, "!", "ERROR", end=end)
    if show_traceback:
        console.print_exception()


def display_warning(message: str) -> None:
    """Display a warning message."""

    _display_message(message, THEME.warning, "?", "WARNING")


def display_info(message: str) -> None:
    """Display an info message."""

    _display_message(message, THEME.info, "*", "INFO")


def display_success(message: str) -> None:
    """Display a success message."""

    _display_message(message, THEME.success, "+", "SUCCESS")


def display_errors(errors: list[Any], title: str | None = None) -> None:
    """Display validation errors in a formatted tree structure.

    Args:
        errors: List of validation errors to display.
        title: Optional title to display above the errors.
    """
    if not errors:
        return

    if title:
        root_label = Text()
        root_label.append(f"{title} ", style=THEME.error)
        root_label.append(f"({len(errors)})", style=THEME.muted)
    else:
        root_label = Text()
    console.print()
    
    tree = Tree(root_label, guide_style=THEME.muted, expanded=True)

    for error in errors:
        path = str(getattr(error, "path", "N/A") or "N/A")
        message = str(getattr(error, "message", "Unknown error"))
        data = getattr(error, "data", None)

        error_text = Text()
        error_text.append("• ", style=THEME.error)
        error_text.append(f"{path}: ", style=THEME.info)
        error_text.append(message, style=THEME.warning)

        error_node = tree.add(error_text)

        if data is not None:
            error_node.add(Text(f"Data: {data}", style=THEME.muted))

    console.print(tree)
    console.file.flush()


def display_diff(original: str, formatted: str, file_path: Path) -> None:
    """Display a git-style diff showing changes between original and formatted content.

    Args:
        original: The original file content.
        formatted: The formatted file content.
        file_path: Path to the file being formatted.
    """
    original_lines = original.splitlines(keepends=False)
    formatted_lines = formatted.splitlines(keepends=False)

    diff = difflib.unified_diff(
        original_lines,
        formatted_lines,
        fromfile=str(file_path),
        tofile=str(file_path),
        lineterm="",
    )

    diff_lines = list(diff)
    if not diff_lines:
        return

    diff_text = Text()
    for line in diff_lines:
        if line.startswith(("---", "+++")):
            diff_text.append(line, style=THEME.muted)
        elif line.startswith("@@"):
            diff_text.append(line, style=THEME.info)
        elif line.startswith("-"):
            diff_text.append(line, style=THEME.error)
        elif line.startswith("+"):
            diff_text.append(line, style=THEME.success)
        else:
            diff_text.append(line)

        diff_text.append("\n")

    console.print(diff_text)
    console.file.flush()
