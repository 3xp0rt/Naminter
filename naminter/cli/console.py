from pathlib import Path
from typing import Dict, List, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from ..core.models import ResultStatus, SiteResult, SelfCheckResult

console: Console = Console()

THEME: Dict[str, str] = {
    'primary': 'bright_blue',
    'success': 'bright_green', 
    'error': 'bright_red',
    'warning': 'bright_yellow',
    'info': 'bright_cyan',
    'muted': 'bright_black',
}

_STATUS_SYMBOLS: Dict[ResultStatus, str] = {
    ResultStatus.FOUND: "+",
    ResultStatus.NOT_FOUND: "-",
    ResultStatus.UNKNOWN: "?",
    ResultStatus.ERROR: "!",
    ResultStatus.NOT_VALID: "X",
}

_STATUS_STYLES: Dict[ResultStatus, Style] = {
    ResultStatus.FOUND: Style(color=THEME['success'], bold=True),
    ResultStatus.NOT_FOUND: Style(color=THEME['error']),
    ResultStatus.UNKNOWN: Style(color=THEME['warning']),
    ResultStatus.ERROR: Style(color=THEME['error'], bold=True),
    ResultStatus.NOT_VALID: Style(color=THEME['error']),
}

class ResultFormatter:
    """Formats test results for console output."""
    
    def __init__(self, show_details: bool = False) -> None:
        """Initialize the result formatter."""
        self.show_details = show_details

    def format_result(self, site_result: SiteResult, response_file_path: Optional[Path] = None) -> Tree:
        """Format a single result as a tree-style output."""
        
        if site_result is None:
            raise ValueError("SiteResult cannot be None")

        if not hasattr(site_result, 'result_status') or site_result.result_status not in ResultStatus:
            raise ValueError("SiteResult must have a valid result_status")

        root_label = Text()
        status_symbol = _STATUS_SYMBOLS.get(site_result.result_status, "?")
        status_style = _STATUS_STYLES.get(site_result.result_status, Style())

        root_label.append(status_symbol, style=status_style)
        root_label.append(" [", style=THEME['muted'])
        root_label.append(site_result.site_name or "Unknown", style=THEME['info'])
        root_label.append("] ", style=THEME['muted'])
        root_label.append(site_result.result_url or "No URL", style=THEME['primary'])

        tree = Tree(root_label, guide_style=THEME["muted"])

        if self.show_details:
            self._add_debug_info(
                tree,
                site_result.response_code,
                site_result.elapsed,
                site_result.error,
                response_file_path
            )

        return tree

    def format_self_check(self, self_check_result: SelfCheckResult, response_files: Optional[List[Optional[Path]]] = None) -> Tree:
        """Format self-check results into a tree structure."""
        
        if not self_check_result:
            raise ValueError("SelfCheckResult cannot be None or empty")
            
        if not isinstance(self_check_result, SelfCheckResult):
            raise ValueError("Parameter must be a SelfCheckResult instance")
            
        if not self_check_result.site_name or not self_check_result.site_name.strip():
            raise ValueError("SelfCheckResult must have a valid site_name")
            
        if not self_check_result.results:
            raise ValueError("SelfCheckResult must have test results")
        
        site_name = self_check_result.site_name
        test_results = self_check_result.results
        overall_status = self_check_result.overall_status

        root_label = Text()
        root_label.append(_STATUS_SYMBOLS.get(overall_status, "?"), style=_STATUS_STYLES.get(overall_status, Style()))
        root_label.append(" [", style=THEME["muted"])
        root_label.append(site_name, style=THEME["info"])
        root_label.append("]", style=THEME["muted"])

        tree = Tree(root_label, guide_style=THEME["muted"], expanded=True)
        
        for i, test in enumerate(test_results):
            if test is None:
                continue
                
            url_text = Text()
            url_text.append(_STATUS_SYMBOLS.get(test.result_status, "?"), 
                          style=_STATUS_STYLES.get(test.result_status, Style()))
            url_text.append(" ", style=THEME["muted"])
            url_text.append(f"{test.username}: ", style=THEME["info"])            
            url_text.append(test.result_url or "No URL", style=THEME["primary"])
            
            test_node = tree.add(url_text)
            
            if self.show_details:
                response_file = response_files[i] if response_files and i < len(response_files) else None
                self._add_debug_info(
                    test_node,
                    test.response_code,
                    test.elapsed,
                    test.error,
                    response_file
                )

        return tree

    def _add_debug_info(self, node: Tree, response_code: Optional[int] = None, elapsed: Optional[float] = None, 
                       error: Optional[str] = None, response_file: Optional[Path] = None) -> None:
        """Add debug information to a tree node."""
        
        if response_code is not None:
            node.add(Text(f"Response Code: {response_code}", style=THEME['info']))
        if response_file:
            node.add(Text(f"Response File: {response_file}", style=THEME['info']))
        if elapsed is not None:
            node.add(Text(f"Elapsed: {elapsed:.2f}s", style=THEME['info']))
        if error:
            node.add(Text(f"Error: {error}", style=THEME['error']))

def display_version(version: str, author: str, description: str) -> None:
    """Display version and metadata of the application."""
    
    if not all([version and version.strip(), author and author.strip(), description and description.strip()]):
        raise ValueError("Version, author, and description must be non-empty strings")
    
    version_table = Table.grid(padding=(0, 2))
    version_table.add_column(style=THEME['info'])
    version_table.add_column(style="bold")

    version_table.add_row("Version:", version)
    version_table.add_row("Author:", author)
    version_table.add_row("Description:", description)

    panel = Panel(
        version_table,
        title="[bold]:mag: Naminter[/]",
        border_style=THEME['muted'],
        box=box.ROUNDED,
    )

    console.print(panel)

def _display_message(message: str, style: str, symbol: str, label: str) -> None:
    """Display a styled message with symbol and label."""
    
    if not all([message and message.strip(), style and style.strip(), symbol and symbol.strip(), label and label.strip()]):
        raise ValueError("Message, style, symbol, and label must be non-empty strings")
    
    formatted_message = Text()
    formatted_message.append(symbol, style=style)
    formatted_message.append(f" [{label}] ", style=style)
    formatted_message.append(message)
    
    console.print(formatted_message)
    if hasattr(console.file, 'flush'):
        console.file.flush()

def display_error(message: str, show_traceback: bool = False) -> None:
    """Display an error message."""
    
    _display_message(message, THEME['error'], "!", "ERROR")
    if show_traceback:
        console.print_exception()

def display_warning(message: str) -> None:
    """Display a warning message."""
    
    _display_message(message, THEME['warning'], "?", "WARNING")

def display_info(message: str) -> None:
    """Display an info message."""
    
    _display_message(message, THEME['info'], "*", "INFO")

def display_success(message: str) -> None:
    """Display a success message."""
    
    _display_message(message, THEME['success'], "+", "SUCCESS")
