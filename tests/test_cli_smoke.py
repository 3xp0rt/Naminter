"""Lightweight CLI smoke tests (full CLI module is omitted from coverage)."""

from __future__ import annotations

from click.testing import CliRunner

from naminter.cli.main import main


def test_main_help_exits_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0


def test_main_version_exits_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0


def test_format_subcommand_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["format", "--help"])
    assert result.exit_code == 0
