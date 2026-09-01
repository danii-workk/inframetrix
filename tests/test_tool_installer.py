"""Tests for ToolInstallerService."""

from inframetrix.services.tool_installer import BIN_DIR, ToolInstallerService, ensure_bin_in_path


def test_tool_installer_get_installable():
    tools = ToolInstallerService.get_installable_tools()
    assert "gitleaks" in tools
    assert "osv-sca" in tools
    assert "syft" in tools


def test_ensure_bin_in_path():
    ensure_bin_in_path()
    assert BIN_DIR.is_dir()
