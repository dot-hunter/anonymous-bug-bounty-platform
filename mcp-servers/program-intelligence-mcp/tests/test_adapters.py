"""Tests for Adapter Registry."""

import pytest
from adapters.adapter_registry import AdapterRegistry, AdapterInfo


@pytest.fixture
def registry():
    """Create an AdapterRegistry instance."""
    return AdapterRegistry()


class TestAdapterRegistry:
    """Test the AdapterRegistry class."""

    def test_builtin_adapters_registered(self, registry):
        """Test that built-in adapters are registered."""
        adapters = registry.list_adapters()
        assert len(adapters) > 0

    def test_vulnera_mcp_adapter(self, registry):
        """Test vulnera-mcp adapter exists."""
        adapter = registry.get("vulnera-mcp")
        assert adapter is not None
        assert adapter.adapter_type == "recon_and_testing"

    def test_bounty_directory_adapter(self, registry):
        """Test bounty-directory adapter exists."""
        adapter = registry.get("bounty-directory")
        assert adapter is not None
        assert adapter.adapter_type == "program_directory"

    def test_agent_reach_adapter(self, registry):
        """Test agent-reach adapter exists."""
        adapter = registry.get("agent-reach")
        assert adapter is not None
        assert adapter.adapter_type == "osint"

    def test_hackerone_adapter(self, registry):
        """Test hackerone adapter exists."""
        adapter = registry.get("hackerone")
        assert adapter is not None
        assert adapter.adapter_type == "platform_api"

    def test_security_research_adapter(self, registry):
        """Test security-research adapter exists."""
        adapter = registry.get("security-research")
        assert adapter is not None
        assert adapter.adapter_type == "static_analysis"

    def test_nuclei_adapter(self, registry):
        """Test nuclei adapter exists."""
        adapter = registry.get("nuclei")
        assert adapter is not None
        assert adapter.adapter_type == "scanner"

    def test_interactsh_adapter(self, registry):
        """Test interactsh adapter exists."""
        adapter = registry.get("interactsh")
        assert adapter is not None
        assert adapter.adapter_type == "oob"

    def test_shodan_adapter(self, registry):
        """Test shodan adapter exists."""
        adapter = registry.get("shodan")
        assert adapter is not None
        assert adapter.adapter_type == "internet_intel"

    def test_register_custom_adapter(self, registry):
        """Test registering a custom adapter."""
        registry.register("custom-mcp", "custom_type", {"capabilities": ["test"]})
        adapter = registry.get("custom-mcp")
        assert adapter is not None
        assert adapter.adapter_type == "custom_type"

    def test_list_adapters(self, registry):
        """Test listing all adapters."""
        adapters = registry.list_adapters()
        names = [a["name"] for a in adapters]
        assert "vulnera-mcp" in names
        assert "bounty-directory" in names
        assert "agent-reach" in names

    def test_count(self, registry):
        """Test counting adapters."""
        count = registry.count()
        assert count >= 8  # At least 8 built-in adapters

    def test_get_capabilities(self, registry):
        """Test getting capabilities."""
        caps = registry.get_capabilities("vulnera-mcp")
        assert len(caps) > 0
        assert "recon.subfinder" in caps

    def test_get_capabilities_nonexistent(self, registry):
        """Test getting capabilities of non-existent adapter."""
        caps = registry.get_capabilities("nonexistent")
        assert caps == []

    def test_adapter_info_to_dict(self):
        """Test AdapterInfo serialization."""
        info = AdapterInfo("test", "test_type", {"key": "value"})
        d = info.to_dict()
        assert d["name"] == "test"
        assert d["type"] == "test_type"
        assert d["config"]["key"] == "value"
